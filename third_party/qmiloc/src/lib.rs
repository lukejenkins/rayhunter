// SPDX-License-Identifier: Apache-2.0
//! A blocking QMI-LOC client over QRTR.
//!
//! On SDX-class Qualcomm modems the Location service (QMI service 16) is
//! registered on QRTR, so a client can find it through the QRTR name service
//! and talk to it directly. No QMUX client id is allocated, no CTL frame is
//! sent, and no `/dev/smdcntl*` port is opened, so a session never touches the
//! data path.
//!
//! ```no_run
//! use std::time::Duration;
//! let mut loc = qmiloc::Client::lookup(Duration::from_secs(5))?;
//! loc.register_nmea();
//! loc.set_nmea_types(qmiloc::NMEA_TYPES_DEFAULT);
//! loc.start();
//! while let Some(text) = loc.next_nmea(Duration::from_secs(1))? {
//!     for s in qmiloc::sentences(&text) {
//!         println!("{}", String::from_utf8_lossy(s));
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Each request returns an [`Outcome`] for the caller to report; the library
//! logs nothing. A session is stopped on drop if it was started and not
//! stopped explicitly.

pub mod qrtr;
pub mod wire;

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

pub use qrtr::Service;
pub use wire::{sentences, Outcome, Sentences, EVENT_MASK_NMEA, NMEA_TYPES_DEFAULT, SESSION_ID, SVC_LOC};

/// How long a request waits for its response.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Indications kept while a request waits for its response.
const QUEUE_MAX: usize = 64;

#[derive(Debug)]
pub enum Error {
    /// The `AF_QIPCRTR` socket could not be created.
    Socket(io::Error),
    /// The name-service lookup failed at the socket level.
    Lookup(io::Error),
    /// The name service has no LOC service registered.
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Socket(e) => write!(f, "AF_QIPCRTR socket: {e}"),
            Error::Lookup(e) => write!(f, "QRTR lookup: {e}"),
            Error::NotFound => write!(f, "LOC service ({SVC_LOC}) not found on QRTR"),
        }
    }
}

impl std::error::Error for Error {}

/// A QMI-LOC client bound to the LOC service found on QRTR.
#[derive(Debug)]
pub struct Client {
    sock: qrtr::QrtrSocket,
    service: Service,
    txn: u16,
    queue: VecDeque<Vec<u8>>,
    started: bool,
    buf: Vec<u8>,
}

impl Client {
    /// Open a QRTR socket and look LOC up, waiting at most `timeout` for the
    /// name service to finish its answer.
    pub fn lookup(timeout: Duration) -> Result<Self, Error> {
        let sock = qrtr::QrtrSocket::new().map_err(Error::Socket)?;
        let service = sock.lookup(SVC_LOC, timeout).map_err(Error::Lookup)?.ok_or(Error::NotFound)?;
        Ok(Client { sock, service, txn: 1, queue: VecDeque::new(), started: false, buf: vec![0; 8192] })
    }

    /// Where LOC was found.
    pub fn service(&self) -> Service {
        self.service
    }

    /// REG_EVENTS with the NMEA event mask.
    pub fn register_nmea(&mut self) -> Outcome {
        self.call(wire::MSG_REG_EVENTS, |t| wire::reg_events(t, EVENT_MASK_NMEA))
    }

    /// SET_NMEA_TYPES. Callers wanting the firmware default skip this call.
    /// The mask is engine-wide: it also changes what every other LOC client receives.
    pub fn set_nmea_types(&mut self, mask: u32) -> Outcome {
        self.call(wire::MSG_SET_NMEA_TYPES, |t| wire::set_nmea_types(t, mask))
    }

    /// START session [`SESSION_ID`] with periodic fixes. May be called again
    /// on a running session to restart it.
    pub fn start(&mut self) -> Outcome {
        self.started = true;
        self.call(wire::MSG_START, |t| wire::start(t, SESSION_ID))
    }

    /// STOP session [`SESSION_ID`].
    pub fn stop(&mut self) -> Outcome {
        self.started = false;
        self.call(wire::MSG_STOP, |t| wire::stop(t, SESSION_ID))
    }

    /// The text of the next NMEA indication; it may hold several sentences,
    /// see [`sentences`]. `Ok(None)` when `timeout` passes, or when a signal
    /// interrupts the wait, so a caller can check its own stop flag.
    pub fn next_nmea(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        if let Some(text) = self.queue.pop_front() {
            return Ok(Some(text));
        }
        let deadline = Instant::now() + timeout;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let n = match self.recv(left) {
                Ok(Some(n)) => n,
                Ok(None) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
                Err(e) => return Err(e),
            };
            if let Some(text) = nmea_of(&self.buf[..n]) {
                return Ok(Some(text.to_vec()));
            }
        }
        Ok(None)
    }

    /// Receive one datagram from the LOC server; others are dropped.
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<usize>> {
        let r = self.sock.recv_from(&mut self.buf, timeout)?;
        Ok(r.and_then(|(n, node, port)| (node == self.service.node && port == self.service.port).then_some(n)))
    }

    /// Send a request and wait for its response. NMEA indications arriving
    /// meanwhile are queued for [`next_nmea`](Self::next_nmea).
    fn call(&mut self, msg_id: u16, build: impl FnOnce(u16) -> Vec<u8>) -> Outcome {
        let txn = self.txn;
        self.txn = self.txn.wrapping_add(1);
        if self.sock.send_to(&build(txn), self.service.node, self.service.port).is_err() {
            return Outcome::NoResponse;
        }
        let deadline = Instant::now() + CALL_TIMEOUT;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let n = match self.recv(left) {
                Ok(Some(n)) => n,
                Ok(None) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Outcome::NoResponse,
            };
            let Some(m) = wire::Message::parse(&self.buf[..n]) else { continue };
            if m.kind == wire::TYPE_RESPONSE && m.txn == txn && m.msg_id == msg_id {
                return Outcome::from_tlvs(m.tlvs);
            }
            if let Some(text) = nmea_of(&self.buf[..n]) {
                if self.queue.len() < QUEUE_MAX {
                    self.queue.push_back(text.to_vec());
                }
            }
        }
        Outcome::NoResponse
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.started {
            self.stop();
        }
    }
}

/// The NMEA text of `buf` if it is an EVENT_NMEA_IND indication.
fn nmea_of(buf: &[u8]) -> Option<&[u8]> {
    let m = wire::Message::parse(buf)?;
    if m.kind != wire::TYPE_INDICATION || m.msg_id != wire::MSG_EVENT_NMEA_IND {
        return None;
    }
    wire::nmea_text(m.tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmea_of_takes_only_nmea_indications() {
        let ind = [0x04, 0x01, 0x00, 0x26, 0x00, 0x06, 0x00, 0x01, 0x03, 0x00, b'$', b'G', 0];
        assert_eq!(nmea_of(&ind), Some(&b"$G"[..]));
        let mut resp = ind;
        resp[0] = wire::TYPE_RESPONSE;
        assert_eq!(nmea_of(&resp), None);
        let mut other = ind;
        other[3] = 0x27;
        assert_eq!(nmea_of(&other), None);
        assert_eq!(nmea_of(&ind[..9]), None);
    }

    #[test]
    fn error_messages_match_the_c_forwarder() {
        assert_eq!(Error::NotFound.to_string(), "LOC service (16) not found on QRTR");
    }
}
