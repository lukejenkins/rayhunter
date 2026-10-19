// SPDX-License-Identifier: Apache-2.0
//! A QRTR datagram socket and the name-service lookup.
//!
//! Interface facts used here (Linux uapi `linux/qrtr.h`): address family 42,
//! `sockaddr_qrtr` = u16 family, u32 node, u32 port; the control port is
//! 0xFFFFFFFE; a control packet is u32 command then u32 service, instance,
//! node, port (little-endian). NEW_SERVER = 4, NEW_LOOKUP = 10.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

pub const AF_QIPCRTR: libc::c_int = 42;
pub const PORT_CTRL: u32 = 0xFFFF_FFFE;
pub const CMD_NEW_SERVER: u32 = 4;
pub const CMD_NEW_LOOKUP: u32 = 10;
pub const CTRL_PKT_LEN: usize = 20;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrQrtr {
    sq_family: libc::sa_family_t,
    sq_node: u32,
    sq_port: u32,
}

/// One entry of the QRTR name service: where a QMI service is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub service: u32,
    /// QRTR packs the QMI service version in the low byte of the instance
    /// field and the instance number above it.
    pub version: u32,
    pub instance: u32,
    pub node: u32,
    pub port: u32,
}

/// A NEW_LOOKUP control packet for `service`, any version and instance.
pub fn lookup_packet(service: u32) -> [u8; CTRL_PKT_LEN] {
    let mut p = [0u8; CTRL_PKT_LEN];
    p[0..4].copy_from_slice(&CMD_NEW_LOOKUP.to_le_bytes());
    p[4..8].copy_from_slice(&service.to_le_bytes());
    p
}

/// What the name service sent back for a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupReply {
    Server(Service),
    /// The all-zero NEW_SERVER that ends the list.
    End,
}

/// Decode a control packet. `None` for anything but a full NEW_SERVER.
pub fn parse_lookup_reply(pkt: &[u8]) -> Option<LookupReply> {
    if pkt.len() < CTRL_PKT_LEN {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes(pkt[i..i + 4].try_into().unwrap());
    if w(0) != CMD_NEW_SERVER {
        return None;
    }
    let (service, instance, node, port) = (w(4), w(8), w(12), w(16));
    if service == 0 && node == 0 && port == 0 {
        return Some(LookupReply::End);
    }
    Some(LookupReply::Server(Service { service, version: instance & 0xFF, instance: instance >> 8, node, port }))
}

/// A blocking `AF_QIPCRTR` datagram socket.
#[derive(Debug)]
pub struct QrtrSocket {
    fd: OwnedFd,
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

impl QrtrSocket {
    pub fn new() -> io::Result<Self> {
        let fd = cvt(unsafe { libc::socket(AF_QIPCRTR, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
        Ok(QrtrSocket { fd: unsafe { OwnedFd::from_raw_fd(fd) } })
    }

    /// This socket's own node: where the local name service listens.
    pub fn local_node(&self) -> io::Result<u32> {
        let mut sa: SockaddrQrtr = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<SockaddrQrtr>() as libc::socklen_t;
        cvt(unsafe { libc::getsockname(self.as_raw_fd(), &mut sa as *mut _ as *mut libc::sockaddr, &mut len) })?;
        Ok(sa.sq_node)
    }

    pub fn send_to(&self, buf: &[u8], node: u32, port: u32) -> io::Result<()> {
        let sa = SockaddrQrtr { sq_family: AF_QIPCRTR as libc::sa_family_t, sq_node: node, sq_port: port };
        let r = unsafe {
            libc::sendto(
                self.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<SockaddrQrtr>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait up to `timeout` for one datagram. `Ok(None)` on timeout; an
    /// interrupting signal is returned as `ErrorKind::Interrupted`. On success
    /// returns the length and the sender's node and port.
    pub fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<(usize, u32, u32)>> {
        let mut pfd = libc::pollfd { fd: self.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        if cvt(unsafe { libc::poll(&mut pfd, 1, ms) })? == 0 {
            return Ok(None);
        }
        let mut sa: SockaddrQrtr = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<SockaddrQrtr>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
                &mut sa as *mut _ as *mut libc::sockaddr,
                &mut len,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock { Ok(None) } else { Err(e) };
        }
        Ok(Some((n as usize, sa.sq_node, sa.sq_port)))
    }

    /// Ask the local name service where `service` is served. Returns the first
    /// match, or `None` if the list ends (or `timeout` passes) without one.
    pub fn lookup(&self, service: u32, timeout: Duration) -> io::Result<Option<Service>> {
        let node = self.local_node()?;
        self.send_to(&lookup_packet(service), node, PORT_CTRL)?;
        let deadline = Instant::now() + timeout;
        let mut found = None;
        let mut buf = [0u8; 64];
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            let (n, _, port) = match self.recv_from(&mut buf, left) {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if port != PORT_CTRL {
                continue;
            }
            match parse_lookup_reply(&buf[..n]) {
                Some(LookupReply::End) => break,
                Some(LookupReply::Server(s)) if s.service == service && found.is_none() => found = Some(s),
                _ => {}
            }
        }
        Ok(found)
    }
}

impl AsRawFd for QrtrSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_matches_uapi_size() {
        assert_eq!(mem::size_of::<SockaddrQrtr>(), 12);
    }

    #[test]
    fn lookup_packet_bytes() {
        let want = [10, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(lookup_packet(16), want);
    }

    #[test]
    fn new_server_decodes_version_and_instance() {
        // Measured on an Orbic R500L5: "16 v2 inst 0 node 3 port 81".
        let pkt = [4, 0, 0, 0, 16, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 81, 0, 0, 0];
        let want = Service { service: 16, version: 2, instance: 0, node: 3, port: 81 };
        assert_eq!(parse_lookup_reply(&pkt), Some(LookupReply::Server(want)));
        let pkt = [4, 0, 0, 0, 16, 0, 0, 0, 0x02, 0x01, 0, 0, 3, 0, 0, 0, 81, 0, 0, 0];
        match parse_lookup_reply(&pkt) {
            Some(LookupReply::Server(s)) => assert_eq!((s.version, s.instance), (2, 1)),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn end_marker_other_commands_and_short_packets() {
        let mut end = [0u8; 20];
        end[0] = 4;
        assert_eq!(parse_lookup_reply(&end), Some(LookupReply::End));
        let mut del = end;
        del[0] = 5; // DEL_SERVER
        assert_eq!(parse_lookup_reply(&del), None);
        assert_eq!(parse_lookup_reply(&end[..19]), None);
    }
}
