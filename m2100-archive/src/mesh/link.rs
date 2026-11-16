//! Meshtastic serial session: wake the radio, run the config handshake, send texts, disconnect.
//! Only wake bytes, want_config, text packets and disconnect are ever written. Everything
//! read back is discarded (only config_complete_id is inspected) and never logged.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::mesh::wire::{
    FrameReader, MAX_TEXT, config_complete_id, disconnect, frame, text_packet, want_config,
};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WAKE_PAUSE: Duration = Duration::from_millis(100);
/// Between texts, and after the last one before disconnect.
const TEXT_PAUSE: Duration = Duration::from_millis(500);
/// The port timeout for the writes after the handshake.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const WAKE_BYTES: usize = 32;

/// The radio did not send config_complete_id with our nonce in time.
#[derive(Debug)]
pub struct HandshakeTimeout;

impl std::fmt::Display for HandshakeTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "radio did not complete the handshake")
    }
}

impl std::error::Error for HandshakeTimeout {}

/// The serial port could not be opened (the radio is unplugged, or not this path).
#[derive(Debug)]
pub struct NoRadio;

impl std::fmt::Display for NoRadio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "radio port could not be opened")
    }
}

pub trait Link {
    /// Bounded by the port timeout; never drains (a `tcdrain` has no timeout).
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()>;
    /// The port timeout for the writes (and reads) that follow.
    fn set_timeout(&mut self, t: Duration) -> std::io::Result<()>;
    /// Ok(0) on timeout.
    fn read_some(&mut self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize>;
}

pub struct SerialLink {
    port: Box<dyn serialport::SerialPort>,
}

/// Open a serial port at 115200 8N1.
pub fn open(path: &str) -> Result<SerialLink> {
    let port = serialport::new(path, 115_200)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| anyhow::Error::new(e).context(NoRadio))?;
    Ok(SerialLink { port })
}

impl Link for SerialLink {
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.port.write_all(b)
    }

    fn set_timeout(&mut self, t: Duration) -> std::io::Result<()> {
        self.port.set_timeout(t)?;
        Ok(())
    }

    fn read_some(&mut self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        use std::io::Read;
        self.port.set_timeout(timeout.max(Duration::from_millis(1)))?;
        match self.port.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Run one session and send each text. Returns how many texts were written.
pub fn send_texts(
    link: &mut dyn Link,
    texts: &[String],
    rand: &mut dyn FnMut() -> u32,
) -> Result<usize> {
    send_texts_with(link, texts, rand, HANDSHAKE_TIMEOUT, TEXT_PAUSE)
}

fn send_texts_with(
    link: &mut dyn Link,
    texts: &[String],
    rand: &mut dyn FnMut() -> u32,
    handshake_timeout: Duration,
    text_pause: Duration,
) -> Result<usize> {
    // Validate before touching the radio, as the texts will go on air (bell included).
    let texts: Vec<String> = texts.iter().map(|t| crate::mesh::on_air(t)).collect();
    if let Some(t) = texts.iter().find(|t| t.len() > MAX_TEXT) {
        anyhow::bail!("mesh text is {} bytes, over the {} byte limit", t.len(), MAX_TEXT);
    }

    link.write_all(&[0xC3u8; WAKE_BYTES])?;
    std::thread::sleep(WAKE_PAUSE);

    let nonce = rand();
    link.write_all(&frame(&want_config(nonce)))?;

    let mut reader = FrameReader::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + handshake_timeout;
    let mut discarded = 0usize;
    'handshake: loop {
        let now = Instant::now();
        if now >= deadline {
            // The caller warns, with the batch in hand.
            log::debug!("mesh: handshake timed out ({discarded} bytes discarded)");
            return Err(HandshakeTimeout.into());
        }
        let n = link.read_some(&mut buf, deadline - now)?;
        discarded += n;
        if n == 0 {
            continue;
        }
        for payload in reader.push(&buf[..n]) {
            if config_complete_id(&payload) == Some(nonce) {
                break 'handshake;
            }
        }
    }

    // Whatever the handshake reads left of its deadline is no bound for the writes.
    link.set_timeout(WRITE_TIMEOUT)?;

    let mut sent = 0;
    for (i, text) in texts.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(text_pause);
        }
        let id = rand() | 1;
        link.write_all(&frame(&text_packet(text, id)))?;
        sent += 1;
    }

    // Let the radio take the last text before the session ends.
    std::thread::sleep(text_pause);
    link.write_all(&frame(&disconnect()))?;
    // The caller logs the outcome, with the batch in hand.
    log::debug!("mesh: sent {sent} text(s), {discarded} bytes discarded");
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeLink {
        written: Vec<u8>,
        to_read: VecDeque<Vec<u8>>,
        /// (bytes written before the call, timeout) per `set_timeout`.
        timeouts: Vec<(usize, Duration)>,
        /// When each write happened.
        write_at: Vec<Instant>,
    }

    impl FakeLink {
        fn new(to_read: Vec<Vec<u8>>) -> Self {
            Self { written: Vec::new(), to_read: to_read.into(), timeouts: Vec::new(), write_at: Vec::new() }
        }
    }

    impl Link for FakeLink {
        fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
            self.written.extend_from_slice(b);
            self.write_at.push(Instant::now());
            Ok(())
        }
        fn set_timeout(&mut self, t: Duration) -> std::io::Result<()> {
            self.timeouts.push((self.written.len(), t));
            Ok(())
        }
        fn read_some(&mut self, buf: &mut [u8], _t: Duration) -> std::io::Result<usize> {
            match self.to_read.pop_front() {
                Some(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Ok(0),
            }
        }
    }

    /// FromRadio { config_complete_id = id } (field 7, varint).
    fn config_complete(id: u32) -> Vec<u8> {
        let mut p = vec![0x38];
        let mut v = u64::from(id);
        while v >= 0x80 {
            p.push((v as u8) | 0x80);
            v >>= 7;
        }
        p.push(v as u8);
        frame(&p)
    }

    fn rand_seq(vals: Vec<u32>) -> impl FnMut() -> u32 {
        let mut it = vals.into_iter();
        move || it.next().expect("rand exhausted")
    }

    const SHORT: Duration = Duration::from_millis(50);

    #[test]
    fn sends_texts_after_matching_config_complete() {
        let n = 0x00abcdef;
        let mut noise = b"DEBUG | boot noise\r\n".to_vec();
        noise.extend(config_complete(n));
        let mut link = FakeLink::new(vec![noise]);
        let mut rand = rand_seq(vec![n, 41]);
        let r = send_texts_with(&mut link, &["x".to_string()], &mut rand, SHORT, Duration::ZERO).unwrap();
        assert_eq!(r, 1);
        let mut want = vec![0xC3u8; 32];
        want.extend(frame(&want_config(n)));
        want.extend(frame(&text_packet("x\u{7}", 41)));
        want.extend(frame(&disconnect()));
        assert_eq!(link.written, want);
    }

    #[test]
    fn ignores_config_complete_with_other_nonce() {
        let mut link = FakeLink::new(vec![config_complete(7)]);
        let mut rand = rand_seq(vec![9, 41]);
        let r = send_texts_with(&mut link, &["x".to_string()], &mut rand, SHORT, Duration::ZERO);
        assert!(r.is_err());
        assert!(!contains(&link.written, &frame(&text_packet("x\u{7}", 41))));
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn no_config_complete_is_an_error_and_sends_nothing() {
        let mut link = FakeLink::new(vec![]);
        let mut rand = rand_seq(vec![9, 41]);
        let r = send_texts_with(&mut link, &["x".to_string()], &mut rand, SHORT, Duration::ZERO);
        let e = r.unwrap_err();
        assert!(e.downcast_ref::<HandshakeTimeout>().is_some());
        let mut want = vec![0xC3u8; 32];
        want.extend(frame(&want_config(9)));
        assert_eq!(link.written, want);
    }

    #[test]
    fn packet_id_is_never_zero() {
        let n = 5;
        let mut link = FakeLink::new(vec![config_complete(n)]);
        let mut rand = rand_seq(vec![n, 0]);
        send_texts_with(&mut link, &["x".to_string()], &mut rand, SHORT, Duration::ZERO).unwrap();
        assert!(contains(&link.written, &frame(&text_packet("x\u{7}", 1))));
    }

    /// Receivers mute the channel and alert on the bell: everything buzzes but the ping.
    #[test]
    fn bell_on_every_text_but_the_quiet_ping() {
        let n = 7;
        let mut link = FakeLink::new(vec![config_complete(n)]);
        let mut rand = rand_seq(vec![n, 41, 43]);
        let texts = ["Home alert".to_string(), crate::mesh::QUIET_TEXT.to_string()];
        send_texts_with(&mut link, &texts, &mut rand, SHORT, Duration::ZERO).unwrap();
        assert!(contains(&link.written, &frame(&text_packet("Home alert\u{7}", 41))));
        assert!(contains(&link.written, &frame(&text_packet(crate::mesh::QUIET_TEXT, 43))));
        assert!(!contains(&link.written, &frame(&text_packet(&format!("{}\u{7}", crate::mesh::QUIET_TEXT), 43))));
    }

    #[test]
    fn a_full_length_text_has_no_room_for_the_bell() {
        let mut link = FakeLink::new(vec![]);
        let mut rand = rand_seq(vec![1, 2]);
        assert!(send_texts(&mut link, &["a".repeat(MAX_TEXT)], &mut rand).is_err());
        assert!(link.written.is_empty());
    }

    #[test]
    fn over_long_text_is_an_error_and_writes_nothing() {
        let mut link = FakeLink::new(vec![]);
        let mut rand = rand_seq(vec![1, 2]);
        let t = "a".repeat(MAX_TEXT + 1);
        assert!(send_texts(&mut link, &[t], &mut rand).is_err());
        assert!(link.written.is_empty());
    }

    /// M3: writes after the handshake get a fresh 1 s timeout, not what the handshake left.
    #[test]
    fn timeout_is_reset_to_one_second_after_the_handshake() {
        let n = 3;
        let mut link = FakeLink::new(vec![config_complete(n)]);
        let mut rand = rand_seq(vec![n, 41]);
        send_texts_with(&mut link, &["x".to_string()], &mut rand, SHORT, Duration::ZERO).unwrap();
        let handshake_bytes = WAKE_BYTES + frame(&want_config(n)).len();
        assert_eq!(link.timeouts, [(handshake_bytes, Duration::from_secs(1))]);
    }

    /// M4: the radio gets a pause between texts and after the last one, before disconnect.
    #[test]
    fn pauses_between_texts_and_before_disconnect() {
        let n = 3;
        let pause = Duration::from_millis(30);
        let mut link = FakeLink::new(vec![config_complete(n)]);
        let mut rand = rand_seq(vec![n, 41, 43]);
        let texts = ["x".to_string(), "y".to_string()];
        send_texts_with(&mut link, &texts, &mut rand, SHORT, pause).unwrap();
        // writes: wake, want_config, text x, text y, disconnect
        let w = &link.write_at;
        assert_eq!(w.len(), 5);
        assert!(w[3] - w[2] >= pause, "between texts");
        assert!(w[4] - w[3] >= pause, "before disconnect");
        assert!(link.written.ends_with(&frame(&disconnect())));
    }
}
