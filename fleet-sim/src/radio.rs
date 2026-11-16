//! The virtual radio: link budget, hop limit, the rebroadcast rule, the
//! `Transport` adapter, and the deterministic helpers (hash, xorshift).
//! Positions live only here and in `World`; they never reach a frame.

use fleet_core::transport::{Transport, TxError, check_len};

/// A link exists when the SNR is at least this.
pub const LINK_MIN_SNR_DB: f32 = -20.0;
/// Rebroadcasts a frame may still get when first sent.
pub const HOP_LIMIT: u8 = 2;

/// Free-space-like: `10 - 30 log10(d / 100 m)` dB. Distances under 1 m are
/// taken as 1 m.
pub fn snr_db(a: (f32, f32), b: (f32, f32)) -> f32 {
    let d = ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt().max(1.0);
    10.0 - 30.0 * (d / 100.0).log10()
}

pub fn in_range(a: (f32, f32), b: (f32, f32)) -> bool {
    snr_db(a, b) >= LINK_MIN_SNR_DB
}

/// The rebroadcast rule. `relay_mode` is the radio's relay flag: always on
/// for the hub, and for a member only while `RelayState` has it on (or the
/// sim forces it). Each frame is rebroadcast at most once per node.
pub fn rebroadcast(relay_mode: bool, already_relayed: bool, hops_left: u8) -> bool {
    relay_mode && !already_relayed && hops_left > 0
}

/// One transmission on the air.
#[derive(Debug, Clone)]
pub struct Tx {
    /// World index of the transmitter; `None` for a rogue.
    pub from: Option<usize>,
    /// Radio-level node number of the transmitter (Meshtastic's relay_node):
    /// the originator, or the relay that repeated the frame.
    pub tx_node: Option<u16>,
    pub pos: (f32, f32),
    pub bytes: Vec<u8>,
    pub hops_left: u8,
}

/// The `Transport` a node's protocol code sees. Frames go to `out`;
/// `set_relay` flips the radio's relay flag.
pub struct SimTransport<'a> {
    pub out: &'a mut Vec<Vec<u8>>,
    pub relay: &'a mut bool,
}

impl Transport for SimTransport<'_> {
    fn send(&mut self, frame: &[u8]) -> Result<(), TxError> {
        check_len(frame)?;
        self.out.push(frame.to_vec());
        Ok(())
    }
    fn set_relay(&mut self, on: bool) -> Result<(), TxError> {
        *self.relay = on;
        Ok(())
    }
}

/// FNV-1a 64: the dedupe key for "this frame was already rebroadcast".
/// Stable across builds, unlike `DefaultHasher`.
pub fn frame_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// xorshift64. A zero seed is replaced, since zero is a fixed point.
#[derive(Debug, Clone)]
pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        XorShift(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// Uniform in [0, 1).
    pub fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_budget() {
        let o = (0.0, 0.0);
        assert!((snr_db(o, (100.0, 0.0)) - 10.0).abs() < 1e-4);
        assert!((snr_db(o, (300.0, 0.0)) - -4.3136).abs() < 1e-3);
        assert!((snr_db(o, (1000.0, 0.0)) - -20.0).abs() < 1e-4);
        assert!(in_range(o, (999.0, 0.0)));
        assert!(!in_range(o, (1001.0, 0.0)));
        // -12 dB is crossed at about 541 m.
        assert!(snr_db(o, (540.0, 0.0)) > -12.0 && snr_db(o, (542.0, 0.0)) < -12.0);
        assert!(snr_db(o, o).is_finite());
    }

    #[test]
    fn rebroadcast_rule() {
        assert!(rebroadcast(true, false, 1));
        assert!(!rebroadcast(false, false, 2), "muted members never relay");
        assert!(!rebroadcast(true, true, 2), "once per frame");
        assert!(!rebroadcast(true, false, 0), "hop limit");
    }

    #[test]
    fn transport_applies_check_len() {
        let (mut out, mut relay) = (Vec::new(), false);
        let mut t = SimTransport {
            out: &mut out,
            relay: &mut relay,
        };
        assert_eq!(t.send(&[0; 185]), Err(TxError::TooLarge));
        assert_eq!(t.send(&[0; 184]), Ok(()));
        t.set_relay(true).unwrap();
        assert_eq!(out.len(), 1);
        assert!(relay);
    }

    #[test]
    fn xorshift_is_deterministic() {
        let (mut a, mut b) = (XorShift::new(7), XorShift::new(7));
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(XorShift::new(0).next_u64(), 0);
    }
}
