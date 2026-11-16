//! Per-sender replay window: the highest counter seen plus a 64-bit bitmap of
//! the counters just below it.

use crate::consts::REPLAY_WINDOW;

/// Bit `i` of `bits` means counter `highest - i` was seen. `bits == 0` means
/// nothing has been seen yet (once anything is seen, bit 0 is always set).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Window {
    highest: u32,
    bits: u64,
}

impl Window {
    pub fn new() -> Self {
        Window::default()
    }

    /// True if `c` is new (and records it); false for a replay or a counter
    /// at or beyond `REPLAY_WINDOW` behind the highest seen.
    pub fn check_and_set(&mut self, c: u32) -> bool {
        if self.bits == 0 {
            self.highest = c;
            self.bits = 1;
            return true;
        }
        if c > self.highest {
            let shift = c - self.highest;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.highest = c;
            return true;
        }
        let d = self.highest - c;
        if d >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64 << d;
        if self.bits & bit != 0 {
            return false;
        }
        self.bits |= bit;
        true
    }
}
