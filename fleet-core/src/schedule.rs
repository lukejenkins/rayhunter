//! Randomised broadcast timing (anti delta-time fingerprinting).
//!
//! The first step of traffic analysis is the time between transmissions: a
//! fixed period fingerprints a node even when its frames are unreadable. The
//! hub's roster and each member's check-in are therefore spaced at random.
//! There is no RNG in here: the caller passes the random bits, which must come
//! from an unpredictable source (the OS RNG on a real device), never a counter
//! or a clock.

pub use crate::consts::{ROSTER_MAX_SECS, ROSTER_MIN_SECS};

/// Seconds until the next roster broadcast: uniform in
/// `[ROSTER_MIN_SECS, ROSTER_MAX_SECS]`.
/// `rand` must come from an unpredictable source (OS RNG on a real hub), never
/// a counter or clock.
pub fn roster_gap(rand: u32) -> u32 {
    ROSTER_MIN_SECS + scale(rand, ROSTER_MAX_SECS - ROSTER_MIN_SECS + 1)
}

/// Seconds until the next check-in: uniform in
/// `[ceil(checkin_secs / 2), checkin_secs]`, never longer than the kit
/// interval, so the hub's missed-check-in, give-up and relay-renewal
/// arithmetic is unchanged. `checkin_secs` of 0 is treated as 1.
pub fn checkin_gap(checkin_secs: u32, rand: u32) -> u32 {
    let s = checkin_secs.max(1);
    let lo = s.div_ceil(2);
    lo + scale(rand, s - lo + 1)
}

/// Maps `rand` onto `0..span` (multiply-shift: 0 -> 0, `u32::MAX` ->
/// `span - 1`; the bias is under `span / 2^32`).
fn scale(rand: u32, span: u32) -> u32 {
    ((rand as u64 * span as u64) >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    fn xorshift(state: &mut u32) -> u32 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *state = x;
        x
    }

    #[test]
    fn roster_gap_bounds() {
        assert_eq!(roster_gap(0), ROSTER_MIN_SECS);
        assert_eq!(ROSTER_MIN_SECS, 300);
        assert_eq!(ROSTER_MAX_SECS, 900);
        assert!(roster_gap(u32::MAX) <= ROSTER_MAX_SECS);
        assert!(roster_gap(u32::MAX) >= ROSTER_MIN_SECS);
    }

    #[test]
    fn roster_gap_spread() {
        let mid = (ROSTER_MIN_SECS + ROSTER_MAX_SECS) / 2;
        let (mut low, mut high) = (0, 0);
        let mut seen = BTreeSet::new();
        let mut st = 0x9e37_79b9;
        for _ in 0..10_000 {
            let g = roster_gap(xorshift(&mut st));
            assert!((ROSTER_MIN_SECS..=ROSTER_MAX_SECS).contains(&g), "{g}");
            if g < mid {
                low += 1;
            } else {
                high += 1;
            }
            seen.insert(g);
        }
        // Both halves of the range are hit, roughly evenly.
        assert!(low > 4_000 && high > 4_000, "low {low} high {high}");
        assert!(seen.len() > 500, "{} distinct gaps", seen.len());
    }

    #[test]
    fn checkin_gap_bounds() {
        for s in [900u32, 61, 60, 1, 0] {
            let eff = s.max(1);
            let lo = eff.div_ceil(2);
            let mut st = 0x1234_5678;
            let mut seen = BTreeSet::new();
            for r in [0, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX]
                .into_iter()
                .chain((0..2_000).map(|_| xorshift(&mut st)))
            {
                let g = checkin_gap(s, r);
                assert!((lo..=eff).contains(&g), "checkin_gap({s}, {r}) = {g}");
                seen.insert(g);
            }
            assert_eq!(checkin_gap(s, 0), lo);
            assert_eq!(checkin_gap(s, u32::MAX), eff);
            // Every value in a small range is reached; a wide one is spread.
            if eff <= 61 {
                assert_eq!(seen.len() as u32, eff - lo + 1, "s = {s}");
            } else {
                assert!(seen.len() > 300, "s = {s}: {} distinct", seen.len());
            }
        }
        assert_eq!(checkin_gap(0, 12345), 1);
    }
}
