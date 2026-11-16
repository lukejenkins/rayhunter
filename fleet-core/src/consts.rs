//! Protocol constants. Values are fixed by the Phase 3a spec.

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME: usize = 184;
pub const HEADER_LEN: usize = 12;
pub const SIG_LEN: usize = 64;
pub const MAX_BODY: usize = MAX_FRAME - HEADER_LEN - SIG_LEN;
pub const WINDOW: u32 = 600;
pub const VERDICT_INTERVAL: u32 = 600;
pub const FUTURE_SKEW: u32 = 300;
/// An already-emitted group alert keeps a supporter this long past `WINDOW`.
pub const WITHDRAW_GRACE: u32 = FUTURE_SKEW;
/// Frames (except Roster and Revocation) older than this at receipt are stale.
pub const MAX_AGE: u32 = 900;
pub const REPLAY_WINDOW: u32 = 64;
/// Counters start at `(now - event_start) * COUNTER_PER_SEC`, so the 64-counter
/// replay window spans 64 s of reordering.
pub const COUNTER_PER_SEC: u32 = 1;
pub const PENDING_MAX: usize = 16;
/// Frames from a sender with no card yet wait this long for the roster: at
/// least the longest gap between roster broadcasts.
pub const PENDING_TTL: u32 = 900;
/// The hub's roster broadcasts are spaced uniformly at random in
/// `[ROSTER_MIN_SECS, ROSTER_MAX_SECS]` (`schedule::roster_gap`), so the gap
/// between them does not fingerprint the hub.
pub const ROSTER_MIN_SECS: u32 = 300;
pub const ROSTER_MAX_SECS: u32 = 900;
const _: () = assert!(
    PENDING_TTL >= ROSTER_MAX_SECS,
    "a pending frame must outlive the longest roster gap"
);
const _: () = assert!(ROSTER_MIN_SECS > 0 && ROSTER_MIN_SECS <= ROSTER_MAX_SECS);
pub const TEXT_MAX: usize = 96;
pub const KIT_MAX: usize = 1024;
pub const PHRASES_MAX: usize = 32;
pub const PHRASE_LEN_MAX: usize = 40;
pub const POINTS_MAX: usize = 16;
pub const POINT_LEN_MAX: usize = 24;
pub const TABLES_BYTES_MAX: usize = 400;
/// Longest kit check-in interval: an order (2 x interval, capped at 60 min)
/// must outlast two intervals to be renewed in time.
pub const CHECKIN_MINUTES_MAX: u8 = 30;
pub const RELAY_MINUTES: u8 = 15;
pub const RELAYS_MAX: usize = 2;
pub const WEAK_SNR_DB: i8 = -12;
pub const GOOD_SNR_DB: i8 = -6;
pub const MISSED_CHECKINS: u8 = 2;
/// A member silent this many check-in intervals is no longer planned for.
pub const GIVE_UP_CHECKINS: u32 = 6;
pub const SNR_UNKNOWN: i8 = i8::MIN;
pub const TAG_LEN: usize = 8;

/// Card length on the wire.
pub const CARD_LEN: usize = 103;

// Domain-separation prefixes: prepended before signing or HMAC, never sent.
pub const DOM_FRAME: &[u8] = b"RHF1";
pub const DOM_CARD: &[u8] = b"RHC1";
pub const DOM_KIT: &[u8] = b"RHK1";
pub const DOM_REVOKE: &[u8] = b"RHR1";
pub const DOM_TAG: &[u8] = b"RHT1";
