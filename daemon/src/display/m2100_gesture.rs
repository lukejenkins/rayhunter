//! The reveal-gesture vocabulary: 7 moves the vendor UI ignores on its home
//! screen (measured 2026-10-06; see the spec, section 2). Four swipe directions,
//! and a touch in one of three status-bar zones. A status-bar move is WHERE you
//! touch, never how long: calibration on 2026-10-08 found no tap/hold line that
//! one person's presses stayed on the right side of (spec section 3c).

use std::time::Duration;

const PANEL_WIDTH: i32 = 320;
/// The vendor's status bar on its home screen: inert to taps and holds.
pub const BAR_HEIGHT: i32 = 40;
/// Travel beyond this is a swipe, whatever its duration or start. Measured on
/// the device: comfortable vertical swipes on the 240 px panel travel ~96 px,
/// while taps move at most ~8 px, so 60 leaves a wide margin on both sides.
pub const SWIPE_MIN: i32 = 60;
/// A longer gap between moves starts the entry over.
pub const MOVE_GAP: Duration = Duration::from_secs(2);
/// Five, not four: with 7 moves that is 16,807 gestures, more than the 10,000
/// the old 10-move vocabulary gave at four.
pub const MIN_LEN: usize = 5;
pub const MAX_LEN: usize = 8;
/// Too close to a zone boundary to be sure. Discarding costs the person one
/// repeated move; guessing would enter a wrong one they cannot detect.
const ZONE_MARGIN: i32 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Up,
    Down,
    Left,
    Right,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Zone {
    Left,
    Middle,
    Right,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Move {
    Swipe(Dir),
    Bar(Zone),
}

impl Move {
    /// Stable 0..=6 code; what gets hashed. Never reorder these. (Was 0..=9
    /// with tap and hold; any gesture stored before 2026-10-08 must be re-set.)
    pub fn code(self) -> u8 {
        match self {
            Move::Swipe(Dir::Up) => 0,
            Move::Swipe(Dir::Down) => 1,
            Move::Swipe(Dir::Left) => 2,
            Move::Swipe(Dir::Right) => 3,
            Move::Bar(Zone::Left) => 4,
            Move::Bar(Zone::Middle) => 5,
            Move::Bar(Zone::Right) => 6,
        }
    }
}

/// One completed touch, assembled by the watcher on release.
#[derive(Clone, Copy, Debug)]
pub struct Touch {
    pub start: (i32, i32),
    pub end: (i32, i32),
    pub held: Duration,
}

pub fn classify(t: &Touch) -> Option<Move> {
    let dx = t.end.0 - t.start.0;
    let dy = t.end.1 - t.start.1;
    // Travel first: a swipe that starts in the bar is still a swipe.
    if dx.abs().max(dy.abs()) > SWIPE_MIN {
        let d = if dx.abs() >= dy.abs() {
            if dx > 0 { Dir::Right } else { Dir::Left }
        } else if dy > 0 {
            Dir::Down
        } else {
            Dir::Up
        };
        return Some(Move::Swipe(d));
    }
    let (x, y) = t.start;
    if !(0..BAR_HEIGHT).contains(&y) {
        return None;
    }
    let (b1, b2) = (PANEL_WIDTH / 3, 2 * PANEL_WIDTH / 3);
    if (x - b1).abs() < ZONE_MARGIN || (x - b2).abs() < ZONE_MARGIN {
        return None;
    }
    let zone = if x < b1 {
        Zone::Left
    } else if x < b2 {
        Zone::Middle
    } else {
        Zone::Right
    };
    Some(Move::Bar(zone))
}

/// Rolling window over the last `len` moves, as the PIN pad does: a fumbled
/// start slides out without needing a reset.
pub struct Matcher {
    len: usize,
    window: Vec<u8>,
    last: Option<std::time::Instant>,
}

impl Matcher {
    pub fn new(len: usize) -> Matcher {
        Matcher {
            len,
            window: Vec::with_capacity(len),
            last: None,
        }
    }

    /// `pressed` and `released` bound the touch that made this move. The pause
    /// that starts an entry over is measured from the previous RELEASE to this
    /// PRESS: time with a finger on the glass is never a pause. Measuring release
    /// to release made a ~2 s hold read as a ~3 s gap (2026-10-08).
    pub fn push(
        &mut self,
        code: u8,
        pressed: std::time::Instant,
        released: std::time::Instant,
    ) -> Option<Vec<u8>> {
        if self
            .last
            .is_some_and(|l| pressed.saturating_duration_since(l) > MOVE_GAP)
        {
            self.window.clear();
        }
        self.last = Some(released);
        self.window.push(code);
        if self.window.len() > self.len {
            self.window.remove(0);
        }
        (self.window.len() == self.len).then(|| self.window.clone())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn reset(&mut self) {
        self.window.clear();
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(start: (i32, i32), end: (i32, i32), ms: u64) -> Touch {
        Touch {
            start,
            end,
            held: Duration::from_millis(ms),
        }
    }

    #[test]
    fn measured_swipes_classify_by_direction() {
        // Real traces from the 2026-10-06 test session.
        assert_eq!(
            classify(&touch((186, 224), (190, 24), 580)),
            Some(Move::Swipe(Dir::Up))
        );
        assert_eq!(
            classify(&touch((204, 0), (197, 226), 650)),
            Some(Move::Swipe(Dir::Down))
        );
        assert_eq!(
            classify(&touch((308, 104), (16, 99), 590)),
            Some(Move::Swipe(Dir::Left))
        );
        assert_eq!(
            classify(&touch((17, 106), (300, 122), 380)),
            Some(Move::Swipe(Dir::Right))
        );
    }

    #[test]
    fn a_swipe_starting_in_the_status_bar_is_a_swipe() {
        // Review focus 1: people start a downward swipe at the very top.
        assert_eq!(
            classify(&touch((160, 5), (162, 200), 400)),
            Some(Move::Swipe(Dir::Down))
        );
    }

    #[test]
    fn measured_status_bar_touches_classify_by_zone() {
        assert_eq!(
            classify(&touch((42, 31), (43, 36), 110)),
            Some(Move::Bar(Zone::Left))
        );
        assert_eq!(
            classify(&touch((181, 28), (184, 39), 900)),
            Some(Move::Bar(Zone::Middle))
        );
        assert_eq!(
            classify(&touch((306, 44), (306, 44), 1790)),
            None,
            "y=44 is below the bar"
        );
        assert_eq!(
            classify(&touch((306, 30), (306, 30), 1790)),
            Some(Move::Bar(Zone::Right))
        );
    }

    #[test]
    fn a_status_bar_move_is_its_zone_however_long_the_press() {
        // 2026-10-08 calibration on unit 1. One person's presses, by style:
        // true taps 102-214 ms; the taps the vendor UI registers 462-600 ms
        // (aimed mid-bar) and 663-826 ms (aimed at the top edge); holds
        // 937-1192 ms and 1571-1788 ms. No single tap/hold line fits them all
        // -- a tap aimed at the edge outlasted a hold aimed mid-bar -- so a
        // status-bar move is WHERE, never how long.
        for ms in [102, 214, 462, 600, 663, 826, 937, 1192, 1571, 1788] {
            assert_eq!(
                classify(&touch((40, 20), (40, 20), ms)),
                Some(Move::Bar(Zone::Left)),
                "{ms} ms"
            );
        }
    }

    #[test]
    fn touches_aimed_at_the_top_edge_land_in_the_bar() {
        // 2026-10-08: aiming at the glass edge put every touch at y 10-25.
        // Aiming at the middle of the strip, perspective put 5 of 9 at y 41-55.
        for y in [10, 11, 12, 15, 18, 19, 22, 24, 25] {
            assert!(classify(&touch((280, y), (280, y), 700)).is_some(), "y={y}");
        }
    }

    #[test]
    fn touches_below_the_bar_that_are_not_swipes_are_not_moves() {
        // Taps and holds there open vendor menus; they must never count.
        assert_eq!(classify(&touch((75, 62), (75, 62), 100)), None);
        assert_eq!(classify(&touch((160, 120), (170, 130), 2500)), None);
    }

    #[test]
    fn a_touch_on_a_zone_boundary_is_discarded_not_guessed() {
        assert_eq!(classify(&touch((106, 20), (106, 20), 100)), None);
        assert_eq!(classify(&touch((213, 20), (213, 20), 100)), None);
    }

    #[test]
    fn short_vertical_swipes_from_the_device_test_still_count() {
        // 2026-10-07 on-device enrolment: comfortable upward swipes on a 240 px
        // panel travelled 96-100 px and were dropped by a 100 px minimum.
        assert_eq!(
            classify(&touch((81, 158), (77, 58), 370)),
            Some(Move::Swipe(Dir::Up))
        );
        assert_eq!(
            classify(&touch((70, 160), (64, 64), 650)),
            Some(Move::Swipe(Dir::Up))
        );
    }

    #[test]
    fn real_taps_never_travel_far_enough_to_be_swipes() {
        // The same session's taps moved at most 8 px.
        assert_eq!(classify(&touch((44, 42), (48, 48), 90)), None);
        assert_eq!(classify(&touch((65, 46), (65, 54), 200)), None);
        assert_eq!(
            classify(&touch((47, 30), (51, 38), 80)),
            Some(Move::Bar(Zone::Left))
        );
    }

    #[test]
    fn every_move_has_a_distinct_code_in_range() {
        let mut all = vec![];
        for d in [Dir::Up, Dir::Down, Dir::Left, Dir::Right] {
            all.push(Move::Swipe(d));
        }
        for z in [Zone::Left, Zone::Middle, Zone::Right] {
            all.push(Move::Bar(z));
        }
        let mut codes: Vec<u8> = all.iter().map(|m| m.code()).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes, (0..=6).collect::<Vec<u8>>());
    }

    #[test]
    fn seven_moves_need_five_of_them_to_beat_the_old_vocabulary() {
        // 10 moves at length 4 gave 10,000 gestures; 7 at length 5 gives 16,807.
        assert_eq!(MIN_LEN, 5);
        assert!(7u32.pow(MIN_LEN as u32) > 10u32.pow(4));
    }

    use std::time::Instant;

    #[test]
    fn the_window_is_returned_once_full() {
        let t = Instant::now();
        let mut m = Matcher::new(4);
        assert_eq!(m.push(1, t, t), None);
        assert_eq!(m.push(2, t, t), None);
        assert_eq!(m.push(3, t, t), None);
        assert_eq!(m.push(4, t, t), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn a_fumbled_start_slides_out_of_the_window() {
        let t = Instant::now();
        let mut m = Matcher::new(4);
        m.push(9, t, t);
        m.push(1, t, t);
        m.push(2, t, t);
        m.push(3, t, t);
        assert_eq!(m.push(4, t, t), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn a_long_gap_starts_over() {
        let t = Instant::now();
        let mut m = Matcher::new(4);
        m.push(1, t, t);
        m.push(2, t, t);
        m.push(3, t, t);
        let later = t + MOVE_GAP + Duration::from_millis(1);
        assert_eq!(m.push(4, later, later), None, "the first three were stale");
    }

    #[test]
    fn the_gap_is_measured_on_the_callers_monotonic_clock() {
        // Review focus 5: nothing here may read wall-clock time. The device boots
        // in 1970 and jumps to 2026; only the Instants passed in may matter.
        let t = Instant::now();
        let mut m = Matcher::new(2);
        m.push(1, t, t);
        assert_eq!(
            m.push(
                2,
                t + Duration::from_millis(1999),
                t + Duration::from_millis(1999)
            ),
            Some(vec![1, 2])
        );
    }

    #[test]
    fn a_long_hold_is_not_a_pause() {
        // 2026-10-08, third reveal test on unit 1: each move pressed about 1 s
        // after the last, then held about 2 s. Measured release to release the
        // gap read ~3 s, so the entry started over mid-gesture.
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut m = Matcher::new(3);
        m.push(1, t, t);
        m.push(2, t + ms(1000), t + ms(3100));
        assert_eq!(m.push(3, t + ms(4100), t + ms(6200)), Some(vec![1, 2, 3]));
    }

    #[test]
    fn the_pause_is_between_touches_not_during_them() {
        let t = Instant::now();
        let mut m = Matcher::new(2);
        m.push(1, t, t);
        let press = t + MOVE_GAP + Duration::from_millis(1);
        assert_eq!(
            m.push(2, press, press + Duration::from_millis(100)),
            None,
            "a real pause before the press still starts over"
        );
    }
}
