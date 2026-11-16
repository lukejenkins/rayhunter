//! Enrolment: setting the reveal gesture or panic PIN by performing it on the
//! panel, and the file protocol the helper script uses to start it.

use crate::display::m2100_secret::{self, Secret};
use std::path::PathBuf;

pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn device() -> Paths {
        Paths {
            dir: PathBuf::from("/data/rayhunter"),
        }
    }
    pub fn reveal(&self) -> PathBuf {
        self.dir.join(".reveal")
    }
    pub fn panic(&self) -> PathBuf {
        self.dir.join(".panic")
    }
    pub fn request(&self) -> PathBuf {
        self.dir.join(".enrol_request")
    }
    pub fn result(&self) -> PathBuf {
        self.dir.join(".enrol_result")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Request {
    Gesture,
    Pin,
    Reload,
}

/// Read and delete the request. Deleted even when unreadable or unknown, so a
/// bad request can never loop.
pub fn take_request(p: &Paths) -> Option<Request> {
    let body = std::fs::read_to_string(p.request()).ok();
    let _ = std::fs::remove_file(p.request());
    match body?.trim() {
        "gesture" => Some(Request::Gesture),
        "pin" => Some(Request::Pin),
        "reload" => Some(Request::Reload),
        other => {
            log::warn!("enrol: ignoring unknown request ({} bytes)", other.len());
            None
        }
    }
}

pub fn write_result(p: &Paths, s: &str) {
    if let Err(e) = m2100_secret::write_atomic(&p.result(), &format!("{s}\n")) {
        log::warn!("enrol: couldn't write result: {e}");
    }
}

pub fn load_reveal(p: &Paths) -> Option<Secret> {
    Secret::from_lines(&std::fs::read_to_string(p.reveal()).ok()?)
}

pub fn save_reveal(p: &Paths, codes: &[u8]) -> std::io::Result<()> {
    m2100_secret::write_atomic(&p.reveal(), &Secret::create(codes).to_lines())
}

use crate::display::m2100_gesture::{MAX_LEN, MIN_LEN};
use std::time::{Duration, Instant};

/// A pause this long ends one performance.
pub const PERFORM_END: Duration = Duration::from_secs(3);
/// The whole enrolment gives up after this.
pub const ENROL_TIMEOUT: Duration = Duration::from_secs(120);
/// Six is the practical floor (see the PIN pad's rolling-window analysis).
pub const PIN_MIN: usize = 6;
pub const PIN_MAX: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Gesture,
    Pin,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    TooShort,
    TooLong,
    TooSimple,
    Mismatch,
    WrongCurrent,
    TimedOut,
}

/// Deliberately no `Debug` detail beyond the outcome: `Done` carries the codes
/// only so the caller can store them, and the caller never logs a `Stage`.
#[derive(Clone, PartialEq, Eq)]
pub enum Stage {
    Verify,
    First,
    Confirm,
    Done(Vec<u8>),
    Failed(Fail),
}

impl std::fmt::Debug for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage::Verify => write!(f, "Verify"),
            Stage::First => write!(f, "First"),
            Stage::Confirm => write!(f, "Confirm"),
            Stage::Done(c) => write!(f, "Done({} items)", c.len()),
            Stage::Failed(x) => write!(f, "Failed({x:?})"),
        }
    }
}

pub struct Enrolment {
    pub target: Target,
    verify: Option<Secret>,
    stage: Stage,
    first: Vec<u8>,
    current: Vec<u8>,
    last: Option<Instant>,
    /// A finger is on the glass. The performance-ended timer waits for it.
    held: bool,
    started: Instant,
}

impl Enrolment {
    pub fn new(target: Target, verify: Option<Secret>, now: Instant) -> Enrolment {
        let stage = if verify.is_some() {
            Stage::Verify
        } else {
            Stage::First
        };
        Enrolment {
            target,
            verify,
            stage,
            first: vec![],
            current: vec![],
            last: None,
            held: false,
            started: now,
        }
    }

    pub fn stage(&self) -> &Stage {
        &self.stage
    }
    pub fn progress(&self) -> usize {
        self.current.len()
    }

    pub fn push(&mut self, code: u8, now: Instant) {
        if matches!(self.stage, Stage::Verify | Stage::First | Stage::Confirm) {
            self.current.push(code);
            self.last = Some(now);
        }
    }

    /// A touch began. Until it ends, the performance can't be over: the 3 s
    /// pause is measured between touches, never during one (2026-10-08).
    pub fn touch_down(&mut self, _now: Instant) {
        self.held = true;
    }

    /// A touch ended, recognised as a move or not. The pause runs from here.
    pub fn touch_up(&mut self, now: Instant) {
        self.held = false;
        if !self.current.is_empty() {
            self.last = Some(now);
        }
    }

    pub fn tick(&mut self, now: Instant) {
        if matches!(self.stage, Stage::Done(_) | Stage::Failed(_)) {
            return;
        }
        if now.saturating_duration_since(self.started) > ENROL_TIMEOUT {
            self.stage = Stage::Failed(Fail::TimedOut);
            return;
        }
        if self.held {
            return;
        }
        let ended = !self.current.is_empty()
            && self
                .last
                .is_some_and(|l| now.saturating_duration_since(l) > PERFORM_END);
        if !ended {
            return;
        }
        let performed = std::mem::take(&mut self.current);
        self.stage = match self.stage {
            Stage::Verify => {
                if self.verify.as_ref().is_some_and(|s| s.matches(&performed)) {
                    self.verify = None;
                    Stage::First
                } else {
                    Stage::Failed(Fail::WrongCurrent)
                }
            }
            Stage::First => match validate(self.target, &performed) {
                Ok(()) => {
                    self.first = performed;
                    Stage::Confirm
                }
                Err(f) => Stage::Failed(f),
            },
            Stage::Confirm => {
                if performed == self.first {
                    Stage::Done(std::mem::take(&mut self.first))
                } else {
                    Stage::Failed(Fail::Mismatch)
                }
            }
            ref s => s.clone(),
        };
    }

    /// Try again after a failure, within the same overall timeout. A
    /// verification already passed stays passed.
    pub fn restart(&mut self, _now: Instant) {
        self.first.clear();
        self.current.clear();
        self.last = None;
        self.held = false;
        self.stage = if self.verify.is_some() {
            Stage::Verify
        } else {
            Stage::First
        };
    }
}

fn validate(target: Target, codes: &[u8]) -> Result<(), Fail> {
    let (min, max) = match target {
        Target::Gesture => (MIN_LEN, MAX_LEN),
        Target::Pin => (PIN_MIN, PIN_MAX),
    };
    if codes.len() < min {
        return Err(Fail::TooShort);
    }
    if codes.len() > max {
        return Err(Fail::TooLong);
    }
    if codes.iter().all(|c| *c == codes[0]) {
        return Err(Fail::TooSimple);
    }
    Ok(())
}

/// Feedback for a gesture enrolment on the stock screen, where there is no
/// enrolment screen. Says THAT something happened, never which move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cue {
    Move,
    Again,
    Saved,
    Failed,
}

pub fn cue_for(before: &Stage, after: &Stage) -> Option<Cue> {
    if before == after {
        return None;
    }
    match after {
        Stage::Confirm | Stage::First => Some(Cue::Again),
        Stage::Done(_) => Some(Cue::Saved),
        Stage::Failed(_) => Some(Cue::Failed),
        Stage::Verify => None,
    }
}

/// (lit, milliseconds). Always ends dark.
pub fn led_steps(c: Cue) -> &'static [(bool, u64)] {
    match c {
        Cue::Move => &[(true, 120), (false, 50)],
        Cue::Again => &[(true, 150), (false, 150), (true, 150), (false, 50)],
        Cue::Saved => &[(true, 1500), (false, 50)],
        Cue::Failed => &[
            (true, 100),
            (false, 100),
            (true, 100),
            (false, 100),
            (true, 100),
            (false, 50),
        ],
    }
}

/// (sounding, milliseconds). Empty: silent.
pub fn chirps(c: Cue) -> &'static [(bool, u64)] {
    match c {
        Cue::Move => &[],
        Cue::Again => &[(true, 80), (false, 80), (true, 80), (false, 0)],
        Cue::Saved => &[(true, 600), (false, 0)],
        Cue::Failed => &[
            (true, 80),
            (false, 80),
            (true, 80),
            (false, 80),
            (true, 80),
            (false, 0),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("rh-enrol-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Paths { dir }
    }

    #[test]
    fn a_request_is_consumed_exactly_once() {
        // Review focus 3: a stale request must not re-enter enrolment every boot.
        let p = scratch("once");
        std::fs::write(p.request(), "gesture\n").unwrap();
        assert_eq!(take_request(&p), Some(Request::Gesture));
        assert!(!p.request().exists());
        assert_eq!(take_request(&p), None);
    }

    #[test]
    fn requests_are_parsed_strictly() {
        let p = scratch("parse");
        for (body, want) in [
            ("pin", Some(Request::Pin)),
            ("reload\n", Some(Request::Reload)),
            ("rm -rf /", None),
        ] {
            std::fs::write(p.request(), body).unwrap();
            assert_eq!(take_request(&p), want, "{body}");
            assert!(!p.request().exists(), "even an unknown request is consumed");
        }
    }

    #[test]
    fn a_saved_gesture_loads_and_matches_but_is_not_readable() {
        let p = scratch("reveal");
        save_reveal(&p, &[0, 5, 6, 3, 1]).unwrap();
        let body = std::fs::read_to_string(p.reveal()).unwrap();
        assert!(!body.contains("05631"));
        assert!(load_reveal(&p).unwrap().matches(&[0, 5, 6, 3, 1]));
    }

    #[test]
    fn no_file_means_no_gesture() {
        let p = scratch("none");
        assert!(load_reveal(&p).is_none());
    }

    use std::time::{Duration, Instant};

    fn perform(e: &mut Enrolment, codes: &[u8], t: &mut Instant) {
        for c in codes {
            *t += Duration::from_millis(500);
            e.push(*c, *t);
        }
        *t += PERFORM_END + Duration::from_millis(1);
        e.tick(*t);
    }

    #[test]
    fn performing_twice_the_same_way_is_done() {
        let mut t = Instant::now();
        let mut e = Enrolment::new(Target::Gesture, None, t);
        perform(&mut e, &[0, 5, 6, 3, 1], &mut t);
        assert_eq!(e.stage(), &Stage::Confirm);
        perform(&mut e, &[0, 5, 6, 3, 1], &mut t);
        assert_eq!(e.stage(), &Stage::Done(vec![0, 5, 6, 3, 1]));
    }

    #[test]
    fn holding_a_touch_does_not_end_the_performance() {
        // 2026-10-08: the 3 s "performance ended" timer ran from the last
        // release and kept running while a finger was held, so a long press
        // could end a performance halfway through. Time on the glass is not a pause.
        let ms = Duration::from_millis;
        let mut t = Instant::now();
        let mut e = Enrolment::new(Target::Gesture, None, t);
        for c in [0u8, 5, 6] {
            t += ms(500);
            e.touch_down(t);
            e.touch_up(t);
            e.push(c, t);
        }
        t += ms(1000);
        e.touch_down(t);
        t += PERFORM_END + ms(500);
        e.tick(t);
        assert_eq!(
            e.stage(),
            &Stage::First,
            "a held touch ended the performance"
        );
        e.touch_up(t);
        e.push(3, t);
        t += ms(500);
        e.touch_down(t);
        e.touch_up(t);
        e.push(1, t);
        t += PERFORM_END + ms(1);
        e.tick(t);
        assert_eq!(e.stage(), &Stage::Confirm);
    }

    #[test]
    fn a_different_second_performance_fails() {
        let mut t = Instant::now();
        let mut e = Enrolment::new(Target::Gesture, None, t);
        perform(&mut e, &[0, 5, 6, 3, 1], &mut t);
        perform(&mut e, &[0, 5, 6, 3, 2], &mut t);
        assert_eq!(e.stage(), &Stage::Failed(Fail::Mismatch));
    }

    #[test]
    fn gestures_must_be_five_to_eight_moves_and_not_one_move_repeated() {
        for (codes, fail) in [
            (&[0u8, 5, 6, 3][..], Fail::TooShort),
            (&[0, 1, 2, 3, 4, 5, 6, 7, 8][..], Fail::TooLong),
            (&[6, 6, 6, 6, 6][..], Fail::TooSimple),
        ] {
            let mut t = Instant::now();
            let mut e = Enrolment::new(Target::Gesture, None, t);
            perform(&mut e, codes, &mut t);
            assert_eq!(e.stage(), &Stage::Failed(fail), "{codes:?}");
        }
    }

    #[test]
    fn pins_must_be_six_to_eight_digits() {
        let mut t = Instant::now();
        let mut e = Enrolment::new(Target::Pin, None, t);
        perform(&mut e, &[1, 2, 3, 4, 5], &mut t);
        assert_eq!(e.stage(), &Stage::Failed(Fail::TooShort));
    }

    #[test]
    fn changing_a_secret_requires_the_current_one_first() {
        let mut t = Instant::now();
        let current = Secret::create(&[1, 2, 3, 4]);
        let mut e = Enrolment::new(Target::Gesture, Some(current.clone()), t);
        assert_eq!(e.stage(), &Stage::Verify);
        perform(&mut e, &[4, 3, 2, 1], &mut t);
        assert_eq!(e.stage(), &Stage::Failed(Fail::WrongCurrent));

        let mut e = Enrolment::new(Target::Gesture, Some(current), t);
        perform(&mut e, &[1, 2, 3, 4], &mut t);
        assert_eq!(e.stage(), &Stage::First);
    }

    #[test]
    fn enrolment_times_out() {
        let t = Instant::now();
        let mut e = Enrolment::new(Target::Gesture, None, t);
        e.tick(t + ENROL_TIMEOUT + Duration::from_millis(1));
        assert_eq!(e.stage(), &Stage::Failed(Fail::TimedOut));
    }

    #[test]
    fn progress_counts_moves_and_never_exposes_them() {
        let t = Instant::now();
        let mut e = Enrolment::new(Target::Gesture, None, t);
        e.push(3, t);
        e.push(11, t);
        assert_eq!(e.progress(), 2);
        assert!(!format!("{:?}", e.stage()).contains("11"));
    }

    #[test]
    fn a_restart_after_failure_keeps_any_verification_already_passed() {
        let mut t = Instant::now();
        let current = Secret::create(&[1, 2, 3, 4]);
        let mut e = Enrolment::new(Target::Gesture, Some(current), t);
        perform(&mut e, &[1, 2, 3, 4], &mut t);
        perform(&mut e, &[5, 5, 5, 5, 5], &mut t);
        assert_eq!(e.stage(), &Stage::Failed(Fail::TooSimple));
        e.restart(t);
        assert_eq!(e.stage(), &Stage::First, "no need to verify again");
    }

    #[test]
    fn stage_changes_map_to_cues() {
        assert_eq!(cue_for(&Stage::First, &Stage::Confirm), Some(Cue::Again));
        assert_eq!(cue_for(&Stage::Verify, &Stage::First), Some(Cue::Again));
        assert_eq!(
            cue_for(&Stage::Confirm, &Stage::Done(vec![1])),
            Some(Cue::Saved)
        );
        assert_eq!(
            cue_for(&Stage::First, &Stage::Failed(Fail::TooShort)),
            Some(Cue::Failed)
        );
        assert_eq!(
            cue_for(&Stage::Confirm, &Stage::Failed(Fail::TimedOut)),
            Some(Cue::Failed)
        );
        assert_eq!(
            cue_for(&Stage::First, &Stage::First),
            None,
            "no change, no cue"
        );
    }

    #[test]
    fn every_cue_has_a_distinct_blink_count_so_the_led_alone_tells_them_apart() {
        let lit = |c: Cue| led_steps(c).iter().filter(|(on, _)| *on).count();
        let counts = [
            lit(Cue::Move),
            lit(Cue::Again),
            lit(Cue::Saved),
            lit(Cue::Failed),
        ];
        assert_eq!(counts, [1, 2, 1, 3]);
        let long = |c: Cue| {
            led_steps(c)
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, ms)| *ms)
                .max()
                .unwrap()
        };
        assert!(
            long(Cue::Saved) >= 1000,
            "saved is a long glow, unlike a move's short blink"
        );
        assert!(long(Cue::Move) <= 200);
    }

    #[test]
    fn every_cue_ends_dark_and_moves_are_silent() {
        for c in [Cue::Move, Cue::Again, Cue::Saved, Cue::Failed] {
            assert_eq!(
                led_steps(c).last().map(|s| s.0),
                Some(false),
                "{c:?} ends dark"
            );
        }
        assert!(chirps(Cue::Move).is_empty(), "a move makes no sound");
        assert_eq!(chirps(Cue::Failed).iter().filter(|(on, _)| *on).count(), 3);
    }
}
