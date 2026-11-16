use rayhunter::analysis::analyzer::EventType;
use serde::{Deserialize, Serialize};

mod generic_framebuffer;

pub mod headless;
pub mod m2100;
pub mod m2100_capture_profiles;
pub mod m2100_cli;
pub mod m2100_profile;
pub mod m2100_profile_io;
pub mod m2100_enrol;
pub mod m2100_font;
pub mod m2100_framebuffer;
pub mod m2100_gesture;
pub mod m2100_hash;
pub mod m2100_live;
pub mod m2100_panic;
pub mod m2100_secret;
pub mod m2100_signal;
pub mod m2100_siglog;
pub mod m2100_token;
pub mod m2100_ui;
pub mod orbic;
pub mod tmobile;
pub mod tplink;
pub mod tplink_framebuffer;
pub mod tplink_onebit;
pub mod uz801;
pub mod wingtech;

/// A list of available display states
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub enum DisplayState {
    /// We're recording but no warning has been found yet.
    Recording,
    /// We're not recording.
    Paused,
    /// A non-informational event has been detected.
    ///
    /// Note that EventType::Informational is never sent through this. If it is, it's the same as
    /// Recording
    WarningDetected { event_type: EventType },
}
