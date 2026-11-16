//! The radio layer's contract. Adapters (sim, Meshtastic, MeshCore) implement
//! `Transport`; the core never sees a radio.

use crate::consts::MAX_FRAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// The frame is longer than `MAX_FRAME`.
    TooLarge,
    Busy,
    Unsupported,
}

pub trait Transport {
    /// Send one frame (at most `MAX_FRAME` bytes; longer is `TooLarge`).
    fn send(&mut self, frame: &[u8]) -> Result<(), TxError>;
    /// Ask the radio layer to rebroadcast (or stop). Called only by `RelayState`.
    fn set_relay(&mut self, on: bool) -> Result<(), TxError>;
}

/// The length rule every adapter must apply in `send`.
pub fn check_len(frame: &[u8]) -> Result<(), TxError> {
    if frame.len() > MAX_FRAME {
        Err(TxError::TooLarge)
    } else {
        Ok(())
    }
}
