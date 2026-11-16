//! Privacy check for owner follow-ups sent over the mesh.

use crate::mesh::TEXT_MAX as MAX_TEXT;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    TooLong { bytes: usize },
    Empty,
    Digits,
    CellWord,
    Coordinates,
}

pub const REMINDER: &str = "No cell IDs, no places.";

// Known limit: DIGITS is "a run of 5+ digits", so digits split by separators
// ("47 291 396", "47-291") are deliberately NOT blocked. \d is Unicode-aware, so
// full-width digits count as digits.
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{5,}").unwrap());
// Word, up to 3 separator chars, optional "is", then a digit ("PCI-12", "PCI is 12").
// No trailing \b so "PCI12" matches; "tactic 3" does not (no digit follows "tac").
static CELL_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(pci|eci|tac|earfcn)\W{0,3}(is\W+)?\d").unwrap());
static COORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // two 2+ decimal numbers, up to 8 non-digits between (labels, N/W letters)
        r"(?i)-?\d{1,3}\.\d{2,}\D{0,8}-?\d{1,3}\.\d{2,}",
        // degrees sign
        r"|\d{1,3}\s*°",
        // N12.34 W123.45
        r"|\b[NS]\s?\d{1,2}\.\d+\s*[EW]\s?\d{1,3}\.\d+",
        // 12.34N (uppercase hemisphere only, so "2.30 s" is fine)
        r"|(?-i:\d{1,3}\.\d{2,}\s?[NSEW]\b)",
        // one decimal each, comma-separated: 38.1, -122.8
        r"|\d{2}\.\d\s*,\s*-?\d{2,3}\.\d",
    ))
    .unwrap()
});

/// Trims, then checks in order: Empty, TooLong (UTF-8 bytes), CellWord, Digits, Coordinates.
pub fn check(text: &str) -> Result<(), Blocked> {
    let t = text.trim();
    if t.is_empty() {
        return Err(Blocked::Empty);
    }
    if t.len() > MAX_TEXT {
        return Err(Blocked::TooLong { bytes: t.len() });
    }
    // CellWord before Digits: "EARFCN#55555" has 5 digits but must report CellWord.
    if CELL_WORD.is_match(t) {
        return Err(Blocked::CellWord);
    }
    if DIGITS.is_match(t) {
        return Err(Blocked::Digits);
    }
    if COORDS.is_match(t) {
        return Err(Blocked::Coordinates);
    }
    Ok(())
}

pub fn reason(b: &Blocked) -> String {
    match b {
        Blocked::TooLong { bytes } => {
            format!("Blocked: too long ({bytes} bytes; the limit is {MAX_TEXT}).")
        }
        Blocked::Empty => "Blocked: the message is empty.".into(),
        Blocked::Digits => "Blocked: 5 or more digits in a row (looks like a cell ID).".into(),
        Blocked::CellWord => {
            "Blocked: PCI, ECI, TAC or EARFCN followed by a number (looks like a cell ID).".into()
        }
        Blocked::Coordinates => "Blocked: looks like coordinates (a place).".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_five_digit_runs() {
        assert_eq!(check("cell 31026"), Err(Blocked::Digits));
        assert_eq!(check("call 1234 now"), Ok(()));
        assert_eq!(check("12:30"), Ok(()));
    }

    #[test]
    fn blocks_cell_words_with_numbers() {
        for s in ["PCI 12", "pci=12", "ECI: 4", "tac 7", "EARFCN#55555"] {
            assert_eq!(check(s), Err(Blocked::CellWord), "{s}");
        }
        assert_eq!(check("Pacific"), Ok(()));
        assert_eq!(check("attack"), Ok(()));
    }

    #[test]
    fn blocks_coordinates() {
        for s in [
            "12.34,-123.45",
            "12.34 -123.45",
            "38°04'N",
            "N12.34 W123.45",
        ] {
            assert_eq!(check(s), Err(Blocked::Coordinates), "{s}");
        }
        assert_eq!(check("version 1.5"), Ok(()));
        assert_eq!(check("at 2.30pm"), Ok(()));
    }

    #[test]
    fn blocks_cell_words_other_separators() {
        for s in [
            "PCI-12",
            "PCI - 12",
            "PCI is 12",
            "ECI (4)",
            "TAC/7",
            "PCI12",
        ] {
            assert_eq!(check(s), Err(Blocked::CellWord), "{s}");
        }
        assert_eq!(check("tactic 3"), Ok(()));
    }

    #[test]
    fn blocks_labelled_and_letter_after_coordinates() {
        for s in [
            "lat 12.34 lon -123.45",
            "12.34N 123.45W",
            "12.34N, 123.45W",
            "38.1, -122.8",
            "38.5,-122.5",
        ] {
            assert_eq!(check(s), Err(Blocked::Coordinates), "{s}");
        }
    }

    #[test]
    fn ordinary_numbers_stay_ok() {
        for s in [
            "version 1.5",
            "at 2.30pm",
            "12:30",
            "call 1234 now",
            "back by 2.5 hours, maybe 3.5",
        ] {
            assert_eq!(check(s), Ok(()), "{s}");
        }
    }

    #[test]
    fn full_width_digits_are_digits() {
        assert_eq!(check("４７２９１"), Err(Blocked::Digits));
    }

    #[test]
    fn too_long_beats_digits() {
        let t = format!("12345{}", "a".repeat(205));
        assert_eq!(t.len(), 210);
        assert_eq!(check(&t), Err(Blocked::TooLong { bytes: 210 }));
    }

    #[test]
    fn counts_utf8_bytes() {
        assert_eq!(check(&"🛑".repeat(49)), Ok(()));
        assert_eq!(
            check(&"🛑".repeat(50)),
            Err(Blocked::TooLong { bytes: 200 })
        );
    }

    /// One byte of the radio's 200 is the alert bell.
    #[test]
    fn limit_leaves_room_for_the_bell() {
        assert_eq!(check(&"a".repeat(199)), Ok(()));
        assert_eq!(check(&"a".repeat(200)), Err(Blocked::TooLong { bytes: 200 }));
        assert!(reason(&Blocked::TooLong { bytes: 200 }).contains("limit is 199"));
    }

    #[test]
    fn presets_pass() {
        for s in [
            "Update: false alarm. Carry on as normal.",
            "Update: looking into it. Keep avoiding sensitive calls. Next update by 23:59.",
            "Update: confirmed. Turn on airplane mode now (Wi-Fi is OK). Wait for the all clear.",
            "All clear: no sign of it since 23:59. Phones back to normal.",
        ] {
            assert_eq!(check(s), Ok(()), "{s}");
        }
    }

    #[test]
    fn empty_or_space_is_blocked() {
        assert_eq!(check(""), Err(Blocked::Empty));
        assert_eq!(check("   \n"), Err(Blocked::Empty));
    }

    #[test]
    fn reasons_are_sentences() {
        assert!(reason(&Blocked::Digits).starts_with("Blocked:"));
    }
}
