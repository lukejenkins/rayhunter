//! Wire format: big-endian, fixed header, typed body, trailing Ed25519 signature.
//! Everything decoded here is hostile input: no panics, no unchecked indexing,
//! no allocation beyond the input's own length.

use crate::consts::*;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    TooShort,
    TooLong,
    Version,
    Type,
    Code,
    Flags,
    Length,
    Text,
    NodeZero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Full,
    Light,
    Messenger,
    Organiser,
    Hub,
}

impl Role {
    pub fn code(self) -> u8 {
        match self {
            Role::Full => 1,
            Role::Light => 2,
            Role::Messenger => 3,
            Role::Organiser => 4,
            Role::Hub => 5,
        }
    }
    pub fn from_code(c: u8) -> Option<Role> {
        Some(match c {
            1 => Role::Full,
            2 => Role::Light,
            3 => Role::Messenger,
            4 => Role::Organiser,
            5 => Role::Hub,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    pub fn code(self) -> u8 {
        match self {
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
        }
    }
    pub fn from_code(c: u8) -> Option<Level> {
        Some(match c {
            1 => Level::Low,
            2 => Level::Medium,
            3 => Level::High,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    ImsiRequested,
    RedirectDowngrade2g,
    Sib67Downgrade,
    NullCipher,
    NasNullCipher,
    IncompleteSib,
    NoNasMessages,
    Diagnostic,
    Test,
    ServiceLost,
    Downgraded,
    TowersGone,
    TowerFlood,
}

impl VerdictKind {
    pub fn code(self) -> u8 {
        match self {
            VerdictKind::ImsiRequested => 0x01,
            VerdictKind::RedirectDowngrade2g => 0x02,
            VerdictKind::Sib67Downgrade => 0x03,
            VerdictKind::NullCipher => 0x04,
            VerdictKind::NasNullCipher => 0x05,
            VerdictKind::IncompleteSib => 0x06,
            VerdictKind::NoNasMessages => 0x07,
            VerdictKind::Diagnostic => 0x08,
            VerdictKind::Test => 0x0F,
            VerdictKind::ServiceLost => 0x20,
            VerdictKind::Downgraded => 0x21,
            VerdictKind::TowersGone => 0x22,
            VerdictKind::TowerFlood => 0x30,
        }
    }
    pub fn from_code(c: u8) -> Option<VerdictKind> {
        Some(match c {
            0x01 => VerdictKind::ImsiRequested,
            0x02 => VerdictKind::RedirectDowngrade2g,
            0x03 => VerdictKind::Sib67Downgrade,
            0x04 => VerdictKind::NullCipher,
            0x05 => VerdictKind::NasNullCipher,
            0x06 => VerdictKind::IncompleteSib,
            0x07 => VerdictKind::NoNasMessages,
            0x08 => VerdictKind::Diagnostic,
            0x0F => VerdictKind::Test,
            0x20 => VerdictKind::ServiceLost,
            0x21 => VerdictKind::Downgraded,
            0x22 => VerdictKind::TowersGone,
            0x30 => VerdictKind::TowerFlood,
            _ => return None,
        })
    }
    /// The three network-condition kinds (0x2x).
    pub fn is_network(self) -> bool {
        matches!(
            self,
            VerdictKind::ServiceLost | VerdictKind::Downgraded | VerdictKind::TowersGone
        )
    }
    /// Map a Rayhunter `AnalyzerMetadata.key` to a kind. Network kinds and
    /// TowerFlood have no Rayhunter key.
    pub fn from_rayhunter_key(key: &str) -> Option<VerdictKind> {
        Some(match key {
            "imsi_requested" => VerdictKind::ImsiRequested,
            "connection_redirect_2g_downgrade" => VerdictKind::RedirectDowngrade2g,
            "lte_sib6_and_7_downgrade" => VerdictKind::Sib67Downgrade,
            "null_cipher" => VerdictKind::NullCipher,
            "nas_null_cipher" => VerdictKind::NasNullCipher,
            "incomplete_sib" => VerdictKind::IncompleteSib,
            "no_nas_messages" => VerdictKind::NoNasMessages,
            "diagnostic_analyzer" => VerdictKind::Diagnostic,
            "test_analyzer" => VerdictKind::Test,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthCode {
    UnitLost = 1,
    BatteryLow = 2,
    NodeRevoked = 3,
}

impl HealthCode {
    pub fn from_code(c: u8) -> Option<HealthCode> {
        Some(match c {
            1 => HealthCode::UnitLost,
            2 => HealthCode::BatteryLow,
            3 => HealthCode::NodeRevoked,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub pubkey: [u8; 32],
    pub node: u16,
    pub role: Role,
    pub expiry: u32,
    pub event_sig: [u8; 64],
}

impl Card {
    pub fn encode(&self) -> [u8; CARD_LEN] {
        let mut o = [0u8; CARD_LEN];
        o[..32].copy_from_slice(&self.pubkey);
        o[32..34].copy_from_slice(&self.node.to_be_bytes());
        o[34] = self.role.code();
        o[35..39].copy_from_slice(&self.expiry.to_be_bytes());
        o[39..].copy_from_slice(&self.event_sig);
        o
    }

    pub fn decode(bytes: &[u8]) -> Result<Card, WireError> {
        let mut r = R::new(bytes);
        let pubkey = r.arr::<32>()?;
        let node = r.u16()?;
        let role = Role::from_code(r.u8()?).ok_or(WireError::Code)?;
        let expiry = r.u32()?;
        let event_sig = r.arr::<64>()?;
        if r.remaining() != 0 {
            return Err(WireError::Length);
        }
        if node == 0 {
            return Err(WireError::NodeZero);
        }
        Ok(Card {
            pubkey,
            node,
            role,
            expiry,
            event_sig,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    Phrase(u8),
    Point(u8),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Verdict {
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
    },
    Status {
        phrase: u8,
    },
    CheckIn {
        hub_snr: i8,
    },
    Directive(Directive),
    Roster(Card),
    Revocation {
        target: u16,
        event_sig: Option<[u8; 64]>,
    },
    HubHealth {
        code: HealthCode,
        subject: u16,
        value: u8,
    },
    RelayOrder {
        target: u16,
        minutes: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub node: u16,
    pub counter: u32,
    pub time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: Header,
    pub body: Body,
    pub sig: [u8; 64],
}

const T_VERDICT: u8 = 0x01;
const T_STATUS: u8 = 0x02;
const T_CHECKIN: u8 = 0x03;
const T_DIRECTIVE: u8 = 0x04;
const T_ROSTER: u8 = 0x05;
const T_REVOCATION: u8 = 0x06;
const T_HUBHEALTH: u8 = 0x07;
const T_RELAYORDER: u8 = 0x08;

/// Bounds-checked cursor. Every read goes through here.
struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        R { b, i: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.i.checked_add(n).ok_or(WireError::Length)?;
        let s = self.b.get(self.i..end).ok_or(WireError::Length)?;
        self.i = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.arr::<2>()?))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.arr::<4>()?))
    }
}

/// Characters refused in any text shown to a person (directive text, kit
/// phrases and points): control characters, and the bidi and invisible format
/// characters that can make text read as something else (M4).
pub fn forbidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn check_text(t: &str) -> Result<(), WireError> {
    if t.is_empty() || t.len() > TEXT_MAX {
        return Err(WireError::Length);
    }
    if t.chars().any(forbidden_char) {
        return Err(WireError::Text);
    }
    Ok(())
}

/// Bytes from version through end of body. Signing happens elsewhere.
pub fn encode_unsigned(h: &Header, b: &Body) -> Result<Vec<u8>, WireError> {
    if h.node == 0 {
        return Err(WireError::NodeZero);
    }
    let mut body: Vec<u8> = Vec::new();
    let ty = match b {
        Body::Verdict { kind, level, tag } => {
            body.push(kind.code());
            body.push(level.code());
            match tag {
                Some(t) => {
                    body.push(1);
                    body.extend_from_slice(t);
                }
                None => body.push(0),
            }
            T_VERDICT
        }
        Body::Status { phrase } => {
            body.push(*phrase);
            T_STATUS
        }
        Body::CheckIn { hub_snr } => {
            body.push(*hub_snr as u8);
            T_CHECKIN
        }
        Body::Directive(d) => {
            match d {
                Directive::Phrase(p) => body.extend_from_slice(&[1, *p]),
                Directive::Point(p) => body.extend_from_slice(&[2, *p]),
                Directive::Text(t) => {
                    check_text(t)?;
                    body.push(3);
                    body.push(t.len() as u8);
                    body.extend_from_slice(t.as_bytes());
                }
            }
            T_DIRECTIVE
        }
        Body::Roster(c) => {
            if c.node == 0 {
                return Err(WireError::NodeZero);
            }
            body.extend_from_slice(&c.encode());
            T_ROSTER
        }
        Body::Revocation { target, event_sig } => {
            body.extend_from_slice(&target.to_be_bytes());
            match event_sig {
                Some(s) => {
                    body.push(1);
                    body.extend_from_slice(s);
                }
                None => body.push(0),
            }
            T_REVOCATION
        }
        Body::HubHealth {
            code,
            subject,
            value,
        } => {
            body.push(*code as u8);
            body.extend_from_slice(&subject.to_be_bytes());
            body.push(*value);
            T_HUBHEALTH
        }
        Body::RelayOrder { target, minutes } => {
            if !(1..=60).contains(minutes) {
                return Err(WireError::Code);
            }
            body.extend_from_slice(&target.to_be_bytes());
            body.push(*minutes);
            T_RELAYORDER
        }
    };
    if body.len() > MAX_BODY {
        return Err(WireError::TooLong);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(PROTOCOL_VERSION);
    out.push(ty);
    out.extend_from_slice(&h.node.to_be_bytes());
    out.extend_from_slice(&h.counter.to_be_bytes());
    out.extend_from_slice(&h.time.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Frame, WireError> {
    if bytes.len() > MAX_FRAME {
        return Err(WireError::TooLong);
    }
    if bytes.len() < HEADER_LEN + SIG_LEN {
        return Err(WireError::TooShort);
    }
    let mut r = R::new(bytes);
    if r.u8()? != PROTOCOL_VERSION {
        return Err(WireError::Version);
    }
    let ty = r.u8()?;
    if !(T_VERDICT..=T_RELAYORDER).contains(&ty) {
        return Err(WireError::Type);
    }
    let node = r.u16()?;
    let counter = r.u32()?;
    let time = r.u32()?;
    if node == 0 {
        return Err(WireError::NodeZero);
    }
    let body = match ty {
        T_VERDICT => {
            let kind = VerdictKind::from_code(r.u8()?).ok_or(WireError::Code)?;
            let level = Level::from_code(r.u8()?).ok_or(WireError::Code)?;
            let flags = r.u8()?;
            if flags & !1 != 0 {
                return Err(WireError::Flags);
            }
            let tag = if flags & 1 != 0 {
                Some(r.arr::<8>()?)
            } else {
                None
            };
            Body::Verdict { kind, level, tag }
        }
        T_STATUS => Body::Status { phrase: r.u8()? },
        T_CHECKIN => Body::CheckIn {
            hub_snr: r.u8()? as i8,
        },
        T_DIRECTIVE => match r.u8()? {
            1 => Body::Directive(Directive::Phrase(r.u8()?)),
            2 => Body::Directive(Directive::Point(r.u8()?)),
            3 => {
                let len = r.u8()? as usize;
                if len == 0 || len > TEXT_MAX {
                    return Err(WireError::Length);
                }
                let raw = r.take(len)?;
                let s = core::str::from_utf8(raw).map_err(|_| WireError::Text)?;
                if s.chars().any(forbidden_char) {
                    return Err(WireError::Text);
                }
                Body::Directive(Directive::Text(String::from(s)))
            }
            _ => return Err(WireError::Code),
        },
        T_ROSTER => Body::Roster(Card::decode(r.take(CARD_LEN)?)?),
        T_REVOCATION => {
            let target = r.u16()?;
            let flags = r.u8()?;
            if flags & !1 != 0 {
                return Err(WireError::Flags);
            }
            let event_sig = if flags & 1 != 0 {
                Some(r.arr::<64>()?)
            } else {
                None
            };
            Body::Revocation { target, event_sig }
        }
        T_HUBHEALTH => {
            let code = HealthCode::from_code(r.u8()?).ok_or(WireError::Code)?;
            let subject = r.u16()?;
            let value = r.u8()?;
            Body::HubHealth {
                code,
                subject,
                value,
            }
        }
        _ => {
            let target = r.u16()?;
            let minutes = r.u8()?;
            if !(1..=60).contains(&minutes) {
                return Err(WireError::Code);
            }
            Body::RelayOrder { target, minutes }
        }
    };
    if r.remaining() != SIG_LEN {
        return Err(WireError::Length);
    }
    let sig = r.arr::<64>()?;
    Ok(Frame {
        header: Header {
            node,
            counter,
            time,
        },
        body,
        sig,
    })
}

/// Everything but the trailing signature. Only call after `decode` succeeded.
pub fn signed_region(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().saturating_sub(SIG_LEN)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hdr() -> Header {
        Header {
            node: 7,
            counter: 0x0102_0304,
            time: 1_700_000_000,
        }
    }

    fn card() -> Card {
        Card {
            pubkey: [3; 32],
            node: 9,
            role: Role::Full,
            expiry: 99,
            event_sig: [5; 64],
        }
    }

    fn text(n: usize) -> Body {
        Body::Directive(Directive::Text("a".repeat(n)))
    }

    fn all_bodies() -> Vec<Body> {
        vec![
            Body::Verdict {
                kind: VerdictKind::ImsiRequested,
                level: Level::High,
                tag: None,
            },
            Body::Verdict {
                kind: VerdictKind::TowerFlood,
                level: Level::Low,
                tag: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            },
            Body::Status { phrase: 4 },
            Body::CheckIn { hub_snr: -128 },
            Body::CheckIn { hub_snr: 20 },
            Body::Directive(Directive::Phrase(3)),
            Body::Directive(Directive::Point(2)),
            text(1),
            text(96),
            Body::Roster(card()),
            Body::Revocation {
                target: 12,
                event_sig: None,
            },
            Body::Revocation {
                target: 12,
                event_sig: Some([8; 64]),
            },
            Body::HubHealth {
                code: HealthCode::BatteryLow,
                subject: 5,
                value: 17,
            },
            Body::RelayOrder {
                target: 4,
                minutes: 15,
            },
        ]
    }

    fn framed(b: &Body) -> Vec<u8> {
        let mut v = encode_unsigned(&hdr(), b).unwrap();
        v.extend_from_slice(&[7u8; 64]);
        v
    }

    #[test]
    fn round_trips_every_body() {
        for b in all_bodies() {
            let bytes = framed(&b);
            let f = decode(&bytes).unwrap();
            assert_eq!(f.header, hdr());
            assert_eq!(f.body, b);
            assert_eq!(f.sig, [7u8; 64]);
            assert_eq!(signed_region(&bytes).len(), bytes.len() - 64);
        }
    }

    #[test]
    fn max_frame_holds() {
        assert!(framed(&text(96)).len() <= MAX_FRAME);
        assert!(framed(&Body::Roster(card())).len() <= MAX_FRAME);
        for b in all_bodies() {
            assert!(framed(&b).len() <= MAX_FRAME);
        }
        assert_eq!(card().encode().len(), 103);
        assert_eq!(Card::decode(&card().encode()).unwrap(), card());
    }

    fn mutate(b: &Body, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut v = framed(b);
        f(&mut v);
        v
    }

    #[test]
    fn rejects_bad_input() {
        let verdict = Body::Verdict {
            kind: VerdictKind::NullCipher,
            level: Level::Medium,
            tag: None,
        };
        let tagged = Body::Verdict {
            kind: VerdictKind::TowerFlood,
            level: Level::Medium,
            tag: Some([0; 8]),
        };
        assert_eq!(decode(&[]), Err(WireError::TooShort));
        assert_eq!(
            decode(&mutate(&verdict, |v| v[0] = 2)),
            Err(WireError::Version)
        );
        assert_eq!(
            decode(&mutate(&verdict, |v| v[1] = 0x09)),
            Err(WireError::Type)
        );
        assert_eq!(
            decode(&mutate(&verdict, |v| v[12] = 0x09)),
            Err(WireError::Code)
        );
        assert_eq!(
            decode(&mutate(&verdict, |v| v[13] = 0)),
            Err(WireError::Code)
        );
        assert_eq!(
            decode(&mutate(&verdict, |v| v[14] = 0x02)),
            Err(WireError::Flags)
        );
        // Claims a tag but 4 bytes short.
        let short = mutate(&tagged, |v| {
            v.drain(12 + 3..12 + 3 + 4);
        });
        assert_eq!(decode(&short), Err(WireError::Length));
        assert_eq!(
            decode(&mutate(&text(5), |v| v[13] = 97)),
            Err(WireError::Length)
        );
        assert_eq!(
            decode(&mutate(&text(2), |v| {
                v[14] = 0xff;
                v[15] = 0xfe;
            })),
            Err(WireError::Text)
        );
        assert_eq!(
            decode(&mutate(&text(2), |v| v[14] = 0x1b)),
            Err(WireError::Text)
        );
        assert_eq!(
            decode(&mutate(&text(5), |v| v[13] = 0)),
            Err(WireError::Length)
        );
        assert_eq!(
            decode(&mutate(&verdict, |v| {
                v[2] = 0;
                v[3] = 0;
            })),
            Err(WireError::NodeZero)
        );
        assert_eq!(
            decode(&mutate(&text(96), |v| v.extend_from_slice(&[0; 76]))),
            Err(WireError::TooLong)
        );
        assert_eq!(decode(&[0u8; 185]), Err(WireError::TooLong));
        // Trailing extra byte after a valid body.
        assert_eq!(
            decode(&mutate(&verdict, |v| v.insert(15, 0))),
            Err(WireError::Length)
        );
        let relay = |m: u8| Body::RelayOrder {
            target: 4,
            minutes: m,
        };
        assert_eq!(
            decode(&mutate(&relay(15), |v| v[14] = 0)),
            Err(WireError::Code)
        );
        assert_eq!(
            decode(&mutate(&relay(15), |v| v[14] = 61)),
            Err(WireError::Code)
        );
        // Encode refuses what decode would refuse.
        assert_eq!(encode_unsigned(&hdr(), &relay(0)), Err(WireError::Code));
        assert_eq!(encode_unsigned(&hdr(), &text(97)), Err(WireError::Length));
    }

    /// Every character M4 forbids beyond the control characters.
    const FORMAT_CHARS: &[char] = &[
        '\u{061C}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}',
        '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2062}',
        '\u{2063}', '\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{FEFF}',
    ];

    #[test]
    fn directive_text_rejects_bidi_and_format_chars() {
        let d = |t: &str| Body::Directive(Directive::Text(t.into()));
        // U+202E (right-to-left override) can make "bridge" read otherwise.
        assert_eq!(
            encode_unsigned(&hdr(), &d("meet at \u{202E}egdirb")),
            Err(WireError::Text)
        );
        for c in FORMAT_CHARS {
            let t: String = ['a', *c, 'b'].iter().collect();
            assert_eq!(
                encode_unsigned(&hdr(), &d(&t)),
                Err(WireError::Text),
                "{c:?}"
            );
        }
        // Decode refuses it too: "aaaa" patched to "a" + U+202E (E2 80 AE).
        let bytes = mutate(&text(4), |v| v[15..18].copy_from_slice(&[0xE2, 0x80, 0xAE]));
        assert_eq!(decode(&bytes), Err(WireError::Text));
        // Neighbours and ordinary non-ASCII text are fine.
        for t in ["caf\u{e9}", "a\u{2010}b", "a\u{2065}b", "a\u{2070}b"] {
            assert!(encode_unsigned(&hdr(), &d(t)).is_ok(), "{t:?}");
        }
    }

    #[test]
    fn hostile_bytes_never_panic() {
        let mut s: u64 = 0x5eed;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let valid: Vec<Vec<u8>> = all_bodies().iter().map(framed).collect();
        for i in 0..20_000usize {
            let n = (next() % 201) as usize;
            let rnd: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            let _ = decode(&rnd);
            let v = &valid[i % valid.len()];
            let cut = (next() as usize) % (v.len() + 1);
            let _ = decode(&v[..cut]);
            let mut flipped = v.clone();
            let bit = (next() as usize) % (flipped.len() * 8);
            flipped[bit / 8] ^= 1 << (bit % 8);
            let _ = decode(&flipped);
        }
    }

    #[test]
    fn rayhunter_keys_map() {
        let t = [
            ("imsi_requested", VerdictKind::ImsiRequested),
            (
                "connection_redirect_2g_downgrade",
                VerdictKind::RedirectDowngrade2g,
            ),
            ("lte_sib6_and_7_downgrade", VerdictKind::Sib67Downgrade),
            ("null_cipher", VerdictKind::NullCipher),
            ("nas_null_cipher", VerdictKind::NasNullCipher),
            ("incomplete_sib", VerdictKind::IncompleteSib),
            ("no_nas_messages", VerdictKind::NoNasMessages),
            ("diagnostic_analyzer", VerdictKind::Diagnostic),
            ("test_analyzer", VerdictKind::Test),
        ];
        for (k, v) in t {
            assert_eq!(VerdictKind::from_rayhunter_key(k), Some(v));
            assert_eq!(VerdictKind::from_code(v.code()), Some(v));
        }
        assert_eq!(VerdictKind::from_rayhunter_key("unknown"), None);
        assert!(VerdictKind::TowersGone.is_network());
        assert!(!VerdictKind::TowerFlood.is_network());
    }
}
