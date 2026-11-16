//! The event kit: everything a device needs, delivered in person (NFC).

use crate::consts::*;
use crate::crypto::{EventAuthority, verify_card, verify_raw};
use crate::wire::{Card, forbidden_char};
use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::SigningKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitError {
    TooLarge,
    Malformed,
    Tables,
    Signature,
    CardMismatch,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tables {
    pub phrases: Vec<String>,
    pub points: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Kit {
    pub event_id: [u8; 8],
    pub start: u32,
    pub expiry: u32,
    pub device_seed: [u8; 32],
    pub card: Card,
    pub event_pub: [u8; 32],
    pub channel: Vec<u8>,
    pub tables: Tables,
    pub tag_secret: [u8; 32],
    pub checkin_minutes: u8,
}

const CHANNEL_MAX: usize = 64;
/// magic 4 + event_id 8 + start 4 + expiry 4 + seed 32 + card 103, then event_pub.
const EVENT_PUB_AT: usize = 4 + 8 + 4 + 4 + 32 + CARD_LEN;

fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(forbidden_char)
}

fn tables_ok(t: &Tables) -> bool {
    if t.phrases.len() > PHRASES_MAX || t.points.len() > POINTS_MAX {
        return false;
    }
    if !t.phrases.iter().all(|p| text_ok(p, PHRASE_LEN_MAX))
        || !t.points.iter().all(|p| text_ok(p, POINT_LEN_MAX))
    {
        return false;
    }
    // R1: UTF-8 text bytes only, not the length prefixes.
    let total: usize = t
        .phrases
        .iter()
        .chain(t.points.iter())
        .map(|s| s.len())
        .sum();
    total <= TABLES_BYTES_MAX
}

/// Bounds-checked cursor; every read returns Malformed on shortfall.
struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KitError> {
        if self.0.len() < n {
            return Err(KitError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], KitError> {
        let mut o = [0u8; N];
        o.copy_from_slice(self.take(N)?);
        Ok(o)
    }
    fn u8(&mut self) -> Result<u8, KitError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, KitError> {
        Ok(u32::from_be_bytes(self.arr::<4>()?))
    }
    fn strings(&mut self, max: usize, count_max: usize) -> Result<Vec<String>, KitError> {
        let n = self.u8()? as usize;
        if n > count_max {
            return Err(KitError::Tables);
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let len = self.u8()? as usize;
            let s = core::str::from_utf8(self.take(len)?).map_err(|_| KitError::Tables)?;
            if !text_ok(s, max) {
                return Err(KitError::Tables);
            }
            v.push(String::from(s));
        }
        Ok(v)
    }
}

// Manual Debug: the seed and tag secret must never reach a log.
impl core::fmt::Debug for Kit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kit")
            .field("event_id", &self.event_id)
            .field("start", &self.start)
            .field("expiry", &self.expiry)
            .field("device_seed", &format_args!("<redacted>"))
            .field("card", &self.card)
            .field("event_pub", &self.event_pub)
            .field("channel", &self.channel)
            .field("tables", &self.tables)
            .field("tag_secret", &format_args!("<redacted>"))
            .field("checkin_minutes", &self.checkin_minutes)
            .finish()
    }
}

pub fn open_kit(bytes: &[u8], now: u32) -> Result<Kit, KitError> {
    if bytes.len() > KIT_MAX {
        return Err(KitError::TooLarge);
    }
    if bytes.len() < EVENT_PUB_AT + 32 + SIG_LEN {
        return Err(KitError::Malformed);
    }
    // The signature check comes first: it needs only fixed offsets, and any
    // corruption anywhere is reported as Signature.
    let mut event_pub = [0u8; 32];
    event_pub.copy_from_slice(&bytes[EVENT_PUB_AT..EVENT_PUB_AT + 32]);
    let (signed, sig_bytes) = bytes.split_at(bytes.len() - SIG_LEN);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes);
    if !verify_raw(&event_pub, signed, &sig) {
        return Err(KitError::Signature);
    }
    let mut c = Cur(signed);
    if c.take(4)? != DOM_KIT {
        return Err(KitError::Malformed);
    }
    let event_id = c.arr::<8>()?;
    let start = c.u32()?;
    let expiry = c.u32()?;
    let device_seed = c.arr::<32>()?;
    let card = Card::decode(c.take(CARD_LEN)?).map_err(|_| KitError::Malformed)?;
    c.take(32)?; // event_pub, already read
    let clen = c.u8()? as usize;
    if clen > CHANNEL_MAX {
        return Err(KitError::Malformed);
    }
    let channel = c.take(clen)?.to_vec();
    let phrases = c.strings(PHRASE_LEN_MAX, PHRASES_MAX)?;
    let points = c.strings(POINT_LEN_MAX, POINTS_MAX)?;
    let tag_secret = c.arr::<32>()?;
    let checkin_minutes = c.u8()?;
    if !c.0.is_empty() || !(1..=CHECKIN_MINUTES_MAX).contains(&checkin_minutes) {
        return Err(KitError::Malformed);
    }
    let tables = Tables { phrases, points };
    if !tables_ok(&tables) {
        return Err(KitError::Tables);
    }
    if !verify_card(&event_pub, &event_id, &card)
        || card.pubkey
            != SigningKey::from_bytes(&device_seed)
                .verifying_key()
                .to_bytes()
    {
        return Err(KitError::CardMismatch);
    }
    if now >= expiry || now >= card.expiry {
        return Err(KitError::Expired);
    }
    Ok(Kit {
        event_id,
        start,
        expiry,
        device_seed,
        card,
        event_pub,
        channel,
        tables,
        tag_secret,
        checkin_minutes,
    })
}

impl EventAuthority {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_kit(
        &self,
        device_seed: [u8; 32],
        card: Card,
        tables: Tables,
        tag_secret: [u8; 32],
        checkin_minutes: u8,
        channel: Vec<u8>,
    ) -> Result<Vec<u8>, KitError> {
        if !tables_ok(&tables) {
            return Err(KitError::Tables);
        }
        if !(1..=CHECKIN_MINUTES_MAX).contains(&checkin_minutes) || channel.len() > CHANNEL_MAX {
            return Err(KitError::Malformed);
        }
        let mut k: Vec<u8> = Vec::with_capacity(KIT_MAX);
        k.extend_from_slice(DOM_KIT);
        k.extend_from_slice(&self.event_id);
        k.extend_from_slice(&self.start.to_be_bytes());
        k.extend_from_slice(&self.expiry.to_be_bytes());
        k.extend_from_slice(&device_seed);
        k.extend_from_slice(&card.encode());
        k.extend_from_slice(&self.public());
        k.push(channel.len() as u8);
        k.extend_from_slice(&channel);
        for list in [&tables.phrases, &tables.points] {
            k.push(list.len() as u8);
            for s in list {
                k.push(s.len() as u8);
                k.extend_from_slice(s.as_bytes());
            }
        }
        k.extend_from_slice(&tag_secret);
        k.push(checkin_minutes);
        let sig = self.sign_raw(&k);
        k.extend_from_slice(&sig);
        if k.len() > KIT_MAX {
            return Err(KitError::TooLarge);
        }
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeKey;
    use crate::wire::Role;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    const EID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn auth() -> EventAuthority {
        EventAuthority::new([9; 32], EID, 1_000, 100_000)
    }

    fn tables(np: usize, pl: usize, nq: usize, ql: usize) -> Tables {
        Tables {
            phrases: (0..np).map(|i| format!("{:0>w$}", i, w = pl)).collect(),
            points: (0..nq).map(|i| format!("{:0>w$}", i, w = ql)).collect(),
        }
    }

    fn good_kit() -> Vec<u8> {
        auth()
            .make_kit(
                [4; 32],
                7,
                Role::Full,
                tables(20, 12, 10, 6),
                [3; 32],
                5,
                vec![0xAA; 16],
            )
            .unwrap()
    }

    #[test]
    fn kit_round_trip_and_size() {
        let a = auth();
        let r = a.make_kit(
            [4; 32],
            7,
            Role::Full,
            tables(32, 12, 16, 6),
            [3; 32],
            5,
            vec![],
        );
        assert_eq!(r, Err(KitError::Tables));
        let t = tables(20, 12, 10, 6);
        let kit = a
            .make_kit(
                [4; 32],
                7,
                Role::Full,
                t.clone(),
                [3; 32],
                5,
                vec![0xAA; 16],
            )
            .unwrap();
        std::println!("kit size = {} bytes (KIT_MAX {})", kit.len(), KIT_MAX);
        assert!(kit.len() <= KIT_MAX);
        let k = open_kit(&kit, 2_000).unwrap();
        assert_eq!(k.event_id, EID);
        assert_eq!(k.start, 1_000);
        assert_eq!(k.expiry, 100_000);
        assert_eq!(k.device_seed, [4; 32]);
        assert_eq!(k.event_pub, a.public());
        assert_eq!(k.channel, vec![0xAA; 16]);
        assert_eq!(k.tables, t);
        assert_eq!(k.tag_secret, [3; 32]);
        assert_eq!(k.checkin_minutes, 5);
        assert_eq!(k.card.node, 7);
        assert_eq!(k.card.role, Role::Full);
        assert_eq!(k.card.pubkey, NodeKey::from_seed([4; 32]).public());
        assert!(crate::crypto::verify_card(&k.event_pub, &EID, &k.card));
    }

    #[test]
    fn kit_make_validates() {
        let a = auth();
        let t = || tables(2, 4, 2, 4);
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t(), [3; 32], 0, vec![]),
            Err(KitError::Malformed)
        );
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t(), [3; 32], 61, vec![]),
            Err(KitError::Malformed)
        );
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t(), [3; 32], 5, vec![0; 65]),
            Err(KitError::Malformed)
        );
        assert_eq!(
            a.make_kit([4; 32], 0, Role::Full, t(), [3; 32], 5, vec![]),
            Err(KitError::Malformed)
        );
        let long = Tables {
            phrases: vec!["x".repeat(41)],
            points: vec![],
        };
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, long, [3; 32], 5, vec![]),
            Err(KitError::Tables)
        );
    }

    /// Patch a kit's signed bytes and re-sign them with the event key, so a
    /// test reaches the checks behind the signature.
    fn resign(a: &EventAuthority, kit: &[u8], patch: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut signed = kit[..kit.len() - SIG_LEN].to_vec();
        patch(&mut signed);
        let sig = a.sign_raw(&signed);
        signed.extend_from_slice(&sig);
        signed
    }

    #[test]
    fn checkin_minutes_at_most_30() {
        // M3: past 30 minutes an order (2 x interval, capped at 60) could
        // not be renewed before it lapsed.
        let a = auth();
        let t = || tables(2, 4, 2, 4);
        let ok = a
            .make_kit([4; 32], 7, Role::Full, t(), [3; 32], 30, vec![])
            .unwrap();
        assert_eq!(open_kit(&ok, 2_000).unwrap().checkin_minutes, 30);
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t(), [3; 32], 31, vec![]),
            Err(KitError::Malformed)
        );
        // A validly signed kit carrying 31 is refused on opening, too.
        let bad = resign(&a, &ok, |k| *k.last_mut().unwrap() = 31);
        assert_eq!(open_kit(&bad, 2_000), Err(KitError::Malformed));
        let same = resign(&a, &ok, |_| {});
        assert!(
            open_kit(&same, 2_000).is_ok(),
            "control: re-signing alone is fine"
        );
    }

    #[test]
    fn phrase_rejects_bidi_override() {
        let a = auth();
        let mut t = tables(2, 4, 2, 4);
        t.phrases[0] = "go \u{202E}htron".to_string();
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t, [3; 32], 5, vec![]),
            Err(KitError::Tables)
        );
        let mut t = tables(2, 4, 2, 4);
        t.points[1] = "\u{FEFF}x".to_string();
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t, [3; 32], 5, vec![]),
            Err(KitError::Tables)
        );
        // A validly signed kit whose phrase "0000" became "0" + U+202E.
        let ok = a
            .make_kit(
                [4; 32],
                7,
                Role::Full,
                tables(2, 4, 2, 4),
                [3; 32],
                5,
                vec![],
            )
            .unwrap();
        let at = EVENT_PUB_AT
            + 32
            + ok[EVENT_PUB_AT + 32..]
                .windows(5)
                .position(|w| w == b"\x040000")
                .unwrap();
        let bad = resign(&a, &ok, |k| {
            k[at + 2..at + 5].copy_from_slice(&[0xE2, 0x80, 0xAE])
        });
        assert_eq!(open_kit(&bad, 2_000), Err(KitError::Tables));
    }

    #[test]
    fn kit_card_signed_by_wrong_authority() {
        let a = auth();
        let dev = NodeKey::from_seed([4; 32]).public();
        // different event key, same event id
        let other_key = EventAuthority::new([10; 32], EID, 1_000, 100_000);
        let c1 = other_key.issue_card(dev, 7, Role::Full, 100_000);
        // same event key, different event id
        let other_id = EventAuthority::new([9; 32], [8; 8], 1_000, 100_000);
        let c2 = other_id.issue_card(dev, 7, Role::Full, 100_000);
        for c in [c1, c2] {
            let kit = a
                .build_kit([4; 32], c, tables(2, 4, 2, 4), [3; 32], 5, vec![])
                .unwrap();
            assert_eq!(open_kit(&kit, 2_000), Err(KitError::CardMismatch));
        }
    }

    #[test]
    fn kit_card_expiry_checked() {
        let a = auth();
        let dev = NodeKey::from_seed([4; 32]).public();
        let c = a.issue_card(dev, 7, Role::Full, 50_000);
        let kit = a
            .build_kit([4; 32], c, tables(2, 4, 2, 4), [3; 32], 5, vec![])
            .unwrap();
        assert!(open_kit(&kit, 49_999).is_ok());
        assert_eq!(open_kit(&kit, 50_000), Err(KitError::Expired));
        assert_eq!(open_kit(&kit, 60_000), Err(KitError::Expired));
    }

    #[test]
    fn kit_debug_redacts_secrets() {
        let a = auth();
        let kit = a
            .make_kit(
                [0xA7; 32],
                7,
                Role::Full,
                tables(2, 4, 2, 4),
                [0xB9; 32],
                5,
                vec![],
            )
            .unwrap();
        let k = open_kit(&kit, 2_000).unwrap();
        let d = format!("{:?}", k);
        assert!(d.contains("<redacted>"));
        for (b, dec) in [(0xA7u8, "167"), (0xB9u8, "185")] {
            assert!(!d.contains(&format!("{:02x}{:02x}{:02x}", b, b, b)));
            assert!(!d.contains(&format!("{dec}, {dec}")), "{d}");
        }
    }

    #[test]
    fn kit_rejects() {
        let kit = good_kit();
        for i in 0..kit.len() {
            let mut g = kit.clone();
            g[i] ^= 0x01;
            assert_eq!(open_kit(&g, 2_000), Err(KitError::Signature), "byte {i}");
        }
        // card for another seed, validly signed
        let a = auth();
        let other = NodeKey::from_seed([77; 32]).public();
        let card = a.issue_card(other, 7, Role::Full, 100_000);
        let bad = a
            .build_kit([4; 32], card, tables(2, 4, 2, 4), [3; 32], 5, vec![])
            .unwrap();
        assert_eq!(open_kit(&bad, 2_000), Err(KitError::CardMismatch));
        // expiry
        assert_eq!(open_kit(&kit, 100_000), Err(KitError::Expired));
        assert_eq!(open_kit(&kit, 100_001), Err(KitError::Expired));
        // too large
        assert_eq!(open_kit(&vec![0u8; 1025], 2_000), Err(KitError::TooLarge));
        // truncation / trailing / empty
        assert!(open_kit(&[], 2_000).is_err());
        assert!(open_kit(&kit[..kit.len() - 1], 2_000).is_err());
        let mut longer = kit.clone();
        longer.push(0);
        assert!(open_kit(&longer, 2_000).is_err());
        // control char in a phrase, validly signed: build via build_kit bypassing? make_kit must refuse
        let mut t = tables(2, 4, 2, 4);
        t.phrases[0] = "a\nb".to_string();
        assert_eq!(
            a.make_kit([4; 32], 7, Role::Full, t, [3; 32], 5, vec![]),
            Err(KitError::Tables)
        );
    }
}
