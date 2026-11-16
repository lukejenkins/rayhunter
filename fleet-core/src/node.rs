//! The receiver and sender: roster, permissions, replay, time, revocation and
//! the pending queue. Everything received is hostile; nothing here panics.

use crate::consts::*;
use crate::crypto::{NodeKey, verify_card, verify_frame, verify_revocation};
use crate::kit::Kit;
use crate::replay::Window;
use crate::wire::{
    Body, Card, Directive, Frame, Header, HealthCode, Level, Role, VerdictKind, WireError, decode,
};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Verdict {
        node: u16,
        role: Role,
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
        time: u32,
    },
    Status {
        node: u16,
        phrase: u8,
        time: u32,
    },
    CheckIn {
        node: u16,
        hub_snr: i8,
        time: u32,
    },
    Directive {
        node: u16,
        directive: Directive,
        time: u32,
    },
    CardLearned {
        node: u16,
        role: Role,
    },
    Revoked {
        node: u16,
    },
    HubHealth {
        code: HealthCode,
        subject: u16,
        value: u8,
    },
    RelayOrder {
        target: u16,
        minutes: u8,
        time: u32,
    },
}

/// Rejection counters, one per reason. Counts only; never holds frame bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rejects {
    pub wire: u32,
    pub signature: u32,
    pub unknown_sender: u32,
    pub not_allowed: u32,
    pub replay: u32,
    pub future: u32,
    pub expired: u32,
    pub revoked: u32,
    pub pending_dropped: u32,
    /// A Verdict closer than `VERDICT_INTERVAL - 30` s (sender's clock) to
    /// the sender's last accepted one of the same kind.
    pub rate_limited: u32,
    /// Dated more than `MAX_AGE` before `now` (all but Roster and Revocation).
    pub stale: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    Wire(WireError),
    Revoked,
    Expired,
    NotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardError {
    /// Not signed by this event's key.
    Signature,
    /// Node number 0 is invalid.
    NodeZero,
    /// A different card is already known for this node number.
    Conflict,
}

struct Pending {
    bytes: Vec<u8>,
    node: u16,
    at: u32,
}

pub struct Node {
    kit: Kit,
    key: NodeKey,
    cards: BTreeMap<u16, Card>,
    revoked: BTreeSet<u16>,
    windows: BTreeMap<u16, Window>,
    pending: VecDeque<Pending>,
    rejects: Rejects,
    last_counter: Option<u32>,
    last_verdict: BTreeMap<u8, u32>,
    /// (sender, kind code) -> frame time of its last accepted Verdict.
    rx_verdict: BTreeMap<(u16, u8), u32>,
    self_revoked: bool,
    last_send_revoked: Option<u16>,
}

impl Node {
    pub fn new(kit: Kit) -> Node {
        let key = NodeKey::from_seed(kit.device_seed);
        let mut own = kit.card.clone();
        own.expiry = own.expiry.min(kit.expiry);
        let mut cards = BTreeMap::new();
        cards.insert(own.node, own);
        Node {
            kit,
            key,
            cards,
            revoked: BTreeSet::new(),
            windows: BTreeMap::new(),
            pending: VecDeque::new(),
            rejects: Rejects::default(),
            last_counter: None,
            last_verdict: BTreeMap::new(),
            rx_verdict: BTreeMap::new(),
            self_revoked: false,
            last_send_revoked: None,
        }
    }

    pub fn me(&self) -> u16 {
        self.kit.card.node
    }

    pub fn role(&self) -> Role {
        self.kit.card.role
    }

    /// Known, unrevoked members.
    pub fn roster(&self) -> impl Iterator<Item = (u16, Role)> {
        self.cards
            .iter()
            .filter(|(n, _)| !self.revoked.contains(n))
            .map(|(n, c)| (*n, c.role))
    }

    pub fn is_revoked(&self, node: u16) -> bool {
        self.revoked.contains(&node)
    }

    /// After a successful `send`/`revoke_self`: the node its Revocation newly
    /// revoked here, or `None` (not a revocation, or already revoked). Reset
    /// by every `send` call. The caller feeds `Inbound::Revoked` to its
    /// Corroborator and planner only when this is `Some`.
    pub fn last_send_revoked(&self) -> Option<u16> {
        self.last_send_revoked
    }

    pub fn rejected(&self) -> &Rejects {
        &self.rejects
    }

    /// Load a member's card directly (the hub, at provisioning). Learned the
    /// same way as a Roster frame: for a newly learned card returns
    /// `CardLearned` followed by the Inbounds of any pending frames from that
    /// node, released through rules 5-9 against `now`, in arrival order.
    /// An identical re-learn returns nothing; so does a revoked node's card.
    pub fn add_card(&mut self, c: Card, now: u32) -> Result<Vec<Inbound>, CardError> {
        if c.node == 0 {
            return Err(CardError::NodeZero);
        }
        if !verify_card(&self.kit.event_pub, &self.kit.event_id, &c) {
            return Err(CardError::Signature);
        }
        let mut out = Vec::new();
        match self.learn(c, now, &mut out) {
            Learn::Conflict => Err(CardError::Conflict),
            Learn::New | Learn::Same => Ok(out),
        }
    }

    pub fn receive(&mut self, bytes: &[u8], now: u32) -> Vec<Inbound> {
        let mut out = Vec::new();
        self.expire_pending(now);
        // Rule 1.
        let frame = match decode(bytes) {
            Ok(f) => f,
            Err(_) => {
                bump(&mut self.rejects.wire);
                return out;
            }
        };
        let h = frame.header;
        // Our own frame, echoed back by a relay: never an Inbound.
        if h.node == self.me() {
            bump(&mut self.rejects.replay);
            return out;
        }
        // Rule 2.
        if now >= self.kit.expiry || h.time < self.kit.start || h.time >= self.kit.expiry {
            bump(&mut self.rejects.expired);
            return out;
        }
        if h.time > now.saturating_add(FUTURE_SKEW) {
            bump(&mut self.rejects.future);
            return out;
        }
        // I2: old frames replayed off the air (to a rebooted or late
        // receiver) are refused at receipt. Cards and revocations stay good.
        let ageless = matches!(frame.body, Body::Roster(_) | Body::Revocation { .. });
        if !ageless && h.time.saturating_add(MAX_AGE) < now {
            bump(&mut self.rejects.stale);
            return out;
        }
        // Rule 3.
        let mut announce = None;
        if let Body::Roster(c) = &frame.body {
            if !verify_card(&self.kit.event_pub, &self.kit.event_id, c) {
                bump(&mut self.rejects.signature);
                return out;
            }
            if c.node == h.node && c.role == Role::Hub {
                let mut c = c.clone();
                c.expiry = c.expiry.min(self.kit.expiry);
                announce = Some(c);
            }
        }
        // Rule 4.
        let sender = match self.cards.get(&h.node) {
            Some(c) => c.clone(),
            None => match announce {
                Some(c) => c,
                None => {
                    if self.revoked.contains(&h.node) {
                        // A revoked node's frames never wait.
                        bump(&mut self.rejects.revoked);
                    } else if self.enqueue(bytes, h.node, now) {
                        bump(&mut self.rejects.unknown_sender);
                    }
                    return out;
                }
            },
        };
        self.verified_rules(bytes, frame, &sender, now, &mut out);
        out
    }

    /// Rules 5-9, given the sender's card.
    fn verified_rules(
        &mut self,
        bytes: &[u8],
        frame: Frame,
        sender: &Card,
        now: u32,
        out: &mut Vec<Inbound>,
    ) {
        let h = frame.header;
        // Rule 5.
        if !verify_frame(&sender.pubkey, &self.kit.event_id, bytes) {
            bump(&mut self.rejects.signature);
            return;
        }
        // Rule 6.
        if self.revoked.contains(&h.node) {
            bump(&mut self.rejects.revoked);
            return;
        }
        if now >= sender.expiry {
            bump(&mut self.rejects.expired);
            return;
        }
        // Rule 7.
        if !self.allowed(sender.role, h.node, &frame.body) {
            bump(&mut self.rejects.not_allowed);
            return;
        }
        // Rule 8.
        if !self
            .windows
            .entry(h.node)
            .or_default()
            .check_and_set(h.counter)
        {
            bump(&mut self.rejects.replay);
            return;
        }
        // Rule 9.
        let (node, time) = (h.node, h.time);
        match frame.body {
            Body::Roster(c) => {
                if let Learn::Conflict = self.learn(c, now, out) {
                    bump(&mut self.rejects.signature);
                }
            }
            Body::Revocation { target, .. } => self.mark_revoked(target, out),
            Body::Verdict { kind, level, tag } => {
                // I1a: at most one verdict per kind per sender per interval
                // (less 30 s of slack), by the sender's own clock.
                let key = (node, kind.code());
                if let Some(&last) = self.rx_verdict.get(&key) {
                    if last as u64 + (VERDICT_INTERVAL - 30) as u64 > time as u64 {
                        bump(&mut self.rejects.rate_limited);
                        return;
                    }
                }
                self.rx_verdict.insert(key, time);
                out.push(Inbound::Verdict {
                    node,
                    role: sender.role,
                    kind,
                    level,
                    tag,
                    time,
                })
            }
            Body::Status { phrase } => out.push(Inbound::Status { node, phrase, time }),
            Body::CheckIn { hub_snr } => out.push(Inbound::CheckIn {
                node,
                hub_snr,
                time,
            }),
            Body::Directive(directive) => out.push(Inbound::Directive {
                node,
                directive,
                time,
            }),
            Body::HubHealth {
                code,
                subject,
                value,
            } => out.push(Inbound::HubHealth {
                code,
                subject,
                value,
            }),
            Body::RelayOrder { target, minutes } => out.push(Inbound::RelayOrder {
                target,
                minutes,
                time,
            }),
        }
    }

    /// The wire-format role table plus the content checks of rule 7. Also
    /// used on the sending side, so a node never sends what will be refused.
    fn allowed(&self, role: Role, sender: u16, body: &Body) -> bool {
        let t = &self.kit.tables;
        match body {
            // M1: network kinds never carry a tag, whoever sends them.
            Body::Verdict { kind, tag, .. } if kind.is_network() && tag.is_some() => false,
            Body::Verdict { kind, tag, .. } => match role {
                Role::Full => true,
                Role::Light => tag.is_none() && *kind != VerdictKind::TowerFlood,
                _ => false,
            },
            Body::Status { phrase } => (*phrase as usize) < t.phrases.len(),
            Body::CheckIn { .. } => true,
            Body::Directive(d) => {
                role == Role::Organiser
                    && match d {
                        Directive::Phrase(p) => (*p as usize) < t.phrases.len(),
                        Directive::Point(p) => (*p as usize) < t.points.len(),
                        Directive::Text(_) => true,
                    }
            }
            Body::Roster(_) | Body::HubHealth { .. } | Body::RelayOrder { .. } => role == Role::Hub,
            Body::Revocation { target, event_sig } => {
                *target != 0
                    && (*target == sender
                        || event_sig.as_ref().is_some_and(|s| {
                            verify_revocation(&self.kit.event_pub, &self.kit.event_id, *target, s)
                        }))
            }
        }
    }

    /// Learn a verified card: emits `CardLearned` (never for a revoked node),
    /// then re-runs the pending queue for its node.
    fn learn(&mut self, mut c: Card, now: u32, out: &mut Vec<Inbound>) -> Learn {
        c.expiry = c.expiry.min(self.kit.expiry);
        if let Some(known) = self.cards.get(&c.node) {
            return if *known == c {
                Learn::Same
            } else {
                Learn::Conflict
            };
        }
        let (node, role) = (c.node, c.role);
        self.cards.insert(node, c.clone());
        if !self.revoked.contains(&node) {
            out.push(Inbound::CardLearned { node, role });
        }
        self.release(&c, now, out);
        Learn::New
    }

    /// Re-run node's pending frames through rules 5-9, in arrival order.
    fn release(&mut self, card: &Card, now: u32, out: &mut Vec<Inbound>) {
        self.expire_pending(now);
        let mut mine = Vec::new();
        let mut rest = VecDeque::new();
        for p in self.pending.drain(..) {
            if p.node == card.node {
                mine.push(p);
            } else {
                rest.push_back(p);
            }
        }
        self.pending = rest;
        for p in mine {
            match decode(&p.bytes) {
                Ok(f) => self.verified_rules(&p.bytes, f, card, now, out),
                Err(_) => bump(&mut self.rejects.wire),
            }
        }
    }

    fn mark_revoked(&mut self, target: u16, out: &mut Vec<Inbound>) {
        if target == self.me() {
            self.self_revoked = true;
        }
        if !self.revoked.insert(target) {
            return;
        }
        let before = self.pending.len();
        self.pending.retain(|p| p.node != target);
        for _ in self.pending.len()..before {
            bump(&mut self.rejects.revoked);
        }
        out.push(Inbound::Revoked { node: target });
    }

    /// False if identical bytes are already queued: the same frame heard
    /// through several relays takes one slot, and is counted once.
    fn enqueue(&mut self, bytes: &[u8], node: u16, now: u32) -> bool {
        if self.pending.iter().any(|p| p.bytes == bytes) {
            return false;
        }
        if self.pending.len() >= PENDING_MAX {
            self.pending.pop_front();
            bump(&mut self.rejects.pending_dropped);
        }
        self.pending.push_back(Pending {
            bytes: bytes.to_vec(),
            node,
            at: now,
        });
        true
    }

    /// Drop entries older than PENDING_TTL (an entry exactly that old stays).
    fn expire_pending(&mut self, now: u32) {
        let before = self.pending.len();
        self.pending
            .retain(|p| now.saturating_sub(p.at) <= PENDING_TTL);
        for _ in self.pending.len()..before {
            bump(&mut self.rejects.pending_dropped);
        }
    }

    /// Sign `body` with this node's key and assign the next counter.
    /// Verdicts must go through [`Node::send_verdict`], which applies the
    /// per-kind rate limit (`VERDICT_INTERVAL`); `send` does not.
    pub fn send(&mut self, body: Body, now: u32) -> Result<Vec<u8>, SendError> {
        self.last_send_revoked = None;
        if self.self_revoked {
            return Err(SendError::Revoked);
        }
        if now >= self.kit.expiry || now >= self.kit.card.expiry {
            return Err(SendError::Expired);
        }
        if !self.allowed(self.role(), self.me(), &body) {
            return Err(SendError::NotAllowed);
        }
        let base = now
            .saturating_sub(self.kit.start)
            .saturating_mul(COUNTER_PER_SEC);
        let counter = match self.last_counter {
            None => base,
            // Counter space exhausted: a repeat would only be dropped as a replay.
            Some(last) => last.checked_add(1).ok_or(SendError::Expired)?.max(base),
        };
        let h = Header {
            node: self.me(),
            counter,
            time: now,
        };
        let f = self
            .key
            .sign_frame(&self.kit.event_id, &h, &body)
            .map_err(SendError::Wire)?;
        self.last_counter = Some(counter);
        // A revocation this node sends applies here too, exactly as receipt
        // would: the relayed echo is dropped as our own frame. The caller
        // feeds its Corroborator and planner `Inbound::Revoked`.
        if let Body::Revocation { target, .. } = body {
            let mut out = Vec::new();
            self.mark_revoked(target, &mut out);
            if !out.is_empty() {
                self.last_send_revoked = Some(target);
            }
        }
        Ok(f)
    }

    pub fn send_verdict(
        &mut self,
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
        now: u32,
    ) -> Result<Option<Vec<u8>>, SendError> {
        if self.self_revoked {
            return Err(SendError::Revoked);
        }
        let role = self.role();
        if !matches!(role, Role::Full | Role::Light)
            || (role == Role::Light && kind == VerdictKind::TowerFlood)
        {
            return Err(SendError::NotAllowed);
        }
        if let Some(&last) = self.last_verdict.get(&kind.code()) {
            // Symmetric, so a clock stepped far backwards can't silence a
            // kind for longer than the interval.
            if now.abs_diff(last) < VERDICT_INTERVAL {
                return Ok(None);
            }
        }
        let tag = if role == Role::Full && !kind.is_network() {
            tag
        } else {
            None
        };
        let f = self.send(Body::Verdict { kind, level, tag }, now)?;
        self.last_verdict.insert(kind.code(), now);
        Ok(Some(f))
    }

    pub fn revoke_self(&mut self, now: u32) -> Result<Vec<u8>, SendError> {
        let f = self.send(
            Body::Revocation {
                target: self.me(),
                event_sig: None,
            },
            now,
        )?;
        self.self_revoked = true;
        Ok(f)
    }
}

enum Learn {
    New,
    Same,
    Conflict,
}

fn bump(n: &mut u32) {
    *n = n.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EventAuthority;
    use crate::kit::{Tables, open_kit};
    use alloc::string::{String, ToString};
    use alloc::vec;

    const EID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const START: u32 = 1_000;
    const EXPIRY: u32 = 100_000;
    const T: u32 = START + 1_000;
    const ROLES: [Role; 5] = [
        Role::Full,
        Role::Light,
        Role::Messenger,
        Role::Organiser,
        Role::Hub,
    ];

    fn event() -> EventAuthority {
        EventAuthority::new([9; 32], EID, START, EXPIRY)
    }

    /// Three phrases, two points.
    fn tables() -> Tables {
        Tables {
            phrases: vec![
                "regroup".to_string(),
                "move north".into(),
                "all clear".into(),
            ],
            points: vec!["fountain".to_string(), "bridge".into()],
        }
    }

    fn seed(node: u16) -> [u8; 32] {
        let mut s = [node as u8; 32];
        s[0] = 0x40;
        s[1] = (node >> 8) as u8;
        s
    }

    fn pubkey(node: u16) -> [u8; 32] {
        NodeKey::from_seed(seed(node)).public()
    }

    fn card(a: &EventAuthority, node: u16, role: Role) -> Card {
        a.issue_card(pubkey(node), node, role, EXPIRY)
    }

    fn kit(a: &EventAuthority, node: u16, role: Role) -> Kit {
        let bytes = a
            .make_kit(seed(node), node, role, tables(), [3; 32], 5, vec![])
            .unwrap();
        open_kit(&bytes, START).unwrap()
    }

    fn member(a: &EventAuthority, node: u16, role: Role) -> Node {
        Node::new(kit(a, node, role))
    }

    /// Node 1 (Full) that already knows the given members' cards.
    fn receiver(a: &EventAuthority, members: &[(u16, Role)]) -> Node {
        let mut r = member(a, 1, Role::Full);
        for &(n, role) in members {
            assert_eq!(
                r.add_card(card(a, n, role), START),
                Ok(vec![Inbound::CardLearned { node: n, role }])
            );
        }
        r
    }

    /// A frame signed by `node`'s real key, bypassing every sender-side check.
    fn forge(node: u16, counter: u32, time: u32, body: &Body) -> Vec<u8> {
        NodeKey::from_seed(seed(node))
            .sign_frame(
                &EID,
                &Header {
                    node,
                    counter,
                    time,
                },
                body,
            )
            .unwrap()
    }

    fn verdict(kind: VerdictKind, tag: Option<[u8; 8]>) -> Body {
        Body::Verdict {
            kind,
            level: Level::High,
            tag,
        }
    }

    fn imsi() -> Body {
        verdict(VerdictKind::ImsiRequested, None)
    }

    /// A body with no rate limit, for tests about replay, time and queueing.
    fn status() -> Body {
        Body::Status { phrase: 0 }
    }

    #[test]
    fn accepts_valid_frames() {
        let a = event();
        let mut r = receiver(&a, &[]);
        let mut hub = member(&a, 6, Role::Hub);
        let mut full = member(&a, 2, Role::Full);
        let mut light = member(&a, 3, Role::Light);
        let mut msgr = member(&a, 4, Role::Messenger);
        let mut org = member(&a, 5, Role::Organiser);

        // Hub self-announcement: learned before anything else.
        let f = hub.send(Body::Roster(card(&a, 6, Role::Hub)), T).unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::CardLearned {
                node: 6,
                role: Role::Hub
            }]
        );
        for (n, role) in [
            (2, Role::Full),
            (3, Role::Light),
            (4, Role::Messenger),
            (5, Role::Organiser),
        ] {
            let f = hub.send(Body::Roster(card(&a, n, role)), T).unwrap();
            assert_eq!(
                r.receive(&f, T),
                vec![Inbound::CardLearned { node: n, role }]
            );
        }

        let tag = Some([7u8; 8]);
        let f = full
            .send_verdict(VerdictKind::NullCipher, Level::Medium, tag, T)
            .unwrap()
            .unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::Verdict {
                node: 2,
                role: Role::Full,
                kind: VerdictKind::NullCipher,
                level: Level::Medium,
                tag,
                time: T
            }]
        );
        let f = light
            .send_verdict(VerdictKind::ServiceLost, Level::Low, None, T)
            .unwrap()
            .unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::Verdict {
                node: 3,
                role: Role::Light,
                kind: VerdictKind::ServiceLost,
                level: Level::Low,
                tag: None,
                time: T
            }]
        );
        let f = msgr.send(Body::Status { phrase: 2 }, T).unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::Status {
                node: 4,
                phrase: 2,
                time: T
            }]
        );
        let f = light.send(Body::CheckIn { hub_snr: -9 }, T + 1).unwrap();
        assert_eq!(
            r.receive(&f, T + 1),
            vec![Inbound::CheckIn {
                node: 3,
                hub_snr: -9,
                time: T + 1
            }]
        );
        for d in [
            Directive::Phrase(1),
            Directive::Point(1),
            Directive::Text(String::from("hold at the bridge")),
        ] {
            let f = org.send(Body::Directive(d.clone()), T).unwrap();
            assert_eq!(
                r.receive(&f, T),
                vec![Inbound::Directive {
                    node: 5,
                    directive: d,
                    time: T
                }]
            );
        }
        let f = hub
            .send(
                Body::HubHealth {
                    code: HealthCode::BatteryLow,
                    subject: 3,
                    value: 12,
                },
                T,
            )
            .unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::HubHealth {
                code: HealthCode::BatteryLow,
                subject: 3,
                value: 12
            }]
        );
        let f = hub
            .send(
                Body::RelayOrder {
                    target: 2,
                    minutes: 15,
                },
                T,
            )
            .unwrap();
        assert_eq!(
            r.receive(&f, T),
            vec![Inbound::RelayOrder {
                target: 2,
                minutes: 15,
                time: T
            }]
        );
        let f = msgr.revoke_self(T).unwrap();
        assert_eq!(r.receive(&f, T), vec![Inbound::Revoked { node: 4 }]);
        assert_eq!(*r.rejected(), Rejects::default());
        assert_eq!(r.me(), 1);
        assert_eq!(r.role(), Role::Full);
        let roster: Vec<(u16, Role)> = r.roster().collect();
        assert_eq!(
            roster,
            vec![
                (1, Role::Full),
                (2, Role::Full),
                (3, Role::Light),
                // 4 revoked itself: no longer listed.
                (5, Role::Organiser),
                (6, Role::Hub)
            ]
        );
        assert!(r.is_revoked(4) && !r.is_revoked(3));
    }

    #[test]
    fn permission_matrix() {
        use Role::*;
        let a = event();
        let rev_other = Body::Revocation {
            target: 9,
            event_sig: None,
        };
        let cases: Vec<(Body, &[Role])> = vec![
            (imsi(), &[Full, Light]),
            (verdict(VerdictKind::Downgraded, None), &[Full, Light]),
            (verdict(VerdictKind::NullCipher, Some([1; 8])), &[Full]),
            (verdict(VerdictKind::TowerFlood, None), &[Full]),
            // M1: a network kind never carries a tag, from anyone.
            (verdict(VerdictKind::Downgraded, Some([2; 8])), &[]),
            (Body::Status { phrase: 0 }, &ROLES),
            (Body::CheckIn { hub_snr: -3 }, &ROLES),
            (Body::Directive(Directive::Phrase(0)), &[Organiser]),
            (Body::Directive(Directive::Point(0)), &[Organiser]),
            (
                Body::Directive(Directive::Text("go".to_string())),
                &[Organiser],
            ),
            (Body::Roster(card(&a, 9, Full)), &[Hub]),
            (rev_other, &[]),
            (
                Body::HubHealth {
                    code: HealthCode::UnitLost,
                    subject: 2,
                    value: 0,
                },
                &[Hub],
            ),
            (
                Body::RelayOrder {
                    target: 2,
                    minutes: 5,
                },
                &[Hub],
            ),
        ];
        // One receiver per sender role; a fresh counter per case, so only
        // the permission decides.
        for role in ROLES {
            let mut r = receiver(&a, &[(2, role)]);
            for (i, (body, allowed)) in cases.iter().enumerate() {
                let refused = r.rejected().not_allowed;
                let out = r.receive(&forge(2, i as u32 + 1, T, body), T);
                if allowed.contains(&role) {
                    assert_eq!(out.len(), 1, "{body:?} from {role:?} should pass");
                    assert_eq!(r.rejected().not_allowed, refused);
                } else {
                    assert!(out.is_empty(), "{body:?} from {role:?} should be refused");
                    assert_eq!(
                        r.rejected().not_allowed,
                        refused + 1,
                        "{body:?} from {role:?}"
                    );
                }
            }
            // Nothing was refused for any other reason.
            assert_eq!(
                *r.rejected(),
                Rejects {
                    not_allowed: r.rejected().not_allowed,
                    ..Default::default()
                }
            );
        }
    }

    #[test]
    fn duplicate_dropped() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        let f = forge(2, 100, T, &status());
        assert_eq!(r.receive(&f, T).len(), 1);
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().replay, 1);

        assert_eq!(r.receive(&forge(2, 200, T, &status()), T).len(), 1);
        // Older but unseen, inside the window: accepted, once.
        assert_eq!(r.receive(&forge(2, 150, T, &status()), T).len(), 1);
        assert!(r.receive(&forge(2, 150, T, &status()), T).is_empty());
        assert_eq!(r.receive(&forge(2, 200 - 63, T, &status()), T).len(), 1);
        // highest - 64 is outside the window.
        assert!(r.receive(&forge(2, 200 - 64, T, &status()), T).is_empty());
        // The old 100 is long outside it.
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().replay, 4);
        // Re-sent highest is a duplicate too.
        assert!(r.receive(&forge(2, 200, T, &status()), T).is_empty());
        assert_eq!(r.rejected().replay, 5);
        // A big jump forward is fine, and clears the old bitmap.
        assert_eq!(r.receive(&forge(2, 200 + 1_000, T, &status()), T).len(), 1);
        assert_eq!(
            *r.rejected(),
            Rejects {
                replay: 5,
                ..Default::default()
            }
        );
    }

    #[test]
    fn future_frame_rejected() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        assert!(r.receive(&forge(2, 1, T + 301, &status()), T).is_empty());
        assert_eq!(r.rejected().future, 1);
        assert_eq!(r.receive(&forge(2, 2, T + 299, &status()), T).len(), 1);
        assert_eq!(r.receive(&forge(2, 3, T + 300, &status()), T).len(), 1);
        // The rejected frame never entered the replay window either: the same
        // counter is still fresh.
        assert_eq!(r.receive(&forge(2, 1, T, &status()), T).len(), 1);
        assert_eq!(
            *r.rejected(),
            Rejects {
                future: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn stale_frames_rejected() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full), (5, Role::Organiser), (6, Role::Hub)]);
        let now = T + 4 * 3600;
        // A 3-hour-old Directive, replayed off the air.
        let d = Body::Directive(Directive::Phrase(0));
        assert!(r.receive(&forge(5, 1, now - 3 * 3600, &d), now).is_empty());
        // A 16-minute-old CheckIn: a restarted hub can't be fooled by it.
        let ci = Body::CheckIn { hub_snr: -3 };
        assert!(r.receive(&forge(2, 1, now - 16 * 60, &ci), now).is_empty());
        // From a sender with no card: stale too, and never queued.
        assert!(r.receive(&forge(8, 1, now - 16 * 60, &ci), now).is_empty());
        assert_eq!(
            *r.rejected(),
            Rejects {
                stale: 3,
                ..Default::default()
            }
        );
        // 14 minutes old, and exactly MAX_AGE old, are accepted. The stale
        // frames never entered the replay window: counter 1 is still new.
        assert_eq!(r.receive(&forge(2, 1, now - 14 * 60, &ci), now).len(), 1);
        assert_eq!(r.receive(&forge(2, 2, now - MAX_AGE, &ci), now).len(), 1);
        assert_eq!(r.receive(&forge(5, 1, now - 60, &d), now).len(), 1);
        // Roster and Revocation are exempt: cards and revocations stay good.
        let old = now - 3 * 3600;
        assert_eq!(
            r.receive(
                &forge(6, 1, old, &Body::Roster(card(&a, 9, Role::Light))),
                now
            ),
            vec![Inbound::CardLearned {
                node: 9,
                role: Role::Light
            }]
        );
        let rev = Body::Revocation {
            target: 9,
            event_sig: Some(a.revocation_sig(9)),
        };
        assert_eq!(
            r.receive(&forge(6, 2, old, &rev), now),
            vec![Inbound::Revoked { node: 9 }]
        );
        assert_eq!(r.rejected().stale, 3);
        // Saturating: no panic at the extremes.
        r.receive(&forge(2, 9, 0, &ci), u32::MAX);
        r.receive(&forge(2, 10, u32::MAX, &ci), 0);
    }

    #[test]
    fn expired_event_and_card() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        // A card with an earlier expiry.
        r.add_card(a.issue_card(pubkey(4), 4, Role::Light, START + 500), START)
            .unwrap();
        assert_eq!(
            r.receive(&forge(4, 1, START + 400, &imsi()), START + 400)
                .len(),
            1
        );
        assert!(
            r.receive(&forge(4, 2, START + 500, &imsi()), START + 500)
                .is_empty()
        );
        assert_eq!(r.rejected().expired, 1);
        // Frame times outside [start, expiry) are refused.
        assert!(r.receive(&forge(2, 1, START - 1, &imsi()), T).is_empty());
        assert!(
            r.receive(&forge(2, 2, EXPIRY, &imsi()), EXPIRY - 1)
                .is_empty()
        );
        assert_eq!(r.rejected().expired, 3);
        // (Heard soon after: a frame over MAX_AGE old is stale.)
        assert_eq!(r.receive(&forge(2, 3, START, &imsi()), START + 10).len(), 1);
        // After the event expiry, everything is expired, even a valid frame.
        assert!(
            r.receive(&forge(2, 4, EXPIRY - 10, &imsi()), EXPIRY)
                .is_empty()
        );
        assert!(
            r.receive(&forge(2, 5, EXPIRY - 10, &imsi()), u32::MAX)
                .is_empty()
        );
        assert_eq!(
            *r.rejected(),
            Rejects {
                expired: 5,
                ..Default::default()
            }
        );
    }

    #[test]
    fn forged_signature() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        let f = NodeKey::from_seed(seed(99))
            .sign_frame(
                &EID,
                &Header {
                    node: 2,
                    counter: 1,
                    time: T,
                },
                &imsi(),
            )
            .unwrap();
        assert!(r.receive(&f, T).is_empty());
        // Right key, another event.
        let f = NodeKey::from_seed(seed(2))
            .sign_frame(
                &[0; 8],
                &Header {
                    node: 2,
                    counter: 2,
                    time: T,
                },
                &imsi(),
            )
            .unwrap();
        assert!(r.receive(&f, T).is_empty());
        // A hub self-announcement whose card is not signed by the event key.
        let other = EventAuthority::new([10; 32], EID, START, EXPIRY);
        let f = forge(6, 1, T, &Body::Roster(card(&other, 6, Role::Hub)));
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(
            *r.rejected(),
            Rejects {
                signature: 3,
                ..Default::default()
            }
        );
        // The forged frames did not burn the real sender's counters.
        assert_eq!(r.receive(&forge(2, 1, T, &imsi()), T).len(), 1);
    }

    #[test]
    fn pending_until_card_arrives() {
        let a = event();
        let mut r = receiver(&a, &[]);
        let v7 = forge(7, 1, T, &imsi());
        assert!(r.receive(&v7, T).is_empty());
        assert_eq!(
            *r.rejected(),
            Rejects {
                unknown_sender: 1,
                ..Default::default()
            }
        );
        // The hub announces itself, then rosters node 7.
        let f = forge(6, 1, T + 1, &Body::Roster(card(&a, 6, Role::Hub)));
        assert_eq!(
            r.receive(&f, T + 1),
            vec![Inbound::CardLearned {
                node: 6,
                role: Role::Hub
            }]
        );
        let f = forge(6, 2, T + 2, &Body::Roster(card(&a, 7, Role::Full)));
        assert_eq!(
            r.receive(&f, T + 2),
            vec![
                Inbound::CardLearned {
                    node: 7,
                    role: Role::Full
                },
                Inbound::Verdict {
                    node: 7,
                    role: Role::Full,
                    kind: VerdictKind::ImsiRequested,
                    level: Level::High,
                    tag: None,
                    time: T
                }
            ]
        );
        // Released once: the same bytes now are a plain replay.
        assert!(r.receive(&v7, T + 3).is_empty());
        assert_eq!(r.rejected().replay, 1);

        // Overflow: 17 frames from unknown node 8; the oldest is dropped.
        let mut r = receiver(&a, &[]);
        for c in 1..=17 {
            assert!(r.receive(&forge(8, c, T, &imsi()), T).is_empty());
        }
        assert_eq!(r.rejected().unknown_sender, 17);
        assert_eq!(r.rejected().pending_dropped, 1);
        // Same again, learning 8 via a hub roster so the released events show.
        let mut r = receiver(&a, &[(6, Role::Hub)]);
        for c in 1..=17 {
            r.receive(&forge(8, c, T, &status()), T);
        }
        let out = r.receive(&forge(6, 1, T, &Body::Roster(card(&a, 8, Role::Full))), T);
        assert_eq!(out.len(), 17);
        assert_eq!(
            out[0],
            Inbound::CardLearned {
                node: 8,
                role: Role::Full
            }
        );
        assert!(
            out[1..]
                .iter()
                .all(|e| matches!(e, Inbound::Status { node: 8, .. }))
        );
        // Counter 1 was the one dropped: it is still fresh.
        assert_eq!(r.receive(&forge(8, 1, T, &status()), T).len(), 1);

        // TTL: an entry older than PENDING_TTL is dropped; one exactly that
        // old stays.
        let mut r = receiver(&a, &[(6, Role::Hub)]);
        assert!(r.receive(&forge(9, 1, T, &imsi()), T).is_empty());
        assert!(r.receive(&forge(9, 2, T + 1, &imsi()), T + 1).is_empty());
        let at = T + PENDING_TTL + 1;
        let out = r.receive(
            &forge(6, 1, at, &Body::Roster(card(&a, 9, Role::Light))),
            at,
        );
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(matches!(
            out[1],
            Inbound::Verdict {
                node: 9,
                time,
                ..
            } if time == T + 1
        ));
        assert_eq!(r.rejected().pending_dropped, 1);
    }

    #[test]
    fn pending_covers_the_longest_roster_gap() {
        // Rosters are up to ROSTER_MAX_SECS apart, so a frame heard just after
        // one may wait that long for the sender's card, and is then released
        // (MAX_AGE is checked at receipt, not at release).
        let a = event();
        let mut r = receiver(&a, &[(6, Role::Hub)]);
        assert!(r.receive(&forge(9, 1, T, &imsi()), T).is_empty());
        let at = T + ROSTER_MAX_SECS;
        let out = r.receive(&forge(6, 1, at, &Body::Roster(card(&a, 9, Role::Full))), at);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(matches!(out[1], Inbound::Verdict { node: 9, time, .. } if time == T));
        assert_eq!(r.rejected().pending_dropped, 0);
        // Via add_card too.
        let mut r = receiver(&a, &[]);
        r.receive(&forge(9, 1, T, &imsi()), T);
        let out = r
            .add_card(card(&a, 9, Role::Full), T + ROSTER_MAX_SECS)
            .unwrap();
        assert_eq!(out.len(), 2, "{out:?}");
        // One second past the TTL is dropped.
        let mut r = receiver(&a, &[]);
        r.receive(&forge(9, 1, T, &imsi()), T);
        let out = r
            .add_card(card(&a, 9, Role::Full), T + PENDING_TTL + 1)
            .unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(r.rejected().pending_dropped, 1);
    }

    #[test]
    fn add_card_releases_pending_against_real_now() {
        let a = event();
        let mut r = receiver(&a, &[]);
        r.receive(&forge(8, 1, T, &imsi()), T);
        let nc = verdict(VerdictKind::NullCipher, None);
        r.receive(&forge(8, 2, T + 1, &nc), T + 1);
        let v = |kind, time| Inbound::Verdict {
            node: 8,
            role: Role::Full,
            kind,
            level: Level::High,
            tag: None,
            time,
        };
        // CardLearned for the provisioned card, then the released frames, in
        // order.
        assert_eq!(
            r.add_card(card(&a, 8, Role::Full), T + 2),
            Ok(vec![
                Inbound::CardLearned {
                    node: 8,
                    role: Role::Full
                },
                v(VerdictKind::ImsiRequested, T),
                v(VerdictKind::NullCipher, T + 1)
            ])
        );
        // Released once: the same bytes now are a replay.
        assert!(r.receive(&forge(8, 1, T, &imsi()), T + 3).is_empty());
        assert_eq!(r.rejected().replay, 1);

        let other = EventAuthority::new([10; 32], EID, START, EXPIRY);
        assert_eq!(
            r.add_card(card(&other, 9, Role::Full), T),
            Err(CardError::Signature)
        );
        assert_eq!(
            r.add_card(a.issue_card(pubkey(9), 0, Role::Full, EXPIRY), T),
            Err(CardError::NodeZero)
        );
        // Identical card again: fine, nothing new. Different key: refused.
        assert_eq!(r.add_card(card(&a, 8, Role::Full), T), Ok(vec![]));
        assert_eq!(
            r.add_card(a.issue_card(pubkey(99), 8, Role::Full, EXPIRY), T),
            Err(CardError::Conflict)
        );
        // The node's own card is in the roster from the start, and cannot be
        // replaced either.
        assert_eq!(
            r.add_card(a.issue_card(pubkey(99), 1, Role::Hub, EXPIRY), T),
            Err(CardError::Conflict)
        );
        assert_eq!(
            r.roster().collect::<Vec<_>>(),
            vec![(1, Role::Full), (8, Role::Full)]
        );
    }

    #[test]
    fn add_card_announces_new_card() {
        // I3: a provisioned card is announced like a rostered one, so the
        // hub's planner learns it from add_card's output.
        let a = event();
        let mut r = receiver(&a, &[]);
        let learned = Inbound::CardLearned {
            node: 8,
            role: Role::Light,
        };
        assert_eq!(r.add_card(card(&a, 8, Role::Light), T), Ok(vec![learned]));
        // An identical re-learn announces nothing.
        assert_eq!(r.add_card(card(&a, 8, Role::Light), T), Ok(vec![]));
        // Pending frames follow the announcement, in arrival order.
        r.receive(&forge(9, 1, T, &status()), T);
        assert_eq!(
            r.add_card(card(&a, 9, Role::Full), T + 1),
            Ok(vec![
                Inbound::CardLearned {
                    node: 9,
                    role: Role::Full
                },
                Inbound::Status {
                    node: 9,
                    phrase: 0,
                    time: T
                }
            ])
        );
        // A revoked node is learned silently.
        let rev = Body::Revocation {
            target: 10,
            event_sig: Some(a.revocation_sig(10)),
        };
        r.add_card(card(&a, 6, Role::Hub), T).unwrap();
        r.receive(&forge(6, 1, T, &rev), T);
        assert_eq!(r.add_card(card(&a, 10, Role::Full), T), Ok(vec![]));
    }

    #[test]
    fn add_card_release_refuses_expired_card() {
        let a = event();
        let mut r = receiver(&a, &[]);
        // Queued while node 4's card would still be valid...
        r.receive(&forge(4, 1, START + 400, &imsi()), START + 400);
        // ...but provisioned only after that card expired.
        let short = a.issue_card(pubkey(4), 4, Role::Light, START + 500);
        let learned = |node, role| Ok(vec![Inbound::CardLearned { node, role }]);
        assert_eq!(r.add_card(short, START + 500), learned(4, Role::Light));
        assert_eq!(
            *r.rejected(),
            Rejects {
                unknown_sender: 1,
                expired: 1,
                ..Default::default()
            }
        );
        // And the real `now` applies the pending TTL too.
        r.receive(&forge(9, 1, T, &imsi()), T);
        assert_eq!(
            r.add_card(card(&a, 9, Role::Full), T + PENDING_TTL + 1),
            learned(9, Role::Full)
        );
        assert_eq!(r.rejected().pending_dropped, 1);
    }

    #[test]
    fn own_echo_dropped() {
        let a = event();
        let mut n = member(&a, 2, Role::Full);
        let f = n.send(Body::Status { phrase: 0 }, T).unwrap();
        assert!(n.receive(&f, T).is_empty());
        assert_eq!(
            *n.rejected(),
            Rejects {
                replay: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn revoked_node_not_learned_or_listed() {
        let a = event();
        let mut r = receiver(&a, &[(3, Role::Light), (6, Role::Hub)]);
        let rev = |c, target| {
            forge(
                6,
                c,
                T,
                &Body::Revocation {
                    target,
                    event_sig: Some(a.revocation_sig(target)),
                },
            )
        };
        assert_eq!(
            r.receive(&rev(1, 10), T),
            vec![Inbound::Revoked { node: 10 }]
        );
        // Its card arriving later in a hub roster: stays revoked, no CardLearned.
        let f = forge(6, 2, T, &Body::Roster(card(&a, 10, Role::Full)));
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(*r.rejected(), Rejects::default());
        assert!(r.is_revoked(10));
        // A known node revoked later drops out of the roster too.
        assert_eq!(r.receive(&rev(3, 3), T), vec![Inbound::Revoked { node: 3 }]);
        assert_eq!(
            r.roster().collect::<Vec<_>>(),
            vec![(1, Role::Full), (6, Role::Hub)]
        );
    }

    #[test]
    fn pending_dedupes_relayed_copies() {
        let a = event();
        let mut r = receiver(&a, &[(6, Role::Hub)]);
        let f = forge(8, 1, T, &imsi());
        for _ in 0..3 {
            assert!(r.receive(&f, T).is_empty());
        }
        assert_eq!(
            *r.rejected(),
            Rejects {
                unknown_sender: 1,
                ..Default::default()
            }
        );
        // One slot: 15 more distinct frames fill the queue without a drop.
        for c in 2..=16 {
            r.receive(&forge(9, c, T, &imsi()), T);
        }
        assert_eq!(r.rejected().pending_dropped, 0);
        let out = r.receive(&forge(6, 1, T, &Body::Roster(card(&a, 8, Role::Full))), T);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(matches!(out[1], Inbound::Verdict { node: 8, .. }));
        assert_eq!(r.rejected().replay, 0);
    }

    #[test]
    fn card_relearning_rules() {
        let a = event();
        let mut r = receiver(&a, &[(6, Role::Hub)]);
        let f = forge(6, 1, T, &Body::Roster(card(&a, 7, Role::Full)));
        assert_eq!(r.receive(&f, T).len(), 1);
        // The identical card again (a new frame): no second CardLearned.
        let f = forge(6, 2, T, &Body::Roster(card(&a, 7, Role::Full)));
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(*r.rejected(), Rejects::default());
        // A different key for a known node number: refused as `signature`.
        let f = forge(
            6,
            3,
            T,
            &Body::Roster(a.issue_card(pubkey(70), 7, Role::Full, EXPIRY)),
        );
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().signature, 1);
        // A hub self-announcement with a different key for a known hub number
        // must verify against the KNOWN card, so it fails as signature too.
        let f = NodeKey::from_seed(seed(60))
            .sign_frame(
                &EID,
                &Header {
                    node: 6,
                    counter: 4,
                    time: T,
                },
                &Body::Roster(a.issue_card(pubkey(60), 6, Role::Hub, EXPIRY)),
            )
            .unwrap();
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().signature, 2);
        // A learned card's expiry is clamped to the event's.
        let long = EventAuthority::new([9; 32], EID, START, EXPIRY + 50_000);
        let f = forge(6, 5, T, &Body::Roster(card(&long, 8, Role::Full)));
        assert_eq!(r.receive(&f, T).len(), 1);
        assert!(
            r.receive(&forge(8, 1, EXPIRY - 1, &imsi()), EXPIRY - 1)
                .len()
                == 1
        );
    }

    #[test]
    fn sender_applies_own_revocation() {
        let a = event();
        let mut org = member(&a, 5, Role::Organiser);
        org.add_card(card(&a, 6, Role::Full), START).unwrap();
        org.send(
            Body::Revocation {
                target: 6,
                event_sig: Some(a.revocation_sig(6)),
            },
            T,
        )
        .unwrap();
        assert!(org.is_revoked(6));
        assert!(!org.roster().any(|(n, _)| n == 6));
        assert!(org.receive(&forge(6, 1 << 20, T, &imsi()), T).is_empty());
        assert_eq!(org.rejected().revoked, 1);
        assert_eq!(org.last_send_revoked(), Some(6), "new");
        // Sent again (a re-broadcast): Ok, but not new.
        org.send(
            Body::Revocation {
                target: 6,
                event_sig: Some(a.revocation_sig(6)),
            },
            T + 1,
        )
        .unwrap();
        assert_eq!(org.last_send_revoked(), None);
        org.send(Body::CheckIn { hub_snr: 0 }, T + 2).unwrap();
        assert_eq!(org.last_send_revoked(), None);
        // revoke_self marks the sender itself, too.
        let mut n7 = member(&a, 7, Role::Full);
        n7.revoke_self(T).unwrap();
        assert!(n7.is_revoked(7));
        assert_eq!(n7.last_send_revoked(), Some(7));
    }

    #[test]
    fn self_revocation_and_event_revocation() {
        let a = event();
        let mut r = receiver(
            &a,
            &[(3, Role::Light), (5, Role::Full), (6, Role::Messenger)],
        );
        let mut n5 = member(&a, 5, Role::Full);
        let f = n5.revoke_self(T).unwrap();
        assert_eq!(r.receive(&f, T), vec![Inbound::Revoked { node: 5 }]);
        assert!(r.is_revoked(5));
        assert!(r.receive(&forge(5, 1 << 30, T, &imsi()), T).is_empty());
        assert_eq!(r.rejected().revoked, 1);

        let mut n3 = member(&a, 3, Role::Light);
        // 3 revoking 6 without an event signature: refused.
        let f = n3.send(
            Body::Revocation {
                target: 6,
                event_sig: None,
            },
            T,
        );
        assert_eq!(f, Err(SendError::NotAllowed));
        let f = forge(
            3,
            1,
            T,
            &Body::Revocation {
                target: 6,
                event_sig: None,
            },
        );
        assert!(r.receive(&f, T).is_empty());
        // An event signature for a different target does not count.
        let f = forge(
            3,
            2,
            T,
            &Body::Revocation {
                target: 6,
                event_sig: Some(a.revocation_sig(7)),
            },
        );
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().not_allowed, 2);
        assert!(!r.is_revoked(6));
        // The organiser's revocation of 6, relayed by node 3: accepted.
        let f = n3
            .send(
                Body::Revocation {
                    target: 6,
                    event_sig: Some(a.revocation_sig(6)),
                },
                T,
            )
            .unwrap();
        assert_eq!(r.receive(&f, T), vec![Inbound::Revoked { node: 6 }]);
        assert!(r.is_revoked(6));
        assert!(
            r.receive(&forge(6, 1, T, &Body::Status { phrase: 0 }), T)
                .is_empty()
        );
        assert_eq!(r.rejected().revoked, 2);

        // A revoked node's pending frames are dropped, and its card arriving
        // later does not un-revoke it.
        r.receive(&forge(10, 1, T, &imsi()), T);
        // (3's real send above moved its counter to 1000.)
        let f = forge(
            3,
            1 << 20,
            T,
            &Body::Revocation {
                target: 10,
                event_sig: Some(a.revocation_sig(10)),
            },
        );
        assert_eq!(r.receive(&f, T), vec![Inbound::Revoked { node: 10 }]);
        assert_eq!(r.add_card(card(&a, 10, Role::Full), T), Ok(vec![]));
        assert!(r.is_revoked(10));
        assert!(r.roster().all(|(n, _)| n != 10 && n != 5 && n != 6));
        assert!(r.receive(&forge(10, 2, T, &imsi()), T).is_empty());
        assert_eq!(r.rejected().revoked, 4);
    }

    #[test]
    fn counter_survives_restart() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        let mut n = member(&a, 2, Role::Full);
        let mut counters = vec![];
        for _ in 0..3 {
            let f = n.send(Body::Status { phrase: 0 }, START + 100).unwrap();
            counters.push(decode(&f).unwrap().header.counter);
            assert_eq!(r.receive(&f, START + 100).len(), 1);
        }
        assert_eq!(counters, vec![100, 101, 102]);
        // Rebooted a few seconds later: rebuilt from the same kit, no memory
        // of its counter. The clock has moved past the burst.
        let mut n = member(&a, 2, Role::Full);
        let f = n.send(Body::Status { phrase: 0 }, START + 105).unwrap();
        assert_eq!(decode(&f).unwrap().header.counter, 105);
        assert_eq!(r.receive(&f, START + 105).len(), 1);
        assert_eq!(*r.rejected(), Rejects::default());
        // Rebooted within the burst's seconds (documented): its first frames
        // reuse counters already seen and are dropped until it passes them.
        let mut n = member(&a, 2, Role::Full);
        let f = n.send(Body::Status { phrase: 0 }, START + 105).unwrap();
        assert!(r.receive(&f, START + 105).is_empty());
        assert_eq!(r.rejected().replay, 1);
        let f = n.send(Body::Status { phrase: 0 }, START + 105).unwrap();
        assert_eq!(r.receive(&f, START + 105).len(), 1);
        // A clock behind the event start does not underflow.
        let mut n = member(&a, 3, Role::Full);
        let f = n.send(Body::Status { phrase: 0 }, 0).unwrap();
        assert_eq!(decode(&f).unwrap().header.counter, 0);
    }

    #[test]
    fn replay_window_spans_64_seconds() {
        // M2: one counter per second, so time-based counters tolerate 63 s
        // of reordering (two frames heard via different paths).
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full)]);
        let mut n = member(&a, 2, Role::Full);
        let early = n.send(status(), T).unwrap();
        let late = n.send(status(), T + 63).unwrap();
        assert_eq!(r.receive(&late, T + 63).len(), 1);
        assert_eq!(r.receive(&early, T + 63).len(), 1, "63 s late still passes");
        let early = n.send(status(), T + 200).unwrap();
        let late = n.send(status(), T + 264).unwrap();
        assert_eq!(r.receive(&late, T + 264).len(), 1);
        assert!(r.receive(&early, T + 264).is_empty(), "64 s is outside");
        assert_eq!(r.rejected().replay, 1);
    }

    #[test]
    fn network_verdicts_rate_limited_per_kind() {
        // Spec 11.1: same message rules as other verdicts, one per kind per
        // node per 10 minutes, from Full and Light alike.
        let a = event();
        for role in [Role::Full, Role::Light] {
            let mut n = member(&a, 2, role);
            for k in [
                VerdictKind::ServiceLost,
                VerdictKind::Downgraded,
                VerdictKind::TowersGone,
            ] {
                assert!(n.send_verdict(k, Level::Low, None, T).unwrap().is_some());
                assert_eq!(n.send_verdict(k, Level::Low, None, T + 599), Ok(None));
                assert!(
                    n.send_verdict(k, Level::Low, None, T + 600)
                        .unwrap()
                        .is_some()
                );
            }
            // A different kind is not held back by the first.
            let mut n = member(&a, 3, role);
            assert!(
                n.send_verdict(VerdictKind::ServiceLost, Level::Low, None, T)
                    .unwrap()
                    .is_some()
            );
            assert!(
                n.send_verdict(VerdictKind::Downgraded, Level::Low, None, T + 1)
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn received_verdicts_rate_limited_per_sender_and_kind() {
        use crate::corroborate::{Audience, Corroborator};
        // The 50-tag probe (I1a): one Full node, 50 High verdicts with 50
        // tags inside ten minutes. One gets through; one group alert.
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full), (3, Role::Full)]);
        let mut c = Corroborator::new(1);
        let mut raised = 0;
        for i in 0..50u32 {
            let t = T + i * 10;
            let f = forge(
                2,
                i + 1,
                t,
                &verdict(VerdictKind::ImsiRequested, Some([i as u8; 8])),
            );
            for inb in r.receive(&f, t) {
                raised += c
                    .observe(&inb, t)
                    .iter()
                    .filter(|x| x.audience == Audience::Group && !x.withdrawn)
                    .count();
            }
        }
        assert_eq!(raised, 1);
        assert_eq!(
            *r.rejected(),
            Rejects {
                rate_limited: 49,
                ..Default::default()
            }
        );
        // The boundary is VERDICT_INTERVAL - 30 by the sender's clock.
        let k = VerdictKind::ImsiRequested;
        let limit = VERDICT_INTERVAL - 30;
        assert!(
            r.receive(
                &forge(2, 100, T + limit - 1, &verdict(k, None)),
                T + limit - 1
            )
            .is_empty()
        );
        assert_eq!(r.rejected().rate_limited, 50);
        // An older frame than the last accepted one is held back too.
        assert!(
            r.receive(&forge(2, 101, T - 5, &verdict(k, None)), T + limit)
                .is_empty()
        );
        assert_eq!(r.rejected().rate_limited, 51);
        assert_eq!(
            r.receive(&forge(2, 102, T + limit, &verdict(k, None)), T + limit)
                .len(),
            1
        );
        // Another kind, or another sender, is not held back.
        assert_eq!(
            r.receive(
                &forge(2, 103, T + limit, &verdict(VerdictKind::NullCipher, None)),
                T + limit
            )
            .len(),
            1
        );
        assert_eq!(
            r.receive(&forge(3, 1, T + limit, &verdict(k, None)), T + limit)
                .len(),
            1
        );
        // A rate-limited frame was still signed and new: its relayed copy is a
        // replay, not a second rate_limited.
        assert!(
            r.receive(&forge(2, 100, T + limit - 1, &verdict(k, None)), T + limit)
                .is_empty()
        );
        assert_eq!(r.rejected().rate_limited, 51);
        assert_eq!(r.rejected().replay, 1);
    }

    #[test]
    fn send_verdict_rate_limited_and_tag_stripped() {
        let a = event();
        let mut full = member(&a, 2, Role::Full);
        let k = VerdictKind::ImsiRequested;
        assert!(
            full.send_verdict(k, Level::High, None, T)
                .unwrap()
                .is_some()
        );
        assert_eq!(full.send_verdict(k, Level::High, None, T + 599), Ok(None));
        assert!(
            full.send_verdict(VerdictKind::NullCipher, Level::High, None, T + 1)
                .unwrap()
                .is_some()
        );
        assert!(
            full.send_verdict(k, Level::High, None, T + 600)
                .unwrap()
                .is_some()
        );

        let tag = Some([5u8; 8]);
        let f = full
            .send_verdict(VerdictKind::Test, Level::Low, tag, T)
            .unwrap()
            .unwrap();
        assert!(matches!(decode(&f).unwrap().body, Body::Verdict { tag: t, .. } if t == tag));
        let mut light = member(&a, 3, Role::Light);
        let f = light
            .send_verdict(VerdictKind::ImsiRequested, Level::Low, tag, T)
            .unwrap()
            .unwrap();
        assert!(matches!(
            decode(&f).unwrap().body,
            Body::Verdict { tag: None, .. }
        ));
        for role in [Role::Messenger, Role::Organiser, Role::Hub] {
            let mut n = member(&a, 4, role);
            assert_eq!(
                n.send_verdict(k, Level::High, None, T),
                Err(SendError::NotAllowed)
            );
        }
        // Expired event.
        assert_eq!(
            full.send_verdict(VerdictKind::Downgraded, Level::High, None, EXPIRY),
            Err(SendError::Expired)
        );
    }

    #[test]
    fn network_verdicts_never_tagged() {
        let a = event();
        let tag = Some([5u8; 8]);
        for role in [Role::Full, Role::Light] {
            let mut n = member(&a, 2, role);
            for k in [
                VerdictKind::ServiceLost,
                VerdictKind::Downgraded,
                VerdictKind::TowersGone,
            ] {
                let f = n.send_verdict(k, Level::Low, tag, T).unwrap().unwrap();
                assert!(
                    matches!(decode(&f).unwrap().body, Body::Verdict { tag: None, .. }),
                    "{role:?} {k:?}"
                );
            }
            // Plain send refuses what a receiver would refuse.
            let b = verdict(VerdictKind::ServiceLost, tag);
            assert_eq!(n.send(b, T), Err(SendError::NotAllowed));
        }
        // Receive: a Full node's tagged network verdict is not_allowed.
        let mut r = receiver(&a, &[(2, Role::Full)]);
        let f = forge(2, 1, T, &verdict(VerdictKind::TowersGone, tag));
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(
            *r.rejected(),
            Rejects {
                not_allowed: 1,
                ..Default::default()
            }
        );
        // Untagged, the same kind passes.
        let f = forge(2, 2, T, &verdict(VerdictKind::TowersGone, None));
        assert_eq!(r.receive(&f, T).len(), 1);
    }

    #[test]
    fn revoked_self_cannot_send() {
        let a = event();
        let mut n = member(&a, 2, Role::Full);
        let f = n.revoke_self(T).unwrap();
        assert!(matches!(
            decode(&f).unwrap().body,
            Body::Revocation {
                target: 2,
                event_sig: None
            }
        ));
        assert_eq!(
            n.send(Body::Status { phrase: 0 }, T),
            Err(SendError::Revoked)
        );
        assert_eq!(
            n.send_verdict(VerdictKind::ImsiRequested, Level::High, None, T),
            Err(SendError::Revoked)
        );
        assert_eq!(n.revoke_self(T), Err(SendError::Revoked));
    }

    #[test]
    fn out_of_table_numbers_rejected() {
        let a = event();
        let mut r = receiver(&a, &[(2, Role::Full), (5, Role::Organiser)]);
        let bad = [
            (2, Body::Status { phrase: 3 }),
            (5, Body::Directive(Directive::Phrase(3))),
            (5, Body::Directive(Directive::Point(2))),
        ];
        for (i, (n, b)) in bad.iter().enumerate() {
            assert!(r.receive(&forge(*n, 10 + i as u32, T, b), T).is_empty());
        }
        assert_eq!(
            *r.rejected(),
            Rejects {
                not_allowed: 3,
                ..Default::default()
            }
        );
        let good = [
            (2, Body::Status { phrase: 2 }),
            (5, Body::Directive(Directive::Phrase(2))),
            (5, Body::Directive(Directive::Point(1))),
        ];
        for (i, (n, b)) in good.iter().enumerate() {
            assert_eq!(r.receive(&forge(*n, 20 + i as u32, T, b), T).len(), 1);
        }
        // The sender refuses them too.
        let mut org = member(&a, 5, Role::Organiser);
        assert_eq!(
            org.send(Body::Directive(Directive::Point(2)), T),
            Err(SendError::NotAllowed)
        );
    }

    #[test]
    fn tower_flood_full_only() {
        let a = event();
        let mut light = member(&a, 3, Role::Light);
        assert_eq!(
            light.send_verdict(VerdictKind::TowerFlood, Level::High, None, T),
            Err(SendError::NotAllowed)
        );
        let mut r = receiver(&a, &[(3, Role::Light)]);
        let f = forge(3, 1, T, &verdict(VerdictKind::TowerFlood, None));
        assert!(r.receive(&f, T).is_empty());
        assert_eq!(r.rejected().not_allowed, 1);
        let mut full = member(&a, 2, Role::Full);
        assert!(
            full.send_verdict(VerdictKind::TowerFlood, Level::High, None, T)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn hostile_input_never_panics() {
        let a = event();
        let mut s: u64 = 0x5eed;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let valid = [
            forge(2, 5, T, &imsi()),
            forge(6, 1, T, &Body::Roster(card(&a, 6, Role::Hub))),
            forge(6, 2, T, &Body::Roster(card(&a, 9, Role::Full))),
            forge(
                3,
                1,
                T,
                &Body::Revocation {
                    target: 4,
                    event_sig: Some(a.revocation_sig(4)),
                },
            ),
            forge(7, u32::MAX, u32::MAX, &Body::Status { phrase: 255 }),
            forge(2, 0, 0, &Body::Directive(Directive::Point(255))),
        ];
        let nows = [0, START - 1, START, T, EXPIRY - 1, EXPIRY, u32::MAX];
        let mut r = receiver(&a, &[(2, Role::Full), (3, Role::Light)]);
        for i in 0..500usize {
            let now = nows[i % nows.len()];
            let n = (next() % 201) as usize;
            let rnd: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            r.receive(&rnd, now);
            let v = &valid[i % valid.len()];
            r.receive(v, now);
            let cut = (next() as usize) % (v.len() + 1);
            r.receive(&v[..cut], now);
            let mut flipped = v.clone();
            let bit = (next() as usize) % (flipped.len() * 8);
            flipped[bit / 8] ^= 1 << (bit % 8);
            r.receive(&flipped, now);
        }
        // Sender side at extreme clocks.
        let mut n = member(&a, 2, Role::Full);
        let _ = n.send(Body::Status { phrase: 0 }, 0);
        let _ = n.send(Body::Status { phrase: 0 }, u32::MAX);
        let _ = n.send_verdict(VerdictKind::ImsiRequested, Level::High, None, 0);
        let _ = n.send_verdict(VerdictKind::ImsiRequested, Level::High, None, u32::MAX);
    }
}
