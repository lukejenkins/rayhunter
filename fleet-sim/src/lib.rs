//! fleet-sim: drives real `fleet-core` code over a virtual radio. Sim-only,
//! never shipped to devices.
//!
//! Every unit is a `Node` + `Corroborator` + `RelayState`; the hub adds a
//! `RelayPlanner`. Time is a virtual clock that only `step` (and
//! `set_clock`) moves: there is no sleeping, no wall clock and no thread, and
//! the only randomness is a xorshift seeded by `World::new`.
//!
//! Transmissions are delivered breadth-first within the same second: a frame
//! and every relay of it land before the clock moves on.
//!
//! The hub (controller ruling R2) is provisioned with every member's card via
//! `Node::add_card`, whose output (`CardLearned` for each new card) goes
//! through the same glue as received Inbounds, so the planner learns them. It
//! broadcasts its own card and then every card as Roster frames at its first
//! tick and then after a random `schedule::roster_gap` (5-15 min); members
//! learn the roster from those frames, so roster traffic counts in airtime.
//! Each member checks in at a random time in its first interval and then
//! after a random `schedule::checkin_gap` (1/2 to 1 interval). Both draw on
//! the World's xorshift, standing in for the OS RNG a real device uses.

pub mod radio;

use fleet_core::corroborate::{Alert, Corroborator};
use fleet_core::kit::Kit;
use fleet_core::node::{Inbound, Node, SendError};
use fleet_core::relay::{RelayConfig, RelayPlanner, RelayState, checkin_body};
use fleet_core::schedule::{checkin_gap, roster_gap};
use fleet_core::transport::Transport;
use fleet_core::wire::{Body, Card, Level, Role, VerdictKind, decode};
use radio::{HOP_LIMIT, LINK_MIN_SNR_DB, SimTransport, Tx, XorShift, frame_hash, snr_db};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The longest gap between two roster broadcasts (they are random in
/// `[ROSTER_MIN_SECS, ROSTER_MAX_SECS]`).
pub use fleet_core::consts::{ROSTER_MAX_SECS, ROSTER_MIN_SECS};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Airtime {
    pub transmissions: u64,
    pub bytes: u64,
}

struct HubState {
    planner: RelayPlanner,
    own: Card,
    cards: Vec<Card>,
    next_roster: u32,
}

struct Unit {
    node: Node,
    corr: Corroborator,
    relay: RelayState,
    hub: Option<HubState>,
    pos: (f32, f32),
    on: bool,
    /// The radio's relay flag, set only through `Transport::set_relay`.
    radio_relay: bool,
    /// Forced on by the sim (the all-relay baseline).
    forced: bool,
    ever_relayed: bool,
    /// Times `RelayState::tick` switched the radio's relay off (an order
    /// lapsed), even if a renewal switched it back on the same second.
    relay_lapses: u32,
    checkin_secs: u32,
    next_checkin: u32,
    /// SNR of the last transmission heard directly from the hub's radio.
    last_hub_snr: Option<f32>,
    alerts: Vec<Alert>,
    inbox: Vec<Inbound>,
    /// Hashes of frames this unit has sent or rebroadcast.
    relayed: BTreeSet<u64>,
}

impl Unit {
    fn relay_mode(&self) -> bool {
        self.hub.is_some() || self.forced || self.radio_relay
    }

    fn hub_node(&self) -> Option<u16> {
        self.node
            .roster()
            .find(|(_, r)| *r == Role::Hub)
            .map(|(n, _)| n)
    }
}

pub struct World {
    now: u32,
    rng: XorShift,
    loss: f32,
    units: Vec<Unit>,
    queue: VecDeque<Tx>,
    log: Vec<Vec<u8>>,
    airtime: Airtime,
    /// (receiver, frame hash) -> transmitters of each copy heard.
    deliveries: BTreeMap<(usize, u64), Vec<Option<usize>>>,
}

impl World {
    pub fn new(seed: u64) -> World {
        World {
            now: 0,
            rng: XorShift::new(seed),
            loss: 0.0,
            units: Vec::new(),
            queue: VecDeque::new(),
            log: Vec::new(),
            airtime: Airtime::default(),
            deliveries: BTreeMap::new(),
        }
    }

    /// Set the virtual clock (forward only). Use before adding units.
    pub fn set_clock(&mut self, t: u32) {
        assert!(t >= self.now, "the clock only moves forward");
        self.now = t;
    }

    pub fn now(&self) -> u32 {
        self.now
    }

    /// The world's deterministic randomness, for scenario inputs.
    pub fn rand_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Deterministic per-delivery loss probability (default 0).
    pub fn set_loss(&mut self, p: f32) {
        self.loss = p.clamp(0.0, 1.0);
    }

    fn push(&mut self, kit: Kit, pos: (f32, f32), hub: Option<HubState>) -> usize {
        let checkin_secs = (kit.checkin_minutes as u32).max(1) * 60;
        let first = self.now + 1 + (self.rng.next_u64() % checkin_secs as u64) as u32;
        let node = Node::new(kit);
        let is_hub = hub.is_some();
        self.units.push(Unit {
            corr: Corroborator::new(node.me()),
            node,
            relay: RelayState::new(),
            hub,
            pos,
            on: true,
            radio_relay: is_hub,
            forced: false,
            ever_relayed: false,
            relay_lapses: 0,
            checkin_secs,
            next_checkin: first,
            last_hub_snr: None,
            alerts: Vec::new(),
            inbox: Vec::new(),
            relayed: BTreeSet::new(),
        });
        self.units.len() - 1
    }

    /// A member. `relay` forces its radio into relay mode for the whole run.
    pub fn add(&mut self, kit: Kit, pos: (f32, f32), relay: bool) -> usize {
        assert_ne!(kit.card.role, Role::Hub, "use add_hub");
        let i = self.push(kit, pos, None);
        self.units[i].forced = relay;
        i
    }

    pub fn add_organiser(&mut self, kit: Kit, pos: (f32, f32), relay: bool) -> usize {
        assert_eq!(kit.card.role, Role::Organiser);
        self.add(kit, pos, relay)
    }

    /// The hub, provisioned with every member's card (ruling R2).
    pub fn add_hub(&mut self, kit: Kit, pos: (f32, f32), cards: Vec<Card>) -> usize {
        assert_eq!(kit.card.role, Role::Hub);
        let checkin_secs = (kit.checkin_minutes as u32).max(1) * 60;
        let planner = RelayPlanner::new(RelayConfig::new(checkin_secs));
        let own = kit.card.clone();
        let hub = HubState {
            planner,
            own,
            cards: cards.clone(),
            next_roster: self.now,
        };
        let i = self.push(kit, pos, Some(hub));
        // add_card's output (CardLearned, then any released frames) goes
        // through the glue like any Inbound, so the planner learns each card.
        for c in cards {
            let learned = self.units[i]
                .node
                .add_card(c, self.now)
                .expect("a member card from this event");
            self.process(i, learned);
        }
        i
    }

    /// Switch a unit off: it neither sends nor hears anything again.
    pub fn remove(&mut self, idx: usize) {
        self.units[idx].on = false;
    }

    pub fn move_to(&mut self, idx: usize, pos: (f32, f32)) {
        self.units[idx].pos = pos;
    }

    pub fn pos(&self, idx: usize) -> (f32, f32) {
        self.units[idx].pos
    }

    pub fn force_relay(&mut self, idx: usize, on: bool) {
        self.units[idx].forced = on;
    }

    /// Advance the clock one second at a time: relay ticks, roster
    /// broadcasts, check-ins, alert expiry, then the hub's planner whenever
    /// `RelayPlanner::due` says so.
    pub fn step(&mut self, secs: u32) {
        for _ in 0..secs {
            self.now += 1;
            let now = self.now;
            for j in 0..self.units.len() {
                if !self.units[j].on {
                    continue;
                }
                let mut out = Vec::new();
                let u = &mut self.units[j];
                let mut t = SimTransport {
                    out: &mut out,
                    relay: &mut u.radio_relay,
                };
                let was = *t.relay;
                let _ = u.relay.tick(now, &mut t);
                if was && !*t.relay {
                    u.relay_lapses += 1;
                }
                if let Some(h) = &mut u.hub {
                    if now >= h.next_roster {
                        h.next_roster = now + roster_gap(self.rng.next_u64() as u32);
                        let all = core::iter::once(&h.own).chain(h.cards.iter());
                        for c in all {
                            if u.node.is_revoked(c.node) {
                                continue;
                            }
                            if let Ok(f) = u.node.send(Body::Roster(c.clone()), now) {
                                t.send(&f).expect("frame within MAX_FRAME");
                            }
                        }
                    }
                } else if now >= u.next_checkin {
                    u.next_checkin = now + checkin_gap(u.checkin_secs, self.rng.next_u64() as u32);
                    if let Ok(f) = u.node.send(checkin_body(u.last_hub_snr), now) {
                        t.send(&f).expect("frame within MAX_FRAME");
                    }
                }
                let expired = u.corr.expire(now);
                u.alerts.extend(expired);
                self.emit(j, out);
                self.flush();
            }
            for j in 0..self.units.len() {
                let u = &mut self.units[j];
                let Some(h) = &mut u.hub else { continue };
                if !u.on || !h.planner.due(now) {
                    continue;
                }
                let mut out = Vec::new();
                let mut t = SimTransport {
                    out: &mut out,
                    relay: &mut u.radio_relay,
                };
                for (target, minutes) in h.planner.plan(now) {
                    if let Ok(f) = u.node.send(Body::RelayOrder { target, minutes }, now) {
                        t.send(&f).expect("frame within MAX_FRAME");
                    }
                }
                self.emit(j, out);
                self.flush();
            }
        }
    }

    /// Send `body` from unit `idx` now. Returns the frame as transmitted.
    ///
    /// A Revocation is applied by the sending `Node` itself; when it was new
    /// (`Node::last_send_revoked`), the glue feeds `Inbound::Revoked` to the
    /// sender's Corroborator, planner and inbox, since the relayed echo is
    /// dropped as its own frame.
    pub fn send_from(&mut self, idx: usize, body: Body) -> Result<Vec<u8>, SendError> {
        let f = self.units[idx].node.send(body, self.now)?;
        if let Some(node) = self.units[idx].node.last_send_revoked() {
            self.process(idx, vec![Inbound::Revoked { node }]);
        }
        self.transmit(idx, &f);
        Ok(f)
    }

    /// The unit revokes itself (`Node::revoke_self`) and transmits it.
    pub fn revoke_self(&mut self, idx: usize) -> Result<Vec<u8>, SendError> {
        let f = self.units[idx].node.revoke_self(self.now)?;
        if let Some(node) = self.units[idx].node.last_send_revoked() {
            self.process(idx, vec![Inbound::Revoked { node }]);
        }
        self.transmit(idx, &f);
        Ok(f)
    }

    /// The unit's own verdict: rate-limited by `Node::send_verdict`
    /// (`Ok(None)`), raised on its own Corroborator, and transmitted.
    pub fn verdict_from(
        &mut self,
        idx: usize,
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
    ) -> Result<Option<Vec<u8>>, SendError> {
        let now = self.now;
        let u = &mut self.units[idx];
        let Some(f) = u.node.send_verdict(kind, level, tag, now)? else {
            return Ok(None);
        };
        // Count exactly what went on the air (send_verdict strips a Light
        // unit's tag), rather than re-deriving the rule here.
        let tag = match decode(&f).map(|fr| fr.body) {
            Ok(Body::Verdict { tag, .. }) => tag,
            _ => unreachable!("send_verdict built a Verdict frame"),
        };
        let role = u.node.role();
        let a = u.corr.observe_own(kind, level, tag, role, now);
        u.alerts.extend(a);
        self.transmit(idx, &f);
        Ok(Some(f))
    }

    /// Raw bytes from a rogue transmitter (no card, no node number).
    pub fn inject_raw(&mut self, from_pos: (f32, f32), bytes: Vec<u8>) {
        self.queue.push_back(Tx {
            from: None,
            tx_node: None,
            pos: from_pos,
            bytes,
            hops_left: HOP_LIMIT,
        });
        self.flush();
    }

    fn transmit(&mut self, idx: usize, frame: &[u8]) {
        let mut out = Vec::new();
        let u = &mut self.units[idx];
        SimTransport {
            out: &mut out,
            relay: &mut u.radio_relay,
        }
        .send(frame)
        .expect("frame within MAX_FRAME");
        self.emit(idx, out);
        self.flush();
    }

    /// Queue frames a unit originated. It never rebroadcasts its own frame.
    fn emit(&mut self, j: usize, frames: Vec<Vec<u8>>) {
        let u = &mut self.units[j];
        if !u.on {
            return;
        }
        for bytes in frames {
            u.relayed.insert(frame_hash(&bytes));
            self.queue.push_back(Tx {
                from: Some(j),
                tx_node: Some(u.node.me()),
                pos: u.pos,
                bytes,
                hops_left: HOP_LIMIT,
            });
        }
    }

    fn flush(&mut self) {
        while let Some(tx) = self.queue.pop_front() {
            self.airtime.transmissions += 1;
            self.airtime.bytes += tx.bytes.len() as u64;
            self.log.push(tx.bytes.clone());
            let h = frame_hash(&tx.bytes);
            for j in 0..self.units.len() {
                if tx.from == Some(j) || !self.units[j].on {
                    continue;
                }
                let snr = snr_db(tx.pos, self.units[j].pos);
                if snr < LINK_MIN_SNR_DB {
                    continue;
                }
                if self.loss > 0.0 && self.rng.next_f32() < self.loss {
                    continue;
                }
                self.deliver(j, &tx, snr, h);
            }
        }
    }

    fn deliver(&mut self, j: usize, tx: &Tx, snr: f32, h: u64) {
        let now = self.now;
        self.deliveries.entry((j, h)).or_default().push(tx.from);
        let inbs = self.units[j].node.receive(&tx.bytes, now);
        self.process(j, inbs);
        let u = &mut self.units[j];
        if tx.tx_node.is_some() && tx.tx_node == u.hub_node() {
            u.last_hub_snr = Some(snr);
        }
        if radio::rebroadcast(u.relay_mode(), u.relayed.contains(&h), tx.hops_left) {
            u.relayed.insert(h);
            u.ever_relayed = true;
            self.queue.push_back(Tx {
                from: Some(j),
                tx_node: Some(u.node.me()),
                pos: u.pos,
                bytes: tx.bytes.clone(),
                hops_left: tx.hops_left - 1,
            });
        }
    }

    /// The glue: every Inbound goes to the inbox, the Corroborator, the
    /// RelayState and (on the hub) the planner. The unit's own revocation
    /// also calls `RelayState::stop`.
    fn process(&mut self, j: usize, inbs: Vec<Inbound>) {
        let now = self.now;
        let u = &mut self.units[j];
        let me = u.node.me();
        for inb in inbs {
            let mut out = Vec::new();
            let mut t = SimTransport {
                out: &mut out,
                relay: &mut u.radio_relay,
            };
            let _ = u.relay.on_order(me, &inb, now, &mut t);
            // A revoked unit (by itself or by an organiser) stops relaying.
            if inb == (Inbound::Revoked { node: me }) {
                let _ = u.relay.stop(&mut t);
            }
            let a = u.corr.observe(&inb, now);
            u.alerts.extend(a);
            if let Some(h) = &mut u.hub {
                h.planner.observe(&inb, now);
            }
            u.inbox.push(inb);
            debug_assert!(out.is_empty(), "on_order never sends");
        }
    }

    pub fn alerts(&self, idx: usize) -> &[Alert] {
        &self.units[idx].alerts
    }

    pub fn inbox(&self, idx: usize) -> &[Inbound] {
        &self.units[idx].inbox
    }

    pub fn node(&self, idx: usize) -> &Node {
        &self.units[idx].node
    }

    /// The unit's radio is in relay mode (always true for the hub).
    pub fn relaying(&self, idx: usize) -> bool {
        self.units[idx].relay_mode()
    }

    /// SNR of the last transmission the unit heard directly from the hub's
    /// radio: what its next check-in will carry.
    pub fn hub_snr(&self, idx: usize) -> Option<f32> {
        self.units[idx].last_hub_snr
    }

    /// Times the unit's relay order lapsed (`RelayState::tick` switched the
    /// radio off), counted even when a renewal follows within the second.
    pub fn relay_lapses(&self, idx: usize) -> u32 {
        self.units[idx].relay_lapses
    }

    /// Has the unit rebroadcast at least one frame?
    pub fn ever_relayed(&self, idx: usize) -> bool {
        self.units[idx].ever_relayed
    }

    /// When the hub at `idx` sends its next roster (`None` for a member).
    pub fn next_roster(&self, idx: usize) -> Option<u32> {
        self.units[idx].hub.as_ref().map(|h| h.next_roster)
    }

    pub fn is_hub(&self, idx: usize) -> bool {
        self.units[idx].hub.is_some()
    }

    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Transmitters of every copy of `frame` that unit `idx` heard
    /// (`None` = a rogue).
    pub fn copies(&self, idx: usize, frame: &[u8]) -> Vec<Option<usize>> {
        self.deliveries
            .get(&(idx, frame_hash(frame)))
            .cloned()
            .unwrap_or_default()
    }

    /// Every transmission, in order, including relays and injected frames.
    pub fn air_log(&self) -> &[Vec<u8>] {
        &self.log
    }

    pub fn airtime(&self) -> Airtime {
        self.airtime
    }
}
