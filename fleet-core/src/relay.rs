//! Quiet mesh: check-ins and on-demand relays (spec 12). The hub plans relays
//! with `RelayPlanner`; every member obeys orders with `RelayState`.

use crate::consts::*;
use crate::node::Inbound;
use crate::transport::{Transport, TxError};
use crate::wire::{Body, Role};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayConfig {
    pub weak_snr_db: i8,
    pub good_snr_db: i8,
    pub checkin_secs: u32,
}

impl RelayConfig {
    pub fn new(checkin_secs: u32) -> Self {
        RelayConfig {
            weak_snr_db: WEAK_SNR_DB,
            good_snr_db: GOOD_SNR_DB,
            checkin_secs,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig::new(15 * 60)
    }
}

/// Round half away from zero, clamp to -127..=127; NaN and None are unknown.
pub fn checkin_body(last_hub_snr: Option<f32>) -> Body {
    let hub_snr = match last_hub_snr {
        Some(x) if !x.is_nan() => {
            let x = x.clamp(-127.0, 127.0);
            let r = if x < 0.0 { x - 0.5 } else { x + 0.5 };
            (r as i32).clamp(-127, 127) as i8
        }
        _ => SNR_UNKNOWN,
    };
    Body::CheckIn { hub_snr }
}

pub struct RelayPlanner {
    cfg: RelayConfig,
    roles: BTreeMap<u16, Role>,
    revoked: BTreeSet<u16>,
    /// Tracked members (known, non-Hub, not revoked) -> hub time first seen.
    first_seen: BTreeMap<u16, u32>,
    /// node -> (hub receive time of last check-in, hub_snr). The frame's own
    /// time is never used: a future-dated frame must not look fresh forever.
    last: BTreeMap<u16, (u32, i8)>,
    /// target -> (relay_until, issued_at) of the order we issued
    orders: BTreeMap<u16, (u32, u32)>,
    /// Hub time of the last plan() call.
    last_plan: Option<u32>,
    /// A CheckIn was observed since the last plan().
    checkin_since_plan: bool,
}

impl RelayPlanner {
    pub fn new(cfg: RelayConfig) -> Self {
        RelayPlanner {
            cfg,
            roles: BTreeMap::new(),
            revoked: BTreeSet::new(),
            first_seen: BTreeMap::new(),
            last: BTreeMap::new(),
            orders: BTreeMap::new(),
            last_plan: None,
            checkin_since_plan: false,
        }
    }

    pub fn observe(&mut self, ev: &Inbound, now: u32) {
        match ev {
            Inbound::CardLearned { node, role } => {
                self.roles.insert(*node, *role);
                if *role == Role::Hub {
                    self.first_seen.remove(node);
                    self.last.remove(node);
                } else if !self.revoked.contains(node) {
                    self.first_seen.entry(*node).or_insert(now);
                }
            }
            Inbound::Revoked { node } => {
                self.revoked.insert(*node);
                self.first_seen.remove(node);
                self.last.remove(node);
                self.orders.remove(node);
            }
            Inbound::CheckIn { node, hub_snr, .. } => {
                self.checkin_since_plan = true;
                if self.first_seen.contains_key(node) {
                    self.last.insert(*node, (now, *hub_snr));
                }
            }
            _ => {}
        }
    }

    /// Time the hub last heard from a tracked member (or first saw its card).
    fn heard(&self, node: u16) -> Option<u32> {
        self.last
            .get(&node)
            .map(|(t, _)| *t)
            .or_else(|| self.first_seen.get(&node).copied())
    }

    fn silence(&self, node: u16, now: u32) -> u32 {
        self.heard(node).map_or(0, |t| now.saturating_sub(t))
    }

    fn is_weak(&self, node: u16, now: u32) -> bool {
        let snr_weak = self
            .last
            .get(&node)
            .is_some_and(|(_, s)| *s == SNR_UNKNOWN || *s < self.cfg.weak_snr_db);
        snr_weak
            || self.silence(node, now)
                > (MISSED_CHECKINS as u32).saturating_mul(self.cfg.checkin_secs)
    }

    fn gave_up(&self, node: u16, now: u32) -> bool {
        self.silence(node, now) > GIVE_UP_CHECKINS.saturating_mul(self.cfg.checkin_secs)
    }

    /// Order length: `max(RELAY_MINUTES, 2 * checkin_minutes)`, capped at
    /// 60, so an order planned once per interval is renewed before it lapses.
    pub fn order_minutes(&self) -> u8 {
        let checkin_minutes = self.cfg.checkin_secs.div_ceil(60);
        checkin_minutes
            .saturating_mul(2)
            .max(RELAY_MINUTES as u32)
            .min(60) as u8
    }

    /// True if a CheckIn was observed since the last `plan()`, or a check-in
    /// interval has passed since it (or `plan()` was never called).
    pub fn due(&self, now: u32) -> bool {
        self.checkin_since_plan
            || self
                .last_plan
                .is_none_or(|t| now.saturating_sub(t) >= self.cfg.checkin_secs)
    }

    fn active(&self, node: u16, now: u32) -> bool {
        self.orders.get(&node).is_some_and(|(u, _)| *u > now)
    }

    /// Orders to send now, as `(target, minutes)`. Call whenever `due()` is
    /// true; at least once per check-in interval.
    pub fn plan(&mut self, now: u32) -> Vec<(u16, u8)> {
        self.last_plan = Some(now);
        self.checkin_since_plan = false;
        let minutes = self.order_minutes();
        let weak: Vec<u16> = self
            .first_seen
            .keys()
            .copied()
            .filter(|n| self.is_weak(*n, now) && !self.gave_up(*n, now))
            .collect();
        let mut issued: BTreeSet<u16> = BTreeSet::new();
        let mut out = Vec::new();
        for w in weak {
            let mut cands: Vec<(u16, i8)> = self
                .last
                .iter()
                .filter(|(n, (t, s))| {
                    **n != w
                        && *s != SNR_UNKNOWN
                        && *s >= self.cfg.good_snr_db
                        && now.saturating_sub(*t) <= self.cfg.checkin_secs
                })
                .map(|(n, (_, s))| (*n, *s))
                .collect();
            cands.sort_by(|a, b| {
                self.active(b.0, now)
                    .cmp(&self.active(a.0, now))
                    .then(b.1.cmp(&a.1))
                    .then(a.0.cmp(&b.0))
            });
            // take(RELAYS_MAX) counts still-active relays too, so a covered
            // weak member never ends up with more than RELAYS_MAX orders.
            for (c, _) in cands.into_iter().take(RELAYS_MAX) {
                if issued.contains(&c) {
                    continue;
                }
                // Renew in the order's last interval, but never an order
                // issued less than an interval ago (no immediate re-renewal).
                let iv = self.cfg.checkin_secs;
                let renew = match self.orders.get(&c) {
                    Some((u, at)) if *u > now => {
                        u.saturating_sub(now) <= iv && now.saturating_sub(*at) >= iv
                    }
                    _ => true,
                };
                if renew {
                    issued.insert(c);
                    self.orders
                        .insert(c, (now.saturating_add(minutes as u32 * 60), now));
                    out.push((c, minutes));
                }
            }
        }
        out
    }
}

pub struct RelayState {
    relay_until: u32,
    on: bool,
    /// Set by `stop`: this unit relays no more (it is revoked).
    stopped: bool,
}

impl Default for RelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayState {
    pub fn new() -> Self {
        RelayState {
            relay_until: 0,
            on: false,
            stopped: false,
        }
    }

    pub fn on_order(
        &mut self,
        me: u16,
        ev: &Inbound,
        now: u32,
        t: &mut dyn Transport,
    ) -> Result<(), TxError> {
        let Inbound::RelayOrder {
            target,
            minutes,
            time,
        } = ev
        else {
            return Ok(());
        };
        if self.stopped || *target != me || !(1..=60).contains(minutes) {
            return Ok(());
        }
        let until = time.saturating_add(*minutes as u32 * 60);
        // I2: an order already lapsed by `now` is ignored.
        if until <= now {
            return Ok(());
        }
        if !self.on {
            t.set_relay(true)?;
            self.on = true;
            self.relay_until = until;
        } else if until > self.relay_until {
            self.relay_until = until;
        }
        Ok(())
    }

    /// Stop relaying for good (M6): call when this unit is revoked. Later
    /// orders are ignored; a failed switch-off is retried by `tick`.
    pub fn stop(&mut self, t: &mut dyn Transport) -> Result<(), TxError> {
        self.stopped = true;
        if self.on {
            t.set_relay(false)?;
            self.on = false;
        }
        Ok(())
    }

    pub fn tick(&mut self, now: u32, t: &mut dyn Transport) -> Result<(), TxError> {
        if self.on && (self.stopped || now >= self.relay_until) {
            t.set_relay(false)?;
            self.on = false;
        }
        Ok(())
    }

    pub fn relaying(&self, now: u32) -> bool {
        self.on && !self.stopped && now < self.relay_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::check_len;

    const IV: u32 = 300;

    #[derive(Default)]
    struct Fake {
        calls: Vec<bool>,
        sent: Vec<usize>,
        fail_off: bool,
    }
    impl Transport for Fake {
        fn send(&mut self, frame: &[u8]) -> Result<(), TxError> {
            check_len(frame)?;
            self.sent.push(frame.len());
            Ok(())
        }
        fn set_relay(&mut self, on: bool) -> Result<(), TxError> {
            if !on && self.fail_off {
                return Err(TxError::Busy);
            }
            self.calls.push(on);
            Ok(())
        }
    }

    fn planner(members: &[(u16, Role)]) -> RelayPlanner {
        let mut p = RelayPlanner::new(RelayConfig::new(IV));
        for (n, r) in members {
            p.observe(&Inbound::CardLearned { node: *n, role: *r }, 0);
        }
        p
    }
    fn checkin(p: &mut RelayPlanner, node: u16, snr: i8, time: u32) {
        p.observe(
            &Inbound::CheckIn {
                node,
                hub_snr: snr,
                time,
            },
            time,
        );
    }
    fn order(target: u16, minutes: u8, time: u32) -> Inbound {
        Inbound::RelayOrder {
            target,
            minutes,
            time,
        }
    }

    #[test]
    fn weak_by_snr_gets_relays() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full), (3, Role::Full)]);
        checkin(&mut p, 1, -15, 1000);
        checkin(&mut p, 2, -3, 1000);
        checkin(&mut p, 3, -4, 1000);
        assert_eq!(p.plan(1000), vec![(2, 15), (3, 15)]);
    }

    #[test]
    fn weak_by_missed_checkins() {
        let mut p = planner(&[(4, Role::Light), (2, Role::Full)]);
        checkin(&mut p, 4, -3, 1000);
        let now = 1000 + 2 * IV + 1;
        checkin(&mut p, 2, -3, now);
        assert_eq!(p.plan(now), vec![(2, 15)]);
    }

    #[test]
    fn unknown_snr_is_weak() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        checkin(&mut p, 1, SNR_UNKNOWN, 1000);
        checkin(&mut p, 2, -3, 1000);
        assert_eq!(p.plan(1000), vec![(2, 15)]);
    }

    #[test]
    fn no_weak_no_orders() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        checkin(&mut p, 1, -3, 1000);
        checkin(&mut p, 2, -8, 1000);
        assert!(p.plan(1000).is_empty());
    }

    /// Planner with weak member 1 and good member 2 at interval `iv`.
    fn weak_and_good(iv: u32) -> RelayPlanner {
        let mut p = RelayPlanner::new(RelayConfig::new(iv));
        for n in [1u16, 2] {
            p.observe(
                &Inbound::CardLearned {
                    node: n,
                    role: Role::Full,
                },
                0,
            );
        }
        p
    }

    #[test]
    fn order_length_covers_two_intervals() {
        assert_eq!(weak_and_good(60).order_minutes(), RELAY_MINUTES);
        assert_eq!(weak_and_good(900).order_minutes(), 30);
        assert_eq!(weak_and_good(25 * 60).order_minutes(), 50);
        assert_eq!(weak_and_good(45 * 60).order_minutes(), 60, "capped");
        assert_eq!(weak_and_good(61).order_minutes(), RELAY_MINUTES);
    }

    #[test]
    fn once_per_interval_planning_never_lapses() {
        // 15-minute interval, plan() only once per interval, member 1 weak
        // throughout: the relay driven by the issued orders never drops.
        let iv = 900;
        let mut p = weak_and_good(iv);
        let mut st = RelayState::new();
        let mut fake = Fake::default();
        let t = 1000;
        let mut issued = 0;
        for now in t..=t + 3 * iv + 60 {
            // The member's own tick runs first: an order from the hub arrives
            // after the radio delay, never ahead of the expiry it renews.
            st.tick(now, &mut fake).unwrap();
            if (now - t) % iv == 0 {
                checkin(&mut p, 1, -15, now);
                checkin(&mut p, 2, -3, now);
                for (target, minutes) in p.plan(now) {
                    issued += 1;
                    st.on_order(2, &order(target, minutes, now), now, &mut fake)
                        .unwrap();
                }
            }
            assert!(st.relaying(now), "relay lapsed at +{}", now - t);
        }
        assert_eq!(issued, 4, "issue + one renewal per interval");
        assert_eq!(fake.calls, vec![true]);
    }

    #[test]
    fn immediate_replan_never_renews() {
        for iv in [60, 300, 900, 3600] {
            let mut p = weak_and_good(iv);
            let t = 1000;
            checkin(&mut p, 1, -15, t);
            checkin(&mut p, 2, -3, t);
            assert_eq!(p.plan(t).len(), 1, "iv {iv}");
            assert!(p.plan(t).is_empty(), "iv {iv}");
            assert!(p.plan(t + 1).is_empty(), "iv {iv}");
        }
    }

    #[test]
    fn one_minute_interval_renews_in_last_minute() {
        let iv = 60;
        let mut p = weak_and_good(iv);
        let t = 1000;
        let mut renewals = Vec::new();
        for k in 0..=16u32 {
            let now = t + k * iv;
            checkin(&mut p, 1, -15, now);
            checkin(&mut p, 2, -3, now);
            for o in p.plan(now) {
                assert_eq!(o, (2, 15));
                renewals.push(now - t);
            }
        }
        // Issued at 0 (until 900); renewed at 840 (60 s left), not before.
        assert_eq!(renewals, vec![0, 840]);
    }

    #[test]
    fn due_after_checkin_or_interval() {
        let iv = 300;
        let mut p = weak_and_good(iv);
        assert!(p.due(1000), "never planned");
        p.plan(1000);
        assert!(!p.due(1000));
        assert!(!p.due(1000 + iv - 1));
        assert!(p.due(1000 + iv), "one interval since the last plan");
        checkin(&mut p, 2, -3, 1010);
        assert!(p.due(1010), "a check-in arrived");
        p.plan(1010);
        assert!(!p.due(1011));
    }

    #[test]
    fn renews_before_expiry() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        let t = 1000;
        checkin(&mut p, 1, -15, t);
        checkin(&mut p, 2, -3, t);
        assert_eq!(p.plan(t), vec![(2, 15)]);
        let at5 = t + 300;
        checkin(&mut p, 1, -15, at5);
        checkin(&mut p, 2, -3, at5);
        assert!(p.plan(at5).is_empty());
        let late = t + 900 - IV + 1;
        checkin(&mut p, 1, -15, late);
        checkin(&mut p, 2, -3, late);
        assert_eq!(p.plan(late), vec![(2, 15)]);
    }

    #[test]
    fn max_two_relays() {
        let mut p = planner(&[
            (1, Role::Full),
            (2, Role::Full),
            (3, Role::Full),
            (4, Role::Full),
            (5, Role::Full),
        ]);
        checkin(&mut p, 1, -15, 1000);
        for n in 2..=5 {
            checkin(&mut p, n, -3, 1000);
        }
        assert_eq!(p.plan(1000), vec![(2, 15), (3, 15)]);
    }

    #[test]
    fn revoked_never_chosen() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full), (3, Role::Full)]);
        checkin(&mut p, 1, -15, 1000);
        checkin(&mut p, 2, -1, 1000);
        checkin(&mut p, 3, -5, 1000);
        p.observe(&Inbound::Revoked { node: 2 }, 1000);
        checkin(&mut p, 2, -1, 1001);
        assert_eq!(p.plan(1001), vec![(3, 15)]);
    }

    #[test]
    fn hub_never_chosen() {
        let mut p = planner(&[(1, Role::Full), (9, Role::Hub), (3, Role::Full)]);
        checkin(&mut p, 1, -15, 1000);
        checkin(&mut p, 9, 0, 1000);
        checkin(&mut p, 3, -5, 1000);
        assert_eq!(p.plan(1000), vec![(3, 15)]);
    }

    #[test]
    fn unknown_role_never_chosen() {
        let mut p = planner(&[(1, Role::Full)]);
        checkin(&mut p, 1, -15, 1000);
        checkin(&mut p, 7, 0, 1000);
        assert!(p.plan(1000).is_empty());
    }

    #[test]
    fn weak_member_never_its_own_relay() {
        // Overlapping thresholds (weak < -5, good >= -10): node 1 at -8 is
        // both weak and "good" and has the best SNR, but must not relay for
        // itself. Only node 2 (-9) may be chosen.
        let cfg = RelayConfig {
            weak_snr_db: -5,
            good_snr_db: -10,
            checkin_secs: IV,
        };
        let mut p = RelayPlanner::new(cfg);
        for n in [1, 2] {
            p.observe(
                &Inbound::CardLearned {
                    node: n,
                    role: Role::Full,
                },
                0,
            );
        }
        checkin(&mut p, 1, -8, 1000);
        checkin(&mut p, 2, -9, 1000);
        // Both are weak; each can only be relayed by the other.
        assert_eq!(p.plan(1000), vec![(2, 15), (1, 15)]);
        // A lone weak node has nobody to relay for it.
        let mut q = RelayPlanner::new(cfg);
        q.observe(
            &Inbound::CardLearned {
                node: 1,
                role: Role::Full,
            },
            0,
        );
        checkin(&mut q, 1, -8, 1000);
        assert!(q.plan(1000).is_empty());
    }

    #[test]
    fn never_checked_in_member_goes_weak() {
        let mut p = RelayPlanner::new(RelayConfig::new(IV));
        let t = 1000;
        p.observe(
            &Inbound::CardLearned {
                node: 1,
                role: Role::Full,
            },
            t,
        );
        p.observe(
            &Inbound::CardLearned {
                node: 2,
                role: Role::Full,
            },
            t,
        );
        let at = t + 2 * IV;
        p.observe(
            &Inbound::CheckIn {
                node: 2,
                hub_snr: -3,
                time: at,
            },
            at,
        );
        assert!(p.plan(at).is_empty());
        let at = t + 2 * IV + 1;
        p.observe(
            &Inbound::CheckIn {
                node: 2,
                hub_snr: -3,
                time: at,
            },
            at,
        );
        assert_eq!(p.plan(at), vec![(2, 15)]);
    }

    #[test]
    fn gives_up_on_silent_member_until_it_returns() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        checkin(&mut p, 1, -3, 1000);
        checkin(&mut p, 2, -3, 1000);
        // 1 stays silent; 2 keeps checking in.
        let edge = 1000 + 6 * IV;
        checkin(&mut p, 2, -3, edge);
        assert_eq!(p.plan(edge), vec![(2, 15)]);
        // Node 2's order from `edge` has lapsed by `past`, so a fresh order
        // WOULD be due if node 1 were still planned for.
        let past = edge + 900;
        checkin(&mut p, 2, -3, past);
        assert!(p.plan(past).is_empty());
        // 1 comes back weak: eligible again.
        let back = past + 10;
        p.observe(
            &Inbound::CheckIn {
                node: 1,
                hub_snr: -15,
                time: back,
            },
            back,
        );
        checkin(&mut p, 2, -3, back);
        assert_eq!(p.plan(back), vec![(2, 15)]);
    }

    #[test]
    fn future_dated_checkin_uses_receive_time() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        let now = 1000;
        p.observe(
            &Inbound::CheckIn {
                node: 1,
                hub_snr: -3,
                time: now + 299,
            },
            now,
        );
        checkin(&mut p, 2, -3, now);
        let later = now + 2 * IV + 1;
        checkin(&mut p, 2, -3, later);
        assert_eq!(p.plan(later), vec![(2, 15)]);
        // and a later check-in is not blocked by the earlier future frame
        let back = later + 1;
        p.observe(
            &Inbound::CheckIn {
                node: 1,
                hub_snr: -3,
                time: back,
            },
            back,
        );
        assert!(p.plan(back).is_empty());
    }

    #[test]
    fn already_relaying_first_then_snr_then_node() {
        let mut p = planner(&[
            (1, Role::Full),
            (2, Role::Full),
            (3, Role::Full),
            (4, Role::Full),
            (5, Role::Full),
        ]);
        let t = 1000;
        checkin(&mut p, 1, -15, t);
        checkin(&mut p, 2, -3, t);
        checkin(&mut p, 3, -3, t);
        checkin(&mut p, 4, -1, t);
        checkin(&mut p, 5, -5, t);
        // best SNR first, tie broken by lowest node
        assert_eq!(p.plan(t), vec![(4, 15), (2, 15)]);
        // 5 is now relaying (as if ordered earlier) and outranks better SNR
        p.orders.insert(5, (t + 900, t));
        let n = t + 10;
        for (node, snr) in [(1, -15), (2, -3), (3, -3), (4, -1), (5, -5)] {
            checkin(&mut p, node, snr, n);
        }
        p.orders.insert(4, (0, 0));
        p.orders.insert(2, (0, 0));
        // 5 active -> first; then best SNR among the rest = 4. 5 not yet due.
        assert_eq!(p.plan(n), vec![(4, 15)]);
    }

    #[test]
    fn no_double_order_across_two_weak_members() {
        let mut p = planner(&[
            (1, Role::Full),
            (2, Role::Full),
            (3, Role::Full),
            (4, Role::Full),
        ]);
        checkin(&mut p, 1, -15, 1000);
        checkin(&mut p, 2, -15, 1000);
        checkin(&mut p, 3, -3, 1000);
        checkin(&mut p, 4, -4, 1000);
        let plan = p.plan(1000);
        assert_eq!(plan, vec![(3, 15), (4, 15)]);
    }

    #[test]
    fn failed_relay_off_is_retried() {
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(5, 1, 1000), 1000, &mut t).unwrap();
        t.fail_off = true;
        assert_eq!(s.tick(1060, &mut t), Err(TxError::Busy));
        assert_eq!(t.calls, vec![true]);
        t.fail_off = false;
        s.tick(1061, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
        assert!(!s.relaying(1061));
    }

    #[test]
    fn member_turns_relay_on_and_off() {
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(5, 15, 1000), 1000, &mut t).unwrap();
        assert_eq!(t.calls, vec![true]);
        s.on_order(5, &order(5, 15, 1100), 1100, &mut t).unwrap();
        assert_eq!(t.calls, vec![true]);
        let until = 1100 + 900;
        assert!(s.relaying(until - 1));
        s.tick(until - 1, &mut t).unwrap();
        assert_eq!(t.calls, vec![true]);
        s.tick(until, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
        assert!(!s.relaying(until));
        s.tick(until + 1, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
    }

    #[test]
    fn lapsed_order_never_switches_relay_on() {
        // I2: an order whose time + minutes is already past (a replay, or a
        // late delivery) is ignored.
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(5, 15, 1000), 1000 + 900, &mut t)
            .unwrap();
        s.on_order(5, &order(5, 15, 1000), 1000 + 5000, &mut t)
            .unwrap();
        assert!(t.calls.is_empty());
        assert!(!s.relaying(1000 + 900));
        // One second inside its lifetime it still applies, until its end.
        s.on_order(5, &order(5, 15, 1000), 1000 + 899, &mut t)
            .unwrap();
        assert_eq!(t.calls, vec![true]);
        assert!(s.relaying(1000 + 899));
        s.tick(1000 + 900, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
    }

    #[test]
    fn stop_switches_relay_off_for_good() {
        // M6: a revoked unit stops relaying and obeys no later order.
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.stop(&mut t).unwrap();
        assert!(t.calls.is_empty(), "not relaying: nothing to switch off");
        let mut s = RelayState::new();
        s.on_order(5, &order(5, 15, 1000), 1000, &mut t).unwrap();
        s.stop(&mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
        assert!(!s.relaying(1001));
        s.on_order(5, &order(5, 15, 1001), 1001, &mut t).unwrap();
        s.tick(1002, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
        assert!(!s.relaying(1002));
        // A failed switch-off is retried by the next tick.
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(5, 15, 1000), 1000, &mut t).unwrap();
        t.fail_off = true;
        assert_eq!(s.stop(&mut t), Err(TxError::Busy));
        t.fail_off = false;
        s.tick(1001, &mut t).unwrap();
        assert_eq!(t.calls, vec![true, false]);
        assert!(!s.relaying(1001));
    }

    #[test]
    fn order_for_someone_else_ignored() {
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(6, 15, 1000), 1000, &mut t).unwrap();
        s.on_order(5, &order(5, 0, 1000), 1000, &mut t).unwrap();
        s.on_order(5, &order(5, 61, 1000), 1000, &mut t).unwrap();
        assert!(t.calls.is_empty());
        assert!(!s.relaying(1000));
    }

    #[test]
    fn no_panic_on_extreme_times() {
        let mut p = planner(&[(1, Role::Full), (2, Role::Full)]);
        checkin(&mut p, 1, -15, u32::MAX);
        checkin(&mut p, 2, -3, u32::MAX);
        let _ = p.plan(u32::MAX);
        let _ = p.plan(0);
        let mut s = RelayState::new();
        let mut t = Fake::default();
        s.on_order(5, &order(5, 60, u32::MAX), u32::MAX, &mut t)
            .unwrap();
        s.tick(u32::MAX, &mut t).unwrap();
    }

    fn snr(x: Option<f32>) -> i8 {
        match checkin_body(x) {
            Body::CheckIn { hub_snr } => hub_snr,
            _ => panic!(),
        }
    }

    #[test]
    fn checkin_byte_rounding() {
        assert_eq!(snr(Some(-6.6)), -7);
        assert_eq!(snr(Some(-6.4)), -6);
        assert_eq!(snr(Some(-6.5)), -7);
        assert_eq!(snr(Some(6.5)), 7);
        assert_eq!(snr(Some(200.0)), 127);
        assert_eq!(snr(Some(-200.0)), -127);
        assert_eq!(snr(Some(f32::INFINITY)), 127);
        assert_eq!(snr(Some(f32::NAN)), SNR_UNKNOWN);
        assert_eq!(snr(None), SNR_UNKNOWN);
    }

    #[test]
    fn transport_rejects_oversize() {
        let mut t = Fake::default();
        assert_eq!(t.send(&[0u8; MAX_FRAME + 1]), Err(TxError::TooLarge));
        assert_eq!(t.send(&[0u8; MAX_FRAME]), Ok(()));
    }
}
