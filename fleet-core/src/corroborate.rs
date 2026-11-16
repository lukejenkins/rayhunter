//! Corroboration and alert tiers (spec 5 and 11.1).
//!
//! Pure: consumes `Inbound` values (and the device's own verdicts) and emits
//! `Alert`s. It never talks to `Node`.
//!
//! ## AlertKey rule (deterministic)
//! * Network kinds (`ServiceLost`, `Downgraded`, `TowersGone`): the key is
//!   always `{kind, tag: None}`; tags are ignored.
//! * Other kinds: one group per distinct tag among the fresh (or, for a key
//!   already emitted, held), non-revoked tagged verdicts of that kind. An untagged verdict joins every one of those
//!   groups. If there is no tagged verdict, the single group is `tag: None`.
//!   (So a key can move from `tag: None` to `tag: Some(..)` when a tagged
//!   verdict arrives; the old key is then withdrawn and the new one emitted.)
//!
//! There is one alert per key (controller ruling R3): support 1 that qualifies
//! gives `StrongSingle`; support >= 2 gives `Corroborated`; a key moving from
//! one to the other re-emits with the same key.
//!
//! Each node has one entry per kind: its newest verdict replaces the older one,
//! tag and all, so it supports at most one tag group per kind. A key is raised
//! from entries under `WINDOW` old; once emitted it keeps an entry until
//! `WINDOW + WITHDRAW_GRACE`, and is withdrawn only when support counted that
//! way no longer qualifies. Held support only keeps or lowers an emitted
//! alert: its units, strength and label rise above what was last emitted only
//! as far as fresh entries carry them (`cap_rise`), so a verdict 600-900 s old
//! can never raise one. A Weaker group that collapses to one held unit is
//! withdrawn rather than turned into a (Strong) StrongSingle, unless a fresh
//! supporter qualifies StrongSingle by itself.

use crate::consts::{WINDOW, WITHDRAW_GRACE};
use crate::node::Inbound;
use crate::wire::{Level, Role, VerdictKind};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Wearer,
    Group,
    Organisers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    Strong,
    Weaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLabel {
    Own,
    Corroborated,
    StrongSingle,
    AreaOutage,
    AreaDowngrade,
    TowersGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertKey {
    pub kind: VerdictKind,
    pub tag: Option<[u8; 8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub key: AlertKey,
    pub audience: Audience,
    pub kind: VerdictKind,
    pub units: u8,
    pub strength: Strength,
    pub label: AlertLabel,
    pub withdrawn: bool,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    node: u16,
    role: Role,
    kind: VerdictKind,
    level: Level,
    tag: Option<[u8; 8]>,
    time: u32,
}

/// What was last emitted for a key (so changes and withdrawals are detected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Emitted {
    units: u8,
    strength: Strength,
    label: AlertLabel,
}

type Key = (u8, Option<[u8; 8]>);

#[derive(Debug, Clone)]
pub struct Corroborator {
    me: u16,
    entries: Vec<Entry>,
    revoked: BTreeSet<u16>,
    emitted: BTreeMap<Key, Emitted>,
}

fn fresh(time: u32, now: u32) -> bool {
    // A verdict dated after `now` (within the skew Node allows) is fresh.
    now.saturating_sub(time) < WINDOW
}

/// Still counts for an alert that has already been emitted (C1): without the
/// grace each supporter would expire just before its next verdict arrives.
fn held(time: u32, now: u32) -> bool {
    now.saturating_sub(time) < WINDOW.saturating_add(WITHDRAW_GRACE)
}

/// The group alert a set of supporting entries qualifies for, if any.
fn qualify<'a>(kind: VerdictKind, sup: impl Iterator<Item = &'a Entry>) -> Option<Emitted> {
    let sup: Vec<&Entry> = sup.collect();
    let mut nodes: Vec<u16> = sup.iter().map(|e| e.node).collect();
    nodes.sort_unstable();
    nodes.dedup();
    let units = nodes.len().min(255) as u8;
    let label = if units >= 2 {
        multi_label(kind)
    } else if !kind.is_network()
        && sup.iter().any(|e| {
            e.role == Role::Full && (kind == VerdictKind::TowerFlood || e.level == Level::High)
        })
    {
        AlertLabel::StrongSingle
    } else {
        return None;
    };
    // StrongSingle is Strong by definition.
    let strength = if label == AlertLabel::StrongSingle || sup.iter().any(|e| e.role == Role::Full)
    {
        Strength::Strong
    } else {
        Strength::Weaker
    };
    Some(Emitted {
        units,
        strength,
        label,
    })
}

/// The label for two or more units.
fn multi_label(kind: VerdictKind) -> AlertLabel {
    match kind {
        VerdictKind::ServiceLost => AlertLabel::AreaOutage,
        VerdictKind::Downgraded => AlertLabel::AreaDowngrade,
        VerdictKind::TowersGone => AlertLabel::TowersGone,
        _ => AlertLabel::Corroborated,
    }
}

/// What the fresh entries of a group carry, axis by axis, whether or not
/// they qualify on their own.
#[derive(Debug, Clone, Copy)]
struct FreshSupport {
    units: u8,
    any_full: bool,
    /// A fresh supporter qualifies StrongSingle on its own (Full, and High
    /// or TowerFlood; never a network kind).
    strong_single: bool,
}

fn fresh_support<'a>(kind: VerdictKind, sup: impl Iterator<Item = &'a Entry>) -> FreshSupport {
    let mut nodes: Vec<u16> = Vec::new();
    let mut any_full = false;
    let mut strong_single = false;
    for e in sup {
        any_full |= e.role == Role::Full;
        strong_single |= !kind.is_network()
            && e.role == Role::Full
            && (kind == VerdictKind::TowerFlood || e.level == Level::High);
        if !nodes.contains(&e.node) {
            nodes.push(e.node);
        }
    }
    FreshSupport {
        units: nodes.len().min(255) as u8,
        any_full,
        strong_single,
    }
}

/// The value to keep for an already-emitted key whose held support `held`
/// still qualifies: decreases follow `held`, but no axis rises above `prev`
/// further than the fresh entries carry it, so a held-but-stale verdict can
/// keep an alert alive yet never raise it.
///
/// Fresh support is taken per axis: a fresh unit count below 2 cannot raise
/// units (prev already has at least 1), and a fresh Full supporter can make a
/// still-qualifying group Strong even when that Full unit alone would not
/// qualify (a Full Low verdict joining two held Light ones).
///
/// `None` withdraws the key: when the capped count is one unit, the only
/// label is StrongSingle (always Strong), which is allowed only if `prev` was
/// already Strong or a fresh supporter qualifies StrongSingle by itself.
/// Otherwise a Weaker group whose units aged out would turn Strong on a
/// verdict that was never fresh.
fn cap_rise(
    kind: VerdictKind,
    prev: Emitted,
    held: Emitted,
    fresh: FreshSupport,
) -> Option<Emitted> {
    let units = held.units.min(prev.units.max(fresh.units));
    if units < 2 {
        // `held` qualifies, so with one unit it is StrongSingle; `prev` may
        // have had more units and been Weaker.
        if prev.strength != Strength::Strong && !fresh.strong_single {
            return None;
        }
        return Some(Emitted {
            units,
            strength: Strength::Strong,
            label: AlertLabel::StrongSingle,
        });
    }
    let strength = if held.strength == Strength::Strong
        && (prev.strength == Strength::Strong || fresh.any_full)
    {
        Strength::Strong
    } else {
        Strength::Weaker
    };
    // units >= 2 came from prev or the fresh entries having >= 2 (and two
    // fresh units always qualify), so this label never ranks above
    // max(prev.label, fresh label).
    Some(Emitted {
        units,
        strength,
        label: multi_label(kind),
    })
}

impl Corroborator {
    pub fn new(me: u16) -> Self {
        Corroborator {
            me,
            entries: Vec::new(),
            revoked: BTreeSet::new(),
            emitted: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, v: &Inbound, now: u32) -> Vec<Alert> {
        match *v {
            Inbound::Verdict {
                node,
                role,
                kind,
                level,
                tag,
                time,
            } => {
                self.add(Entry {
                    node,
                    role,
                    kind,
                    level,
                    tag,
                    time,
                });
                self.evaluate(now)
            }
            Inbound::Revoked { node } => {
                self.revoked.insert(node);
                self.entries.retain(|e| e.node != node);
                self.evaluate(now)
            }
            _ => Vec::new(),
        }
    }

    /// The device's own verdict: always a Wearer alert, and `me` counts as one
    /// supporter in the group logic, as if received from `me` at `now`.
    pub fn observe_own(
        &mut self,
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
        role: Role,
        now: u32,
    ) -> Vec<Alert> {
        let mut out = Vec::new();
        out.push(Alert {
            key: AlertKey {
                kind,
                tag: if kind.is_network() { None } else { tag },
            },
            audience: Audience::Wearer,
            kind,
            units: 1,
            strength: if role == Role::Full {
                Strength::Strong
            } else {
                Strength::Weaker
            },
            label: AlertLabel::Own,
            withdrawn: false,
        });
        self.add(Entry {
            node: self.me,
            role,
            kind,
            level,
            tag,
            time: now,
        });
        out.extend(self.evaluate(now));
        out
    }

    pub fn expire(&mut self, now: u32) -> Vec<Alert> {
        self.evaluate(now)
    }

    fn add(&mut self, e: Entry) {
        if self.revoked.contains(&e.node) {
            return;
        }
        // One entry per (node, kind): the newest replaces the older one, tag
        // and all, so a node supports at most one tag group per kind (I1b).
        if let Some(old) = self
            .entries
            .iter_mut()
            .find(|o| o.node == e.node && o.kind == e.kind)
        {
            if e.time >= old.time {
                *old = e;
            }
        } else {
            self.entries.push(e);
        }
    }

    fn evaluate(&mut self, now: u32) -> Vec<Alert> {
        self.entries.retain(|e| held(e.time, now));

        // Current qualifying groups. A group not yet emitted is raised from
        // fresh entries only; an emitted one is kept from held entries and
        // raised only from fresh ones.
        let mut current: BTreeMap<Key, (VerdictKind, Emitted)> = BTreeMap::new();
        let mut kinds: Vec<VerdictKind> = Vec::new();
        for e in &self.entries {
            if !kinds.contains(&e.kind) {
                kinds.push(e.kind);
            }
        }
        for kind in kinds {
            let of_kind = || self.entries.iter().filter(|e| e.kind == kind);
            let mut tags: Vec<Option<[u8; 8]>> = Vec::new();
            if !kind.is_network() {
                for e in of_kind() {
                    let counts =
                        fresh(e.time, now) || self.emitted.contains_key(&(kind.code(), e.tag));
                    if e.tag.is_some() && counts && !tags.contains(&e.tag) {
                        tags.push(e.tag);
                    }
                }
            }
            if tags.is_empty() {
                tags.push(None);
            }
            for gtag in tags {
                let in_group = |e: &&Entry| kind.is_network() || e.tag.is_none() || e.tag == gtag;
                let fresh_of = || of_kind().filter(in_group).filter(|e| fresh(e.time, now));
                let value = match self.emitted.get(&(kind.code(), gtag)) {
                    // Not yet emitted: raised from fresh entries only.
                    None => qualify(kind, fresh_of()),
                    // Already emitted: kept from held entries, but raised only
                    // as far as fresh entries support.
                    Some(prev) => qualify(kind, of_kind().filter(in_group)).and_then(|held_q| {
                        cap_rise(kind, *prev, held_q, fresh_support(kind, fresh_of()))
                    }),
                };
                if let Some(value) = value {
                    current.insert((kind.code(), gtag), (kind, value));
                }
            }
        }

        let mut out = Vec::new();
        let mk = |kind: VerdictKind, tag: Option<[u8; 8]>, s: Emitted, withdrawn: bool| Alert {
            key: AlertKey { kind, tag },
            audience: Audience::Group,
            kind,
            units: s.units,
            strength: s.strength,
            label: s.label,
            withdrawn,
        };
        for (k, (kind, s)) in &current {
            if self.emitted.get(k) != Some(s) {
                out.push(mk(*kind, k.1, *s, false));
            }
        }
        for (k, s) in &self.emitted {
            if !current.contains_key(k) {
                let kind = VerdictKind::from_code(k.0).expect("code came from a kind");
                out.push(mk(kind, k.1, *s, true));
            }
        }
        self.emitted = current.into_iter().map(|(k, (_, s))| (k, s)).collect();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::VERDICT_INTERVAL;

    const ME: u16 = 1;
    const T: u32 = 10_000;

    fn v(
        node: u16,
        role: Role,
        kind: VerdictKind,
        level: Level,
        tag: Option<[u8; 8]>,
        time: u32,
    ) -> Inbound {
        Inbound::Verdict {
            node,
            role,
            kind,
            level,
            tag,
            time,
        }
    }
    fn groups(a: &[Alert]) -> Vec<&Alert> {
        a.iter().filter(|x| x.audience == Audience::Group).collect()
    }
    const K: VerdictKind = VerdictKind::ImsiRequested;

    #[test]
    fn own_verdict_is_wearer_only() {
        let mut c = Corroborator::new(ME);
        let a = c.observe_own(K, Level::Medium, None, Role::Full, T);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].audience, Audience::Wearer);
        assert_eq!(a[0].label, AlertLabel::Own);
        assert_eq!(a[0].units, 1);
        assert!(!a[0].withdrawn);
    }

    #[test]
    fn two_units_within_window() {
        let mut c = Corroborator::new(ME);
        c.observe_own(K, Level::Medium, None, Role::Full, T);
        let a = c.observe(&v(2, Role::Light, K, Level::Low, None, T + 540), T + 540);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].label, AlertLabel::Corroborated);
        assert_eq!(g[0].units, 2);
        assert_eq!(g[0].strength, Strength::Strong);
        assert!(!g[0].withdrawn);

        let mut c = Corroborator::new(ME);
        c.observe_own(K, Level::Medium, None, Role::Full, T);
        let a = c.observe(&v(2, Role::Light, K, Level::Low, None, T + 601), T + 601);
        assert!(groups(&a).is_empty());
    }

    #[test]
    fn light_only_is_weaker() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].strength, Strength::Weaker);
        assert_eq!(g[0].label, AlertLabel::Corroborated);
    }

    #[test]
    fn tags_must_match() {
        let (t1, t2) = ([1u8; 8], [2u8; 8]);
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, Some(t1), T), T);
        let a = c.observe(&v(3, Role::Full, K, Level::Low, Some(t2), T), T);
        assert!(groups(&a).is_empty());

        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, Some(t1), T), T);
        let a = c.observe(&v(3, Role::Full, K, Level::Low, Some(t1), T), T);
        assert_eq!(groups(&a).len(), 1);
        assert_eq!(groups(&a)[0].key.tag, Some(t1));

        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, Some(t1), T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].units, 2);
    }

    #[test]
    fn strong_single() {
        let mut c = Corroborator::new(ME);
        let a = c.observe(&v(2, Role::Full, K, Level::High, None, T), T);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].label, AlertLabel::StrongSingle);
        assert_eq!(g[0].strength, Strength::Strong);
        assert_eq!(g[0].units, 1);

        let mut c = Corroborator::new(ME);
        let a = c.observe(&v(2, Role::Light, K, Level::High, None, T), T);
        assert!(groups(&a).is_empty());

        let mut c = Corroborator::new(ME);
        let a = c.observe(
            &v(2, Role::Full, VerdictKind::TowerFlood, Level::Low, None, T),
            T,
        );
        assert_eq!(groups(&a)[0].label, AlertLabel::StrongSingle);
    }

    #[test]
    fn strong_single_upgrades_to_corroborated_same_key() {
        let mut c = Corroborator::new(ME);
        let a1 = c.observe(&v(2, Role::Full, K, Level::High, None, T), T);
        let a2 = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a1)[0].key, groups(&a2)[0].key);
        assert_eq!(groups(&a2)[0].label, AlertLabel::Corroborated);
    }

    #[test]
    fn third_unit_updates_count() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a2 = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let a3 = c.observe(&v(4, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a2)[0].units, 2);
        assert_eq!(groups(&a3).len(), 1);
        assert_eq!(groups(&a3)[0].units, 3);
        assert_eq!(groups(&a3)[0].key, groups(&a2)[0].key);
        // A repeat that changes nothing emits nothing.
        let a4 = c.observe(&v(4, Role::Light, K, Level::Low, None, T), T);
        assert!(groups(&a4).is_empty());
    }

    #[test]
    fn network_outage_tiers() {
        let sl = VerdictKind::ServiceLost;
        let mut c = Corroborator::new(ME);
        let a = c.observe(&v(2, Role::Light, sl, Level::Low, None, T), T);
        assert!(groups(&a).is_empty());
        let a = c.observe(&v(3, Role::Light, sl, Level::Low, Some([9; 8]), T), T);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].label, AlertLabel::AreaOutage);
        assert_eq!(g[0].units, 2);
        assert_eq!(g[0].key.tag, None);

        let dg = VerdictKind::Downgraded;
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, dg, Level::High, None, T), T);
        let a = c.observe(&v(3, Role::Light, dg, Level::Low, None, T), T);
        assert_eq!(groups(&a)[0].label, AlertLabel::AreaDowngrade);

        let mut c = Corroborator::new(ME);
        c.observe(
            &v(2, Role::Light, VerdictKind::TowersGone, Level::Low, None, T),
            T,
        );
        let a = c.observe(
            &v(3, Role::Light, VerdictKind::TowersGone, Level::Low, None, T),
            T,
        );
        assert_eq!(groups(&a)[0].label, AlertLabel::TowersGone);

        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, sl, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, dg, Level::Low, None, T), T);
        assert!(groups(&a).is_empty());
    }

    #[test]
    fn network_strength_follows_roles() {
        // Spec 11.1: only light nodes agreeing is "weaker", as for any kind.
        let sl = VerdictKind::ServiceLost;
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, sl, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, sl, Level::Low, None, T), T);
        assert_eq!(groups(&a)[0].label, AlertLabel::AreaOutage);
        assert_eq!(groups(&a)[0].strength, Strength::Weaker);
        // One full node among them makes it strong.
        let a = c.observe(&v(4, Role::Full, sl, Level::Low, None, T), T);
        assert_eq!(groups(&a)[0].units, 3);
        assert_eq!(groups(&a)[0].strength, Strength::Strong);
        // A single unit's own loss stays with its wearer, whatever its role.
        let mut c = Corroborator::new(ME);
        let a = c.observe_own(sl, Level::Low, None, Role::Light, T);
        assert!(groups(&a).is_empty());
        assert_eq!(a[0].audience, Audience::Wearer);
        assert_eq!(a[0].label, AlertLabel::Own);
    }

    #[test]
    fn revocation_withdraws_support() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a).len(), 1);
        let a = c.observe(&Inbound::Revoked { node: 3 }, T + 1);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert!(g[0].withdrawn);
        assert_eq!(g[0].key, AlertKey { kind: K, tag: None });
        // A revoked node's later verdicts no longer count.
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 2), T + 2);
        assert!(groups(&a).is_empty());
        // Withdrawn once only.
        assert!(groups(&c.expire(T + 3)).is_empty());
    }

    #[test]
    fn window_expiry_withdraws() {
        // An emitted alert keeps its supporters for WITHDRAW_GRACE past the
        // window (C1), and is withdrawn exactly when that runs out.
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, None, T), T);
        c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        assert!(c.expire(T + 599).is_empty());
        assert!(c.expire(T + 601).is_empty(), "held by the grace");
        assert!(c.expire(T + WINDOW + WITHDRAW_GRACE - 1).is_empty());
        let a = c.expire(T + WINDOW + WITHDRAW_GRACE);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert!(g[0].withdrawn);
        assert!(c.expire(T + 2000).is_empty());
    }

    /// Apply group alerts to the set of currently raised keys.
    fn track(active: &mut Vec<AlertKey>, a: &[Alert]) {
        for x in groups(a) {
            active.retain(|k| *k != x.key);
            if !x.withdrawn {
                active.push(x.key);
            }
        }
    }

    #[test]
    fn fifty_tag_probe_one_group_at_a_time() {
        // One seized Full node sends 50 High verdicts with 50 tags inside
        // ten minutes (I1b): its newest verdict replaces the older one.
        let mut c = Corroborator::new(ME);
        let mut active = Vec::new();
        for i in 0..50u8 {
            let t = T + i as u32 * 10;
            let a = c.observe(&v(2, Role::Full, K, Level::High, Some([i; 8]), t), t);
            track(&mut active, &a);
            assert!(active.len() <= 1, "after tag {i}: {active:?}");
        }
        assert_eq!(
            active,
            vec![AlertKey {
                kind: K,
                tag: Some([49; 8])
            }]
        );
    }

    #[test]
    fn one_node_cannot_hold_two_tag_groups() {
        let (t1, t2) = (Some([1u8; 8]), Some([2u8; 8]));
        let mut c = Corroborator::new(ME);
        let mut active = Vec::new();
        track(
            &mut active,
            &c.observe(&v(3, Role::Light, K, Level::Low, None, T), T),
        );
        let a = c.observe(&v(4, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a)[0].strength, Strength::Weaker);
        track(&mut active, &a);
        // Full node 2 with tag 1: the group becomes Strong (once).
        let a = c.observe(&v(2, Role::Full, K, Level::Low, t1, T + 10), T + 10);
        track(&mut active, &a);
        assert_eq!(active, vec![AlertKey { kind: K, tag: t1 }]);
        // Node 2 again with tag 2: tag 1 loses it, so only one Strong group.
        let a = c.observe(&v(2, Role::Full, K, Level::Low, t2, T + 20), T + 20);
        track(&mut active, &a);
        assert_eq!(active, vec![AlertKey { kind: K, tag: t2 }], "{a:?}");
        let g = groups(&a);
        assert!(g.iter().any(|x| x.key.tag == t1 && x.withdrawn));
        assert!(
            g.iter()
                .any(|x| x.key.tag == t2 && x.units == 3 && x.strength == Strength::Strong)
        );
    }

    #[test]
    fn sustained_detection_never_flaps() {
        // Two Full units each send a verdict every VERDICT_INTERVAL (3 is
        // 60 s behind 2), each delivered 5 s late, for an hour.
        let mut c = Corroborator::new(ME);
        let sends: Vec<(u16, u32)> = (0..=6u32)
            .flat_map(|j| {
                [
                    (2u16, T + j * VERDICT_INTERVAL),
                    (3, T + 60 + j * VERDICT_INTERVAL),
                ]
            })
            .collect();
        let last_time = sends.iter().map(|s| s.1).max().unwrap();
        let mut seen: Vec<(u32, Alert)> = Vec::new();
        for now in T..=last_time + WINDOW + WITHDRAW_GRACE + 60 {
            let mut a = Vec::new();
            for &(node, time) in &sends {
                if time + 5 == now {
                    a.extend(c.observe(&v(node, Role::Full, K, Level::Medium, None, time), now));
                }
            }
            a.extend(c.expire(now));
            seen.extend(groups(&a).into_iter().map(|x| (now, *x)));
        }
        let (t_raise, first) = seen[0];
        assert!(!first.withdrawn);
        assert_eq!((first.label, first.units), (AlertLabel::Corroborated, 2));
        assert_eq!(t_raise, T + 60 + 5);
        // Exactly one more group alert: the final withdrawal, no flapping.
        assert_eq!(seen.len(), 2, "{seen:?}");
        let (t_off, w) = seen[1];
        assert!(w.withdrawn);
        assert!(
            t_off >= last_time + WINDOW,
            "withdrawn at {t_off}, last {last_time}"
        );
        assert!(t_off <= last_time + WINDOW + WITHDRAW_GRACE);
    }

    #[test]
    fn skewed_clocks_still_corroborate() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T - 240), T);
        assert_eq!(groups(&a).len(), 1);
        assert_eq!(groups(&a)[0].units, 2);
    }

    #[test]
    fn future_dated_verdict_counts_and_extremes_do_not_panic() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Full, K, Level::Low, None, T + 200), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a).len(), 1);
        c.observe(&v(4, Role::Light, K, Level::Low, None, u32::MAX), 0);
        c.observe(&v(5, Role::Light, K, Level::Low, None, 0), u32::MAX);
        c.expire(u32::MAX);
        c.expire(0);
    }

    #[test]
    fn same_node_twice_counts_once() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(2, Role::Light, K, Level::Medium, None, T + 5), T + 5);
        assert!(groups(&a).is_empty());
        // Own twice likewise.
        let mut c = Corroborator::new(ME);
        c.observe_own(K, Level::Low, None, Role::Light, T);
        let a = c.observe_own(K, Level::Low, None, Role::Light, T + 5);
        assert!(groups(&a).is_empty());
    }

    #[test]
    fn own_plus_received_corroborate() {
        let mut c = Corroborator::new(ME);
        c.observe_own(K, Level::Low, None, Role::Light, T);
        let a = c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        assert_eq!(groups(&a)[0].units, 2);
    }

    #[test]
    fn light_cannot_strong_single() {
        let mut c = Corroborator::new(ME);
        let a = c.observe(
            &v(2, Role::Light, VerdictKind::TowerFlood, Level::Low, None, T),
            T,
        );
        assert!(groups(&a).is_empty());
        let a = c.observe(&v(3, Role::Light, K, Level::High, None, T), T);
        assert!(groups(&a).is_empty());
    }

    #[test]
    fn own_key_normalised_for_network_kinds() {
        let mut c = Corroborator::new(ME);
        let a = c.observe_own(
            VerdictKind::ServiceLost,
            Level::Low,
            Some([7; 8]),
            Role::Full,
            T,
        );
        assert_eq!(a[0].key.tag, None);
        let a = c.observe_own(K, Level::Low, Some([7; 8]), Role::Full, T);
        assert_eq!(a[0].key.tag, Some([7; 8]));
    }

    #[test]
    fn exactly_window_old_does_not_count() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 600), T + 600);
        assert!(groups(&a).is_empty());
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 599), T + 599);
        assert_eq!(groups(&a).len(), 1);
    }

    #[test]
    fn stale_held_verdict_cannot_raise_units() {
        let mut c = Corroborator::new(ME);
        let a = c.observe(&v(2, Role::Full, K, Level::High, None, T), T);
        let g = groups(&a);
        assert_eq!((g[0].label, g[0].units), (AlertLabel::StrongSingle, 1));
        // A Light verdict dated 700 s back: held (under 900 s), not fresh.
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T - 700), T + 10);
        assert!(groups(&a).is_empty(), "stale support raised it: {a:?}");
        // Re-evaluation alone does not raise it either.
        assert!(groups(&c.expire(T + 20)).is_empty());
        // A fresh verdict from the same unit does.
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 30), T + 30);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!((g[0].label, g[0].units), (AlertLabel::Corroborated, 2));
        assert_eq!(g[0].strength, Strength::Strong);
        assert!(!g[0].withdrawn);
    }

    #[test]
    fn stale_held_verdict_cannot_raise_strength() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let g = groups(&a);
        assert_eq!((g[0].units, g[0].strength), (2, Strength::Weaker));
        // A held-but-stale Full verdict (700 s old) changes nothing.
        let a = c.observe(&v(4, Role::Full, K, Level::Low, None, T - 700), T + 10);
        assert!(groups(&a).is_empty(), "stale Full raised it: {a:?}");
        assert!(groups(&c.expire(T + 20)).is_empty());
        // A fresh Full verdict makes it Strong (and three units).
        let a = c.observe(&v(4, Role::Full, K, Level::Low, None, T + 30), T + 30);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!((g[0].units, g[0].strength), (3, Strength::Strong));
        assert_eq!(g[0].label, AlertLabel::Corroborated);
    }

    #[test]
    fn held_support_still_keeps_and_lowers() {
        // A is Full: High lowers to StrongSingle, Medium is withdrawn.
        for (level, after) in [
            (Level::High, Some(AlertLabel::StrongSingle)),
            (Level::Medium, None),
        ] {
            let mut c = Corroborator::new(ME);
            c.observe(&v(2, Role::Full, K, level, None, T), T);
            let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 5), T + 5);
            assert_eq!(groups(&a)[0].units, 2);
            // A refreshes; B goes stale but stays held: no change at all.
            let a = c.observe(&v(2, Role::Full, K, level, None, T + 600), T + 600);
            assert!(groups(&a).is_empty(), "{level:?}: {a:?}");
            for now in T + 601..T + 5 + WINDOW + WITHDRAW_GRACE {
                assert!(groups(&c.expire(now)).is_empty(), "{level:?} at {now}");
            }
            // B past 900 s: whatever A alone qualifies for.
            let a = c.expire(T + 5 + WINDOW + WITHDRAW_GRACE);
            let g = groups(&a);
            assert_eq!(g.len(), 1, "{level:?}: {a:?}");
            match after {
                Some(label) => {
                    assert!(!g[0].withdrawn);
                    assert_eq!((g[0].label, g[0].units), (label, 1));
                    assert_eq!(g[0].strength, Strength::Strong);
                }
                None => assert!(g[0].withdrawn),
            }
        }
    }

    #[test]
    fn collapse_to_one_cannot_raise_strength() {
        // Weaker·2 from two Light units; a Full/High verdict that was never
        // fresh must not leave a Strong StrongSingle behind when they age out.
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let g = groups(&a);
        assert_eq!((g[0].label, g[0].units), (AlertLabel::Corroborated, 2));
        assert_eq!(g[0].strength, Strength::Weaker);
        let a = c.observe(&v(4, Role::Full, K, Level::High, None, T + 40), T + 650);
        assert!(groups(&a).is_empty(), "{a:?}");
        for now in T + 651..T + 900 {
            assert!(groups(&c.expire(now)).is_empty(), "at {now}");
        }
        let a = c.expire(T + 900);
        let g = groups(&a);
        assert_eq!(g.len(), 1, "{a:?}");
        assert!(g[0].withdrawn, "never-fresh Full/High raised it: {a:?}");
        assert!(groups(&c.expire(T + 901)).is_empty());
    }

    #[test]
    fn strong_collapse_to_held_single_stays() {
        // Corroborated·2 Strong (node 2 Full/High); node 3 ages out while
        // node 2 is held but not fresh: StrongSingle·1 Strong, not withdrawn.
        let mut c = Corroborator::new(ME);
        c.observe(&v(3, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(2, Role::Full, K, Level::High, None, T + 100), T + 100);
        let g = groups(&a);
        assert_eq!((g[0].label, g[0].units), (AlertLabel::Corroborated, 2));
        assert_eq!(g[0].strength, Strength::Strong);
        let a = c.expire(T + 900);
        let g = groups(&a);
        assert_eq!(g.len(), 1, "{a:?}");
        assert!(!g[0].withdrawn, "{a:?}");
        assert_eq!((g[0].label, g[0].units), (AlertLabel::StrongSingle, 1));
        assert_eq!(g[0].strength, Strength::Strong);
    }

    #[test]
    fn offset_refreshes_do_not_oscillate() {
        // Two Light units refreshing every VERDICT_INTERVAL, 300 s apart, and
        // a third (Full) joining briefly: once lowered back to two units the
        // alert stays put between refreshes.
        let mut c = Corroborator::new(ME);
        let mut seen = Vec::new();
        for now in T..T + 6 * VERDICT_INTERVAL {
            let mut a = Vec::new();
            let d = now - T;
            if d % VERDICT_INTERVAL == 0 {
                a.extend(c.observe(&v(2, Role::Light, K, Level::Low, None, now), now));
            }
            if d % VERDICT_INTERVAL == 300 {
                a.extend(c.observe(&v(3, Role::Light, K, Level::Low, None, now - 40), now));
            }
            if d == 1000 {
                a.extend(c.observe(&v(4, Role::Full, K, Level::Low, None, now), now));
            }
            a.extend(c.expire(now));
            seen.extend(
                groups(&a)
                    .into_iter()
                    .map(|x| (now - T, x.units, x.strength)),
            );
        }
        assert_eq!(
            seen,
            vec![
                (300, 2, Strength::Weaker),
                (1000, 3, Strength::Strong),
                (1000 + WINDOW + WITHDRAW_GRACE, 2, Strength::Weaker),
            ]
        );
    }

    #[test]
    fn strength_only_change_emits_update() {
        let mut c = Corroborator::new(ME);
        c.observe(&v(2, Role::Light, K, Level::Low, None, T), T);
        let a = c.observe(&v(3, Role::Light, K, Level::Low, None, T + 300), T + 300);
        assert_eq!(groups(&a)[0].strength, Strength::Weaker);
        // Node 2 ages out (window + grace, since the alert was emitted) in
        // the same step a Full node joins: units stay 2.
        let at = T + WINDOW + WITHDRAW_GRACE;
        let a = c.observe(&v(4, Role::Full, K, Level::Low, None, at), at);
        let g = groups(&a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].units, 2);
        assert_eq!(g[0].strength, Strength::Strong);
        assert!(!g[0].withdrawn);
    }
}
