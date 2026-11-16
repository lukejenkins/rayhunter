//! End-to-end scenarios for Part 3: real fleet-core code over the virtual
//! radio. All time is simulated; every run is reproducible from its seed.

use fleet_core::consts::*;
use fleet_core::corroborate::{Alert, AlertLabel, Audience, Strength};
use fleet_core::crypto::{EventAuthority, NodeKey};
use fleet_core::kit::{Kit, Tables, open_kit};
use fleet_core::node::{Inbound, Rejects, SendError};
use fleet_core::wire::{Body, Card, Directive, Header, Level, Role, VerdictKind, decode};
use fleet_sim::{Airtime, World, radio};
use std::collections::BTreeMap;

const EID: [u8; 8] = *b"sim-evt1";
const START: u32 = 1_000_000;
const EXPIRY: u32 = START + 6 * 3600;
const T0: u32 = START + 60;
const HUB: u16 = 100;
const IMSI: VerdictKind = VerdictKind::ImsiRequested;

fn auth_until(expiry: u32) -> EventAuthority {
    EventAuthority::new([7; 32], EID, START, expiry)
}

fn auth() -> EventAuthority {
    auth_until(EXPIRY)
}

fn seed(node: u16) -> [u8; 32] {
    let mut s = [0x5a; 32];
    s[..2].copy_from_slice(&node.to_be_bytes());
    s
}

fn tables() -> Tables {
    Tables {
        phrases: vec!["regroup".into(), "move north".into(), "all clear".into()],
        points: vec!["fountain".into(), "bridge".into()],
    }
}

fn kit(a: &EventAuthority, node: u16, role: Role, checkin_min: u8) -> Kit {
    let bytes = a
        .make_kit(
            seed(node),
            node,
            role,
            tables(),
            [3; 32],
            checkin_min,
            vec![],
        )
        .unwrap();
    open_kit(&bytes, T0).unwrap()
}

/// A hub plus members; `idx[node]` is the World index of each node number.
struct Fleet {
    w: World,
    hub: usize,
    idx: BTreeMap<u16, usize>,
}

impl Fleet {
    fn i(&self, node: u16) -> usize {
        self.idx[&node]
    }
    /// Every World index, hub included.
    fn all(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.idx.values().copied().collect();
        v.push(self.hub);
        v.sort();
        v
    }
    fn members(&self) -> Vec<usize> {
        self.idx.values().copied().collect()
    }
}

fn fleet_with(
    a: &EventAuthority,
    world_seed: u64,
    checkin_min: u8,
    hub_pos: (f32, f32),
    members: &[(u16, Role, (f32, f32))],
) -> Fleet {
    let mut w = World::new(world_seed);
    w.set_clock(T0);
    let kits: Vec<Kit> = members
        .iter()
        .map(|(n, r, _)| kit(a, *n, *r, checkin_min))
        .collect();
    let cards: Vec<Card> = kits.iter().map(|k| k.card.clone()).collect();
    let hub = w.add_hub(kit(a, HUB, Role::Hub, checkin_min), hub_pos, cards);
    let mut idx = BTreeMap::new();
    for (k, (n, r, pos)) in kits.into_iter().zip(members) {
        let i = if *r == Role::Organiser {
            w.add_organiser(k, *pos, false)
        } else {
            w.add(k, *pos, false)
        };
        idx.insert(*n, i);
    }
    Fleet { w, hub, idx }
}

fn fleet(members: &[(u16, Role, (f32, f32))]) -> Fleet {
    fleet_with(&auth(), 1, 1, (0.0, 0.0), members)
}

/// The last Group alert for `kind`, if it is current (not withdrawn).
fn current_group(alerts: &[Alert], kind: VerdictKind) -> Option<Alert> {
    alerts
        .iter()
        .rev()
        .find(|a| a.audience == Audience::Group && a.kind == kind)
        .copied()
        .filter(|a| !a.withdrawn)
}

fn ever_group(alerts: &[Alert], kind: VerdictKind) -> bool {
    alerts
        .iter()
        .any(|a| a.audience == Audience::Group && a.kind == kind)
}

/// Every reject except `pending_dropped`, which is a follow-on count for a
/// frame already counted once under `unknown_sender`.
fn reject_total(r: &Rejects) -> u32 {
    r.wire
        + r.signature
        + r.unknown_sender
        + r.not_allowed
        + r.replay
        + r.future
        + r.expired
        + r.revoked
        + r.rate_limited
        + r.stale
}

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

fn counter_at(t: u32) -> u32 {
    (t - START) * COUNTER_PER_SEC
}

fn assert_corroborated(f: &Fleet, kind: VerdictKind, label: AlertLabel, strength: Strength) {
    for i in f.all() {
        let a = current_group(f.w.alerts(i), kind)
            .unwrap_or_else(|| panic!("index {i}: no current group alert for {kind:?}"));
        assert_eq!(a.label, label, "index {i}");
        assert_eq!(a.units, 2, "index {i}");
        assert_eq!(a.strength, strength, "index {i}");
    }
}

#[test]
fn corroborated_alert_end_to_end() {
    let mut f = fleet(&[
        (1, Role::Full, (150.0, 0.0)),
        (2, Role::Light, (-150.0, 0.0)),
    ]);
    f.w.step(30);
    let (a, b) = (f.i(1), f.i(2));
    assert!(
        f.w.verdict_from(a, IMSI, Level::Medium, None)
            .unwrap()
            .is_some()
    );
    f.w.step(240);
    assert!(
        f.w.verdict_from(b, IMSI, Level::Medium, None)
            .unwrap()
            .is_some()
    );
    f.w.step(1);
    assert_corroborated(&f, IMSI, AlertLabel::Corroborated, Strength::Strong);
}

#[test]
fn light_only_weaker_end_to_end() {
    let mut f = fleet(&[
        (1, Role::Light, (150.0, 0.0)),
        (2, Role::Light, (-150.0, 0.0)),
    ]);
    f.w.step(30);
    let (a, b) = (f.i(1), f.i(2));
    f.w.verdict_from(a, IMSI, Level::High, None)
        .unwrap()
        .unwrap();
    f.w.step(240);
    // One Light unit, even at High, is never a group alert.
    for i in f.all() {
        assert!(!ever_group(f.w.alerts(i), IMSI), "index {i}");
    }
    f.w.verdict_from(b, IMSI, Level::High, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    assert_corroborated(&f, IMSI, AlertLabel::Corroborated, Strength::Weaker);
}

#[test]
fn hub_off_alerts_continue() {
    let mut f = fleet(&[
        (1, Role::Full, (100.0, 0.0)),
        (2, Role::Full, (-100.0, 0.0)),
        (3, Role::Light, (0.0, 150.0)),
    ]);
    f.w.step(30);
    for i in f.members() {
        assert_eq!(f.w.node(i).roster().count(), 4, "roster learned");
    }
    f.w.remove(f.hub);
    let before = f.w.airtime();
    f.w.verdict_from(f.i(1), IMSI, Level::Medium, None)
        .unwrap()
        .unwrap();
    f.w.step(60);
    f.w.verdict_from(f.i(2), IMSI, Level::Medium, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    for i in f.members() {
        let a = current_group(f.w.alerts(i), IMSI).expect("alert without the hub");
        assert_eq!((a.label, a.units), (AlertLabel::Corroborated, 2));
    }
    assert!(f.w.airtime().transmissions > before.transmissions);
}

#[test]
fn replayed_frame_rejected() {
    let mut f = fleet(&[
        (1, Role::Full, (100.0, 0.0)),
        (2, Role::Full, (-100.0, 0.0)),
        (3, Role::Light, (0.0, 150.0)),
    ]);
    f.w.step(30);
    let src = f.i(1);
    let frame =
        f.w.verdict_from(src, IMSI, Level::Medium, None)
            .unwrap()
            .unwrap();
    f.w.step(30);
    let replays: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| f.w.node(i).rejected().replay)
        .collect();
    let alerts: Vec<usize> = f.all().iter().map(|&i| f.w.alerts(i).len()).collect();
    let inbox: Vec<usize> = f.all().iter().map(|&i| f.w.inbox(i).len()).collect();
    let pos = f.w.pos(src);
    f.w.inject_raw(pos, frame);
    f.w.step(1);
    for (k, &i) in f.all().iter().enumerate() {
        assert!(f.w.node(i).rejected().replay > replays[k], "index {i}");
        assert_eq!(f.w.alerts(i).len(), alerts[k], "index {i}: no new alert");
        assert_eq!(f.w.inbox(i).len(), inbox[k], "index {i}: no new inbound");
    }
}

#[test]
fn revoked_node_cut_off() {
    let a = auth();
    let mut f = fleet_with(
        &a,
        1,
        1,
        (0.0, 0.0),
        &[
            (1, Role::Full, (100.0, 0.0)),
            (2, Role::Full, (-100.0, 0.0)),
            (4, Role::Full, (0.0, 120.0)),
            (5, Role::Organiser, (0.0, -30.0)),
        ],
    );
    f.w.step(30);
    let (n4, org) = (f.i(4), f.i(5));
    f.w.send_from(
        org,
        Body::Revocation {
            target: 4,
            event_sig: Some(a.revocation_sig(4)),
        },
    )
    .unwrap();
    f.w.step(5);
    // Everyone, the organiser included: a sender applies its own revocation.
    let others: Vec<usize> = f.all();
    for &i in &others {
        assert!(
            f.w.inbox(i).contains(&Inbound::Revoked { node: 4 }),
            "index {i} learned the revocation"
        );
        assert!(f.w.node(i).is_revoked(4), "index {i}");
    }
    // 4 heard its own revocation and refuses to send.
    assert_eq!(
        f.w.verdict_from(n4, IMSI, Level::High, None),
        Err(SendError::Revoked)
    );
    // A compromised 4 that ignores it: its frames are refused everywhere.
    let now = f.w.now();
    let revoked: Vec<u32> = others
        .iter()
        .map(|&i| f.w.node(i).rejected().revoked)
        .collect();
    let bad = forge(
        4,
        counter_at(now) + 1_000,
        now,
        &Body::Verdict {
            kind: IMSI,
            level: Level::High,
            tag: None,
        },
    );
    let pos = f.w.pos(n4);
    f.w.inject_raw(pos, bad);
    for (k, &i) in others.iter().enumerate() {
        if i != n4 {
            assert!(f.w.node(i).rejected().revoked > revoked[k], "index {i}");
        }
    }
    // And a real verdict from 1 finds no second supporter.
    f.w.verdict_from(f.i(1), IMSI, Level::Medium, None)
        .unwrap()
        .unwrap();
    f.w.step(60);
    for &i in &others {
        assert!(!ever_group(f.w.alerts(i), IMSI), "index {i}");
        assert!(
            !f.w.inbox(i)
                .iter()
                .any(|x| matches!(x, Inbound::Verdict { node: 4, .. })),
            "index {i}"
        );
    }
}

/// The organiser's own device applies the revocation it sends (ruling 1):
/// the relayed echo is dropped as its own frame, so it can't learn it by
/// receipt.
#[test]
fn organiser_applies_own_revocation() {
    let a = auth();
    let mut f = fleet_with(
        &a,
        1,
        1,
        (0.0, 0.0),
        &[
            (4, Role::Full, (0.0, 120.0)),
            (5, Role::Organiser, (0.0, -30.0)),
        ],
    );
    f.w.step(30);
    let org = f.i(5);
    f.w.send_from(
        org,
        Body::Revocation {
            target: 4,
            event_sig: Some(a.revocation_sig(4)),
        },
    )
    .unwrap();
    f.w.step(5);
    assert!(f.w.node(org).is_revoked(4));
    assert!(f.w.inbox(org).contains(&Inbound::Revoked { node: 4 }));
    // Sent again (a re-broadcast): not new, so no second Revoked.
    f.w.send_from(
        org,
        Body::Revocation {
            target: 4,
            event_sig: Some(a.revocation_sig(4)),
        },
    )
    .unwrap();
    let n =
        f.w.inbox(org)
            .iter()
            .filter(|x| **x == Inbound::Revoked { node: 4 })
            .count();
    assert_eq!(n, 1);
    // A compromised 4 is refused there too, and can't corroborate.
    let now = f.w.now();
    let before = f.w.node(org).rejected().revoked;
    let bad = forge(
        4,
        counter_at(now) + 1_000,
        now,
        &Body::Verdict {
            kind: IMSI,
            level: Level::High,
            tag: None,
        },
    );
    let pos = f.w.pos(f.i(4));
    f.w.inject_raw(pos, bad);
    assert!(f.w.node(org).rejected().revoked > before);
    assert!(!ever_group(f.w.alerts(org), IMSI));
}

#[test]
fn expired_event_silent() {
    let expiry = START + 1800;
    let a = auth_until(expiry);
    let mut f = fleet_with(
        &a,
        1,
        1,
        (0.0, 0.0),
        &[
            (1, Role::Full, (100.0, 0.0)),
            (2, Role::Full, (-100.0, 0.0)),
        ],
    );
    f.w.step(30);
    let before_expiry = f.w.now();
    f.w.step(expiry - f.w.now() + 1);
    assert!(f.w.now() > expiry);
    assert_eq!(
        f.w.verdict_from(f.i(1), IMSI, Level::High, None),
        Err(SendError::Expired)
    );
    // Nothing is sent once the event is over: no roster, no check-ins.
    let air = f.w.airtime();
    f.w.step(1200);
    assert_eq!(f.w.airtime(), air);
    // A frame dated inside the event, heard after it: refused everywhere.
    let expired: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| f.w.node(i).rejected().expired)
        .collect();
    let inbox: Vec<usize> = f.all().iter().map(|&i| f.w.inbox(i).len()).collect();
    let late = forge(
        2,
        counter_at(before_expiry) + 5_000,
        before_expiry,
        &Body::Verdict {
            kind: IMSI,
            level: Level::High,
            tag: None,
        },
    );
    f.w.inject_raw((0.0, 50.0), late);
    for (k, &i) in f.all().iter().enumerate() {
        if i == f.i(2) {
            continue; // its own frame: dropped as an echo first
        }
        assert!(f.w.node(i).rejected().expired > expired[k], "index {i}");
        assert_eq!(f.w.inbox(i).len(), inbox[k], "index {i}");
    }
}

/// 1,000 hostile frames of every malformed kind from a rogue with no card.
fn hostile_set(w: &mut World, now: u32, known: &[u16], captured: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let rogue = NodeKey::from_seed([0xee; 32]);
    let verdict = Body::Verdict {
        kind: IMSI,
        level: Level::High,
        tag: None,
    };
    let mut out = Vec::new();
    for n in 0..1000u32 {
        let r = w.rand_u64();
        let pick = known[(r as usize >> 8) % known.len()];
        let counter = counter_at(now) + 10_000 + n;
        let sign = |node: u16, time: u32, body: &Body| {
            rogue
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
        };
        let f = match n % 10 {
            // Pure noise, 0..=255 bytes.
            0 | 1 => {
                let len = (r % 256) as usize;
                (0..len).map(|_| w.rand_u64() as u8).collect()
            }
            // A captured good frame with one byte flipped.
            2 => {
                let mut f = captured[n as usize % captured.len()].clone();
                let at = (r as usize) % f.len();
                f[at] ^= 1 << (r % 8);
                f
            }
            // A captured good frame, truncated.
            3 => {
                let f = &captured[n as usize % captured.len()];
                f[..(r as usize) % f.len()].to_vec()
            }
            // Wrong protocol version.
            4 => {
                let mut f = sign(pick, now, &verdict);
                f[0] = 2;
                f
            }
            // Signed by the rogue's key, claiming a known member.
            5 => sign(pick, now, &verdict),
            // Dated 6 minutes in the receivers' future.
            6 => sign(pick, now + 360, &verdict),
            // Dated before the event.
            7 => sign(pick, START - 10, &verdict),
            // A forged Roster card for a new node (bad event signature).
            8 => sign(
                HUB,
                now,
                &Body::Roster(Card {
                    pubkey: rogue.public(),
                    node: 900 + (n as u16 % 50),
                    role: Role::Organiser,
                    expiry: EXPIRY,
                    event_sig: [0x11; 64],
                }),
            ),
            // A sender nobody has a card for.
            _ => sign(700 + (n as u16 % 100), now, &verdict),
        };
        out.push(f);
    }
    out
}

#[test]
fn hostile_frames() {
    // The rogue at (1600,0) reaches the far members 1-3 only: it is out of
    // range of the hub (which relays everything) and of the organiser.
    let mut f = fleet(&[
        (1, Role::Full, (700.0, 0.0)),
        (2, Role::Light, (800.0, 100.0)),
        (3, Role::Full, (750.0, -100.0)),
        (5, Role::Organiser, (50.0, 0.0)),
    ]);
    f.w.step(30);
    let rogue_pos = (1600.0, 0.0);
    let near: Vec<usize> = [1u16, 2, 3].iter().map(|&n| f.i(n)).collect();
    for i in f.all() {
        assert_eq!(
            radio::in_range(rogue_pos, f.w.pos(i)),
            near.contains(&i),
            "geometry, index {i}"
        );
        assert!(
            !near.contains(&i) || !f.w.relaying(i),
            "near members are muted"
        );
    }
    let captured: Vec<Vec<u8>> = vec![
        f.w.verdict_from(f.i(1), IMSI, Level::Medium, None)
            .unwrap()
            .unwrap(),
        f.w.send_from(f.i(5), Body::Directive(Directive::Phrase(0)))
            .unwrap(),
        f.w.send_from(f.i(2), Body::Status { phrase: 1 }).unwrap(),
    ];
    let now = f.w.now();
    let frames = hostile_set(&mut f.w, now, &[1, 2, 3, 5, HUB], &captured);
    assert_eq!(frames.len(), 1000);
    let rej0: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| reject_total(f.w.node(i).rejected()))
        .collect();
    let dropped0: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| f.w.node(i).rejected().pending_dropped)
        .collect();
    let inbox0: Vec<usize> = f.all().iter().map(|&i| f.w.inbox(i).len()).collect();
    let alerts0: Vec<usize> = f.all().iter().map(|&i| f.w.alerts(i).len()).collect();
    for fr in frames {
        f.w.inject_raw(rogue_pos, fr);
    }
    for (k, &i) in f.all().iter().enumerate() {
        let r = f.w.node(i).rejected();
        let expect = if near.contains(&i) { 1000 } else { 0 };
        assert_eq!(reject_total(r) - rej0[k], expect, "index {i}: {r:?}");
        if !near.contains(&i) {
            assert_eq!(r.pending_dropped, dropped0[k], "index {i}");
        }
        assert_eq!(f.w.inbox(i).len(), inbox0[k], "index {i}: no Inbound");
        assert_eq!(f.w.alerts(i).len(), alerts0[k], "index {i}: no alert");
    }
    // The fleet still works afterwards.
    f.w.step(60);
    f.w.verdict_from(f.i(3), IMSI, Level::Medium, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    for &i in &near {
        let a = current_group(f.w.alerts(i), IMSI).expect("still corroborates");
        assert_eq!(a.units, 2);
    }
}

/// Companion to `hostile_frames` with the hub in range of the rogue, so
/// counts are not exact (the hub's radio repeats what it hears).
#[test]
fn hostile_frames_hub_in_range() {
    let mut f = fleet(&[
        (1, Role::Full, (100.0, 0.0)),
        (2, Role::Light, (-100.0, 0.0)),
        (3, Role::Full, (900.0, 0.0)),
        (5, Role::Organiser, (0.0, 50.0)),
    ]);
    f.w.step(30);
    let rogue_pos = (-300.0, 0.0);
    let far = f.i(3);
    assert!(radio::in_range(rogue_pos, f.w.pos(f.hub)));
    assert!(
        !radio::in_range(rogue_pos, f.w.pos(far)),
        "3 hears only relays"
    );
    let captured: Vec<Vec<u8>> = vec![
        f.w.verdict_from(f.i(1), IMSI, Level::Medium, None)
            .unwrap()
            .unwrap(),
        f.w.send_from(f.i(5), Body::Directive(Directive::Phrase(0)))
            .unwrap(),
    ];
    let now = f.w.now();
    let frames = hostile_set(&mut f.w, now, &[1, 2, 3, 5, HUB], &captured);
    let rej0: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| reject_total(f.w.node(i).rejected()))
        .collect();
    let inbox0: Vec<usize> = f.all().iter().map(|&i| f.w.inbox(i).len()).collect();
    let alerts0: Vec<usize> = f.all().iter().map(|&i| f.w.alerts(i).len()).collect();
    let log0 = f.w.air_log().len();
    let undecodable: Vec<bool> = frames.iter().map(|b| decode(b).is_err()).collect();
    for fr in &frames {
        f.w.inject_raw(rogue_pos, fr.clone());
    }
    for (k, &i) in f.all().iter().enumerate() {
        assert_eq!(f.w.inbox(i).len(), inbox0[k], "index {i}: no Inbound");
        assert_eq!(f.w.alerts(i).len(), alerts0[k], "index {i}: no alert");
        let grew = reject_total(f.w.node(i).rejected()) - rej0[k];
        if radio::in_range(rogue_pos, f.w.pos(i)) {
            assert!(grew >= 1000, "index {i}: {grew}");
        }
    }
    // Finding: the hub's radio repeats frames it cannot decode.
    let relayed_garbage = frames
        .iter()
        .zip(&undecodable)
        .filter(|(b, bad)| **bad && f.w.copies(far, b).contains(&Some(f.hub)))
        .count();
    println!(
        "hostile_frames_hub_in_range: {} of 1000 undecodable, hub relayed {} of them; \
         {} transmissions for 1000 injected; far member rejected {}",
        undecodable.iter().filter(|b| **b).count(),
        relayed_garbage,
        f.w.air_log().len() - log0,
        reject_total(f.w.node(far).rejected())
            - rej0[f.all().iter().position(|&i| i == far).unwrap()],
    );
    // The fleet still works afterwards.
    f.w.step(60);
    f.w.verdict_from(f.i(2), IMSI, Level::Medium, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    for i in f.all() {
        assert!(current_group(f.w.alerts(i), IMSI).is_some(), "index {i}");
    }
}

#[test]
fn area_outage_end_to_end() {
    let mut f = fleet(&[
        (1, Role::Full, (100.0, 0.0)),
        (2, Role::Light, (-100.0, 0.0)),
        (3, Role::Full, (0.0, 150.0)),
    ]);
    f.w.step(30);
    let lost = VerdictKind::ServiceLost;
    let (a, b) = (f.i(1), f.i(2));
    f.w.verdict_from(a, lost, Level::High, None)
        .unwrap()
        .unwrap();
    f.w.step(60);
    // One unit: only its wearer hears about it.
    assert!(
        f.w.alerts(a)
            .iter()
            .any(|x| x.audience == Audience::Wearer && x.kind == lost)
    );
    for i in f.all() {
        assert!(!ever_group(f.w.alerts(i), lost), "index {i}");
        if i != a {
            assert!(
                !f.w.alerts(i).iter().any(|x| x.kind == lost),
                "index {i}: not its wearer"
            );
        }
    }
    f.w.verdict_from(b, lost, Level::High, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    assert_corroborated(&f, lost, AlertLabel::AreaOutage, Strength::Strong);
}

/// R4 geometry: hub (0,0), organiser beside it, midway member at (300,0),
/// and the drifter walking (200,0) -> (1200,0) over 10 minutes.
struct Drift {
    f: Fleet,
    t_cross: u32,
    t_measured: Option<u32>,
    t_relay: Option<u32>,
}

const DRIFTER: u16 = 3;
const MIDWAY: u16 = 2;
const ORG: u16 = 5;

fn drift() -> Drift {
    let mut f = fleet(&[
        (MIDWAY, Role::Full, (300.0, 0.0)),
        (DRIFTER, Role::Light, (200.0, 0.0)),
        (ORG, Role::Organiser, (0.0, 30.0)),
    ]);
    // Settle: roster learned, a round of check-ins, no relays needed.
    f.w.step(120);
    let (mid, dr) = (f.i(MIDWAY), f.i(DRIFTER));
    assert!(!f.w.relaying(mid), "no relay while everyone is close");
    let hub_pos = f.w.pos(f.hub);
    let mut t_cross = None;
    let mut t_relay = None;
    let mut t_measured = None;
    for s in 0..=60u32 {
        let x = 200.0 + 1000.0 * s as f32 / 60.0;
        f.w.move_to(dr, (x, 0.0));
        if t_cross.is_none() && radio::snr_db(hub_pos, (x, 0.0)) < WEAK_SNR_DB as f32 {
            t_cross = Some(f.w.now());
        }
        for _ in 0..10 {
            f.w.step(1);
            let weak = f.w.hub_snr(dr).is_some_and(|x| x < WEAK_SNR_DB as f32);
            if t_measured.is_none() && weak {
                t_measured = Some(f.w.now());
            }
            if t_relay.is_none() && f.w.relaying(mid) {
                t_relay = Some(f.w.now());
            }
        }
    }
    Drift {
        f,
        t_cross: t_cross.expect("the drifter crosses -12 dB"),
        t_measured,
        t_relay,
    }
}

#[test]
fn drifting_node_gets_relay() {
    let Drift {
        mut f,
        t_cross,
        t_measured,
        t_relay,
    } = drift();
    let (mid, dr, org) = (f.i(MIDWAY), f.i(DRIFTER), f.i(ORG));
    let t_relay = t_relay.expect("the midway member relays");
    let t_measured = t_measured.expect("the drifter measures the weak hub");
    println!(
        "drift: crossed -12 dB at +{} s, drifter measured it at +{} s, relaying at +{} s",
        t_cross - T0,
        t_measured - T0,
        t_relay - T0
    );
    assert!(t_relay >= t_measured, "no relay before the drifter is weak");
    // R4: the drifter's hub SNR (what its check-in carries) falls below
    // -12 dB, and within one check-in interval the midway member relays.
    assert!(
        t_relay <= t_measured + 60,
        "relay within one check-in interval: measured {t_measured}, relay {t_relay}"
    );
    // The drifter samples the hub's SNR only when the hub transmits, so
    // against the geometric crossing the bound is two intervals.
    assert!(t_measured >= t_cross);
    assert!(
        t_relay <= t_cross + 2 * 60,
        "cross {t_cross}, relay {t_relay}"
    );
    // The drifter is now out of direct range of the hub and the organiser.
    let dpos = f.w.pos(dr);
    assert!(!radio::in_range(f.w.pos(f.hub), dpos));
    assert!(!radio::in_range(f.w.pos(org), dpos));
    assert!(radio::in_range(f.w.pos(mid), dpos));
    assert!(f.w.relaying(mid));
    let d = Directive::Text("regroup at the fountain".into());
    f.w.send_from(org, Body::Directive(d.clone())).unwrap();
    f.w.step(1);
    assert!(
        f.w.inbox(dr).iter().any(
            |x| matches!(x, Inbound::Directive { node: ORG, directive, .. } if *directive == d)
        ),
        "the directive reaches the drifter through the relay"
    );
}

#[test]
fn relay_expires() {
    let Drift { mut f, .. } = drift();
    let (mid, dr) = (f.i(MIDWAY), f.i(DRIFTER));
    assert!(f.w.relaying(mid));
    f.w.move_to(dr, (200.0, 0.0));
    let t_back = f.w.now();
    let bound = t_back + RELAY_MINUTES as u32 * 60 + 60;
    let mut t_off = None;
    while f.w.now() <= bound {
        f.w.step(1);
        if t_off.is_none() && !f.w.relaying(mid) {
            t_off = Some(f.w.now());
        }
    }
    let t_off = t_off.expect("relay switches off within RELAY_MINUTES + one interval");
    println!("relay off {} s after the drifter returned", t_off - t_back);
    // And it stays off.
    f.w.step(600);
    for i in f.members() {
        assert!(!f.w.relaying(i), "index {i}");
    }
}

/// M7: at the default 15-minute check-in, a weak member's relay is held
/// for a full hour with no gap, and lapses once the member recovers.
#[test]
fn relay_held_for_an_hour_at_default_checkin() {
    let mut f = fleet_with(
        &auth(),
        7,
        15,
        (0.0, 0.0),
        &[
            (1, Role::Full, (300.0, 0.0)),  // relay candidate, about -4 dB
            (2, Role::Light, (650.0, 0.0)), // weak, about -14 dB
        ],
    );
    let (mid, weak) = (f.i(1), f.i(2));
    let iv = 15 * 60;
    let bound = f.w.now() + 2 * iv;
    while !f.w.relaying(mid) {
        assert!(f.w.now() < bound, "no relay ordered within two intervals");
        f.w.step(1);
    }
    let t_on = f.w.now();
    for _ in 0..3600 {
        f.w.step(1);
        assert!(f.w.relaying(mid), "relay gap at +{} s", f.w.now() - t_on);
        // Not even a lapse renewed within the same second (on real radios
        // that is a gap of one round trip).
        assert_eq!(
            f.w.relay_lapses(mid),
            0,
            "order lapsed at +{} s",
            f.w.now() - t_on
        );
    }
    // Recovery: the member walks back towards the hub.
    f.w.move_to(weak, (200.0, 0.0));
    let t_back = f.w.now();
    // Hub transmission to sample (roster, at most ROSTER_MAX_SECS) + a
    // check-in + the rest of a 30-minute order.
    let bound = t_back + ROSTER_MAX_SECS + iv + 30 * 60;
    let mut t_off = None;
    while t_off.is_none() && f.w.now() <= bound {
        f.w.step(1);
        if !f.w.relaying(mid) {
            t_off = Some(f.w.now());
        }
    }
    let t_off = t_off.expect("the relay lapses after recovery");
    println!(
        "relay_held_for_an_hour: on at +{} s, off {} s after recovery",
        t_on - T0,
        t_off - t_back
    );
    f.w.step(3600);
    assert!(!f.w.relaying(mid), "and stays off");
}

#[test]
fn forged_relay_order_ignored() {
    let mut f = fleet(&[
        (1, Role::Full, (-100.0, 0.0)),
        (2, Role::Light, (100.0, 0.0)),
        (3, Role::Full, (0.0, 100.0)),
    ]);
    f.w.step(30);
    let now = f.w.now();
    let lt = f.i(2);
    let na: Vec<u32> = f
        .all()
        .iter()
        .map(|&i| f.w.node(i).rejected().not_allowed)
        .collect();
    let mut forged = Vec::new();
    for target in [1u16, 3] {
        let fr = forge(
            2,
            counter_at(now) + 1_000 + target as u32,
            now,
            &Body::RelayOrder {
                target,
                minutes: 15,
            },
        );
        forged.push(fr.clone());
        let pos = f.w.pos(lt);
        f.w.inject_raw(pos, fr);
    }
    f.w.step(5);
    for (k, &i) in f.all().iter().enumerate() {
        if i != lt {
            assert!(f.w.node(i).rejected().not_allowed >= na[k] + 2, "index {i}");
        }
        assert!(
            !f.w.inbox(i)
                .iter()
                .any(|x| matches!(x, Inbound::RelayOrder { .. })),
            "index {i}"
        );
    }
    for i in f.members() {
        assert!(!f.w.relaying(i), "index {i}: no relay from a forged order");
    }
    // Control: the same order from the hub does switch member 1 on.
    f.w.send_from(
        f.hub,
        Body::RelayOrder {
            target: 1,
            minutes: 15,
        },
    )
    .unwrap();
    f.w.step(1);
    assert!(f.w.relaying(f.i(1)));
}

/// M6: a unit that revokes itself, or hears its own revocation, stops
/// relaying even with an order still running.
#[test]
fn revoked_unit_stops_relaying() {
    let a = auth();
    let mut f = fleet_with(
        &a,
        1,
        1,
        (0.0, 0.0),
        &[
            (1, Role::Full, (-100.0, 0.0)),
            (2, Role::Full, (100.0, 0.0)),
            (5, Role::Organiser, (0.0, -30.0)),
        ],
    );
    f.w.step(30);
    let (n1, n2) = (f.i(1), f.i(2));
    for target in [1, 2] {
        f.w.send_from(
            f.hub,
            Body::RelayOrder {
                target,
                minutes: 15,
            },
        )
        .unwrap();
    }
    f.w.step(1);
    assert!(f.w.relaying(n1) && f.w.relaying(n2));
    // 1 revokes itself.
    f.w.revoke_self(n1).unwrap();
    assert!(!f.w.relaying(n1), "self-revoked: relay off at once");
    // 2 hears the organiser's revocation of it.
    f.w.send_from(
        f.i(5),
        Body::Revocation {
            target: 2,
            event_sig: Some(a.revocation_sig(2)),
        },
    )
    .unwrap();
    assert!(f.w.node(n2).is_revoked(2));
    assert!(!f.w.relaying(n2), "revoked by the organiser: relay off");
    // Neither comes back on before its order would have run out.
    f.w.step(600);
    assert!(!f.w.relaying(n1) && !f.w.relaying(n2));
}

#[test]
fn relayed_duplicate_counts_once() {
    // W is weak (-15 dB); R1 and R2 are the only good candidates; S and X
    // are middling (-8 dB) and stay muted.
    const W: u16 = 1;
    const R1: u16 = 2;
    const R2: u16 = 3;
    const S: u16 = 4;
    const X: u16 = 6;
    let mut f = fleet(&[
        (W, Role::Full, (700.0, 0.0)),
        (R1, Role::Full, (100.0, 0.0)),
        (R2, Role::Light, (0.0, 150.0)),
        (S, Role::Full, (-400.0, 0.0)),
        (X, Role::Full, (-380.0, 50.0)),
    ]);
    f.w.step(150);
    let (r1, r2, s, x) = (f.i(R1), f.i(R2), f.i(S), f.i(X));
    assert!(f.w.relaying(r1) && f.w.relaying(r2), "two relays active");
    assert!(!f.w.relaying(s) && !f.w.relaying(x));
    let replay0 = f.w.node(x).rejected().replay;
    let frame =
        f.w.verdict_from(s, IMSI, Level::High, None)
            .unwrap()
            .unwrap();
    f.w.step(1);
    let via = f.w.copies(x, &frame);
    assert!(via.contains(&Some(s)), "heard directly: {via:?}");
    assert!(
        via.contains(&Some(r1)) && via.contains(&Some(r2)),
        "via both relays: {via:?}"
    );
    assert_eq!(
        f.w.node(x).rejected().replay - replay0,
        via.len() as u32 - 1,
        "every extra copy is dropped as a replay"
    );
    let from_s =
        f.w.inbox(x)
            .iter()
            .filter(|v| matches!(v, Inbound::Verdict { node: S, .. }))
            .count();
    assert_eq!(from_s, 1);
    let a = current_group(f.w.alerts(x), IMSI).unwrap();
    assert_eq!((a.label, a.units), (AlertLabel::StrongSingle, 1));
    // A second unit makes exactly two, however many copies were heard.
    f.w.verdict_from(x, IMSI, Level::High, None)
        .unwrap()
        .unwrap();
    f.w.step(1);
    for i in [x, s, r1, r2] {
        let a = current_group(f.w.alerts(i), IMSI).unwrap();
        assert_eq!(
            (a.label, a.units),
            (AlertLabel::Corroborated, 2),
            "index {i}"
        );
    }
}

/// The 30-minute script: 8 members (7 field units + organiser), check-ins
/// every 15 minutes, 3 verdicts and 2 directives. Member 7 is weak, so the
/// muted run orders relays on demand.
fn airtime_script(all_relay: bool) -> (Airtime, World) {
    let mut f = fleet_with(
        &auth(),
        42,
        15,
        (0.0, 0.0),
        &[
            (1, Role::Full, (200.0, 0.0)),
            (2, Role::Full, (0.0, 250.0)),
            (3, Role::Light, (-300.0, 0.0)),
            (4, Role::Light, (0.0, -350.0)),
            (5, Role::Full, (400.0, 300.0)),
            (6, Role::Light, (-450.0, -200.0)),
            (7, Role::Full, (650.0, 0.0)),
            (9, Role::Organiser, (20.0, 20.0)),
        ],
    );
    if all_relay {
        for i in f.members() {
            f.w.force_relay(i, true);
        }
    }
    let start = f.w.airtime();
    assert_eq!(start, Airtime::default());
    let org = f.i(9);
    let t = |m: u32| T0 + m * 60;
    let script: Vec<(u32, u8)> = vec![(5, 1), (9, 2), (12, 3), (15, 0), (25, 0)];
    let mut d = 0u8;
    for (m, who) in script {
        f.w.step(t(m) - f.w.now());
        if who == 0 {
            f.w.send_from(org, Body::Directive(Directive::Point(d)))
                .unwrap();
            d += 1;
        } else {
            f.w.verdict_from(f.i(who as u16), IMSI, Level::Medium, None)
                .unwrap()
                .unwrap();
        }
    }
    f.w.step(t(30) - f.w.now());
    (f.w.airtime(), f.w)
}

#[test]
fn quiet_mesh_airtime() {
    let (muted, w) = airtime_script(false);
    let (all, wa) = airtime_script(true);
    println!(
        "quiet_mesh_airtime: muted+on-demand {} tx / {} B; all-relay {} tx / {} B",
        muted.transmissions, muted.bytes, all.transmissions, all.bytes
    );
    // Transmissions per frame type (0x01 Verdict .. 0x08 RelayOrder).
    for (name, w) in [("muted", &w), ("all-relay", &wa)] {
        let mut by: BTreeMap<u8, u32> = BTreeMap::new();
        for f in w.air_log() {
            *by.entry(f[1]).or_default() += 1;
        }
        println!("quiet_mesh_airtime: {name} by frame type {by:?}");
    }
    // On-demand relays did happen in the muted run.
    assert!((0..w.len()).any(|i| w.ever_relayed(i) && !w.is_hub(i)));
    assert!(muted.transmissions < all.transmissions);
    assert!(muted.bytes < all.bytes);
}

#[test]
fn no_position_on_air() {
    let (air, w) = airtime_script(false);
    assert_eq!(w.air_log().len() as u64, air.transmissions);
    for f in w.air_log() {
        assert!(f.len() <= MAX_FRAME);
        let fr = decode(f).expect("every transmitted frame is a protocol frame");
        // Exhaustive over body variants. No structured field carries a
        // position; Directive text is free text, so organisers must not type
        // locations (README).
        match fr.body {
            Body::Verdict { .. }
            | Body::Status { .. }
            | Body::CheckIn { .. }
            | Body::Directive(_)
            | Body::Roster(_)
            | Body::Revocation { .. }
            | Body::HubHealth { .. }
            | Body::RelayOrder { .. } => {}
        }
    }
}

/// Distinct send times of frames originated by `node` matching `pick`, in
/// order (relayed copies and same-second bursts collapse to one time).
fn send_times(w: &World, node: u16, pick: impl Fn(&Body) -> bool) -> Vec<u32> {
    let mut times: Vec<u32> = w
        .air_log()
        .iter()
        .filter_map(|b| decode(b).ok())
        .filter(|f| f.header.node == node && pick(&f.body))
        .map(|f| f.header.time)
        .collect();
    times.sort();
    times.dedup();
    times
}

fn gaps(times: &[u32]) -> Vec<u32> {
    times.windows(2).map(|p| p[1] - p[0]).collect()
}

#[test]
fn broadcast_gaps_are_jittered() {
    // Fixed periods fingerprint a node by delta time even when its frames
    // are unreadable: roster and check-in gaps are random.
    let iv_min = 15u8;
    let iv = iv_min as u32 * 60;
    let mut f = fleet_with(
        &auth(),
        7,
        iv_min,
        (0.0, 0.0),
        &[
            (1, Role::Full, (200.0, 0.0)),
            (2, Role::Light, (0.0, 250.0)),
        ],
    );
    f.w.step(3 * 3600);
    let rosters = gaps(&send_times(&f.w, HUB, |b| matches!(b, Body::Roster(_))));
    println!("broadcast_gaps_are_jittered: roster gaps {rosters:?}");
    assert!(rosters.len() >= 3 * 3600 / ROSTER_MAX_SECS as usize - 1);
    assert!(
        rosters
            .iter()
            .all(|g| (ROSTER_MIN_SECS..=ROSTER_MAX_SECS).contains(g)),
        "{rosters:?}"
    );
    let distinct: std::collections::BTreeSet<_> = rosters.iter().collect();
    assert!(distinct.len() >= 3, "roster gaps {rosters:?}");

    let checkins = gaps(&send_times(&f.w, 1, |b| matches!(b, Body::CheckIn { .. })));
    println!("broadcast_gaps_are_jittered: check-in gaps {checkins:?}");
    assert!(checkins.len() >= 3 * 3600 / iv as usize - 1);
    assert!(
        checkins.iter().all(|g| (iv / 2..=iv).contains(g)),
        "{checkins:?}"
    );
    let distinct: std::collections::BTreeSet<_> = checkins.iter().collect();
    assert!(distinct.len() >= 3, "check-in gaps {checkins:?}");
}

#[test]
fn pending_frame_waits_out_a_long_roster_gap() {
    // A unit that joins just after a roster hears a verdict from a member it
    // has no card for; the card arrives with the next roster up to
    // ROSTER_MAX_SECS later, and the verdict is released then.
    let a = auth();
    let (kb, ka) = (kit(&a, 1, Role::Full, 15), kit(&a, 2, Role::Light, 15));
    let mut w = World::new(3);
    w.set_clock(T0);
    let hub = w.add_hub(
        kit(&a, HUB, Role::Hub, 15),
        (0.0, 0.0),
        vec![kb.card.clone(), ka.card.clone()],
    );
    let b = w.add(kb, (100.0, 0.0), false);
    // Find a roster gap of at least 850 s and stop 850 s before its end.
    let lead = 850;
    let mut last = w.next_roster(hub).unwrap();
    let mut found = false;
    while w.now() < EXPIRY - 2 * 3600 {
        w.step(1);
        let next = w.next_roster(hub).unwrap();
        if next != last {
            last = next;
            if next - w.now() >= lead {
                found = true;
                break;
            }
        }
    }
    assert!(found, "no roster gap of {lead} s or more");
    let roster_at = w.next_roster(hub).unwrap();
    w.step(roster_at - lead - w.now());
    let late = w.add(ka, (0.0, 100.0), false);
    w.verdict_from(b, IMSI, Level::High, None).unwrap().unwrap();
    assert_eq!(
        w.node(late).rejected().unknown_sender,
        1,
        "the verdict waits"
    );
    assert!(
        !w.inbox(late)
            .iter()
            .any(|i| matches!(i, Inbound::Verdict { .. }))
    );
    w.step(roster_at - w.now());
    let inbox = w.inbox(late);
    assert!(
        inbox.contains(&Inbound::CardLearned {
            node: 1,
            role: Role::Full
        }),
        "{inbox:?}"
    );
    assert!(
        inbox
            .iter()
            .any(|i| matches!(i, Inbound::Verdict { node: 1, .. })),
        "verdict not released after {lead} s: {inbox:?}"
    );
    assert_eq!(w.node(late).rejected().pending_dropped, 0);
}
