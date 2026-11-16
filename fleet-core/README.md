# fleet-core

Transport-neutral protocol library for the private Rayhunter field fleet (spec: `SPEC-fleet-part3.md`).
`no_std` + `alloc`. It never touches a radio, a clock or a file: the caller passes in bytes and
the time. The simulator in `../fleet-sim` runs it end to end. Phase 3a only; no radio adapter yet.

## Cheat sheet

### Frame layout (all integers big-endian)

| Bytes | Field |
|---|---|
| 1 | version (`1`) |
| 1 | type |
| 2 | node number (never `0`) |
| 4 | counter |
| 4 | time (seconds, the sender's clock) |
| 0..=108 | body |
| 64 | Ed25519 signature |

Whole frame at most `MAX_FRAME` = 184 bytes. The signature covers `"RHF1" || event_id(8) || version..end of body`.
The event ID is not sent; a frame from another event simply fails verification.

### Message type x who may send it

| Type | Name | Body | Full | Light | Messenger | Organiser | Hub |
|---|---|---|---|---|---|---|---|
| `0x01` | Verdict | kind, level, flags, [tag 8] | yes | yes, no tag, no TowerFlood | no | no | no |
| `0x02` | Status | phrase | yes | yes | yes | yes | yes |
| `0x03` | CheckIn | hub_snr (i8) | yes | yes | yes | yes | yes |
| `0x04` | Directive | phrase / point / text 1..=96 B | no | no | no | yes | no |
| `0x05` | Roster | one 103 B card | no | no | no | no | yes |
| `0x06` | Revocation | target, [event_sig 64] | self, or any with event sig | self, or any with event sig | self, or any with event sig | self, or any with event sig | self, or any with event sig |
| `0x07` | HubHealth | code, subject, value | no | no | no | no | yes |
| `0x08` | RelayOrder | target, minutes 1..=60 | no | no | no | no | yes |

- Revocation: any node may revoke itself; a Revocation of another node needs an event-key signature in the body, and
  then anyone may carry it.
- Status phrases and Directive phrases/points must be inside the kit's tables (index < table length).
- Roles: `1` Full, `2` Light, `3` Messenger, `4` Organiser, `5` Hub. Levels: `1` Low, `2` Medium, `3` High.
- Any unknown version, type, code, role, level, flag bit or directive subtype is a decode error.
  Directive text, kit phrases and kit points must be UTF-8 with no control characters and none of the bidi/invisible
  format characters U+061C, U+200B-U+200F, U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF
  (`wire::forbidden_char`, shared by wire and kit).

### Verdict kinds

| Code | Kind | Rayhunter key (stable `AnalyzerMetadata.key`) |
|---|---|---|
| `0x01` | ImsiRequested | `imsi_requested` |
| `0x02` | RedirectDowngrade2g | `connection_redirect_2g_downgrade` |
| `0x03` | Sib67Downgrade | `lte_sib6_and_7_downgrade` |
| `0x04` | NullCipher | `null_cipher` |
| `0x05` | NasNullCipher | `nas_null_cipher` |
| `0x06` | IncompleteSib | `incomplete_sib` |
| `0x07` | NoNasMessages | `no_nas_messages` |
| `0x08` | Diagnostic | `diagnostic_analyzer` |
| `0x0F` | Test | `test_analyzer` (test channel only) |
| `0x20` | ServiceLost | none; spec 11.1 network kind |
| `0x21` | Downgraded | none; spec 11.1 |
| `0x22` | TowersGone | none; spec 11.1 |
| `0x30` | TowerFlood | none; spec 5, Full nodes only |

Network kinds (`0x2x`) never carry a tag: `send_verdict` strips it for every role, and a received tagged one is
refused as `not_allowed`. Informational is never sent. HubHealth codes: `1` UnitLost,
`2` BatteryLow, `3` NodeRevoked.

### Constants (`src/consts.rs`)

| Name | Value | Meaning |
|---|---|---|
| `MAX_FRAME` | 184 | whole frame, bytes |
| `HEADER_LEN` / `SIG_LEN` / `MAX_BODY` | 12 / 64 / 108 | |
| `WINDOW` | 600 s | corroboration window for raising an alert; exactly 600 s old no longer counts |
| `WITHDRAW_GRACE` | 300 s (= `FUTURE_SKEW`) | an alert already raised keeps a supporter until 900 s old |
| `VERDICT_INTERVAL` | 600 s | one verdict per kind per sender; receivers drop one closer than 570 s (`rate_limited`) |
| `FUTURE_SKEW` | 300 s | frames dated further ahead are rejected |
| `MAX_AGE` | 900 s | frames dated further back at receipt are `stale` (not Roster or Revocation) |
| `REPLAY_WINDOW` | 64 | counters behind the highest seen that still pass (once each) |
| `COUNTER_PER_SEC` | 1 | counter starts at `(now - event_start)`, +1 per frame: 64 s of reordering passes |
| `CHECKIN_MINUTES_MAX` | 30 | kit check-in interval is 1..=30 min (so a 60-min order can be renewed) |
| `PENDING_MAX` / `PENDING_TTL` | 16 / 900 s | frames from senders with no card yet; `PENDING_TTL >= ROSTER_MAX_SECS` is a compile-time assert |
| `ROSTER_MIN_SECS` / `ROSTER_MAX_SECS` | 300 / 900 s | roster broadcast gap, uniform random between them (`schedule::roster_gap`) |
| `TEXT_MAX` | 96 | directive text bytes |
| `KIT_MAX` | 1024 | bytes |
| `PHRASES_MAX` / `PHRASE_LEN_MAX` | 32 / 40 | empty phrases are rejected |
| `POINTS_MAX` / `POINT_LEN_MAX` | 16 / 24 | empty points are rejected |
| `TABLES_BYTES_MAX` | 400 | phrase + point text bytes together |
| `RELAY_MINUTES` | 15 | minimum order length |
| `RELAYS_MAX` | 2 | relays per weak member |
| `WEAK_SNR_DB` / `GOOD_SNR_DB` | -12 / -6 | weak below -12; relay candidates at -6 or better |
| `MISSED_CHECKINS` | 2 | silent this many intervals = weak |
| `GIVE_UP_CHECKINS` | 6 | silent longer = no more relays until it checks in |
| `SNR_UNKNOWN` | -128 | check-in byte when the member has not heard the hub |
| `TAG_LEN` | 8 | tower tag bytes |
| `CARD_LEN` | 103 | card bytes |

Signing prefixes (never sent): `RHF1` frame, `RHC1` card, `RHK1` kit, `RHR1` revocation, `RHT1` tower tag.

### Alert tiers (`corroborate.rs`)

| Rule | Label | Audience | Strength |
|---|---|---|---|
| This device's own verdict | `Own` | Wearer only | Strong if Full, else Weaker |
| 2+ distinct units, same kind (and same tag if tagged), within 600 s | `Corroborated` | Group | Strong if any Full among them, else Weaker |
| One Full unit, level High | `StrongSingle` | Group | Strong |
| One Full unit, TowerFlood (any level) | `StrongSingle` | Group | Strong |
| 2+ units, ServiceLost | `AreaOutage` | Group | as Corroborated |
| 2+ units, Downgraded | `AreaDowngrade` | Group | as Corroborated |
| 2+ units, TowersGone | `TowersGone` | Group | as Corroborated |
| One unit alone, network kind | `Own` | Wearer only | |
| One Light unit alone (any level) | none | none | |

- Every device runs the rule itself; the hub is not needed. Its own verdict counts as one unit.
- Alert key = kind + tag. Network kinds always use tag `None`. An untagged verdict joins every tagged group of its kind.
- A revoked node's support is removed and the alert is withdrawn if fewer than 2 remain.
- Raising needs supporters under 600 s old. Once raised, an alert keeps a supporter until it is 900 s old
  (`WINDOW + WITHDRAW_GRACE`) and is withdrawn only when support, counted that way, falls below what its label needs
  (`expire(now)`). Without the grace a catcher that stays put flapped every 10 minutes.
- The grace only keeps or lowers an alert, never raises it: units, strength and label rise above what was last
  emitted only as far as supporters under 600 s old carry them (a 700 s-old verdict cannot turn StrongSingle into
  Corroborated, nor Weaker into Strong). A Weaker group that collapses to one held unit is withdrawn, not turned into
  a Strong StrongSingle, unless that unit (Full, High or TowerFlood) is fresh.
- One entry per (node, kind): a node's newest verdict of a kind replaces its older one, tag and all. The same node
  twice counts once, and a node supports at most one tag group per kind.
- `Audience::Organisers` (hub health) exists but nothing in the core emits it: HubHealth arrives as `Inbound::HubHealth` and the app must show it to organisers only (3d).

### Timing (`src/schedule.rs`)

| What | When | Why |
|---|---|---|
| Hub roster broadcast | every 5-15 min, uniform random (`roster_gap(rand)`) | a fixed period fingerprints the hub by delta time between transmissions, even unread |
| Member check-in | random in [1/2, 1] x the kit's interval (`checkin_gap(secs, rand)`) | same; never longer than the interval, so the planner's missed-check-in, give-up and renewal arithmetic is unchanged |
| Randomness | supplied by the caller, from the OS RNG on a real device | the core has no RNG; never pass a counter or a clock |
| Pending frames | wait up to 15 min (`PENDING_TTL`) for the sender's card | covers the longest roster gap; `MAX_AGE` is checked at receipt, so a frame released up to 900 s later is still delivered. A released verdict only helps raise an alert while under `WINDOW` (600 s) by its own time and is dropped by the Corroborator at 900 s, so a late joiner's verdicts older than that are effectively lost (accepted) |

- Released Inbounds may be up to about 1800 s old by their own timestamp (`MAX_AGE` + `PENDING_TTL`): apps must show a
  Status or Directive `time` rather than treat it as current, and a released CheckIn's SNR becomes the member's first
  reading in the planner.
- Cost: check-ins average about 3/4 of the interval, so roughly a third more check-in frames (`quiet_mesh_airtime`
  muted: CheckIn 48 -> 66).
- Residual, not fixed (3b question): a roster is still sent as a back-to-back burst of one frame per card, so the burst
  length reveals the member count.

### Relay rule in five lines

1. Members never rebroadcast. They send a check-in at most every `checkin_minutes` (from the kit; random in [1/2, 1] x that) carrying their last SNR from the hub.
2. The hub's `RelayPlanner` marks a member weak if its SNR < -12, the SNR is unknown, or it has been silent more than 2 intervals (measured from first sight if it never checked in).
3. For each weak member it orders up to 2 members (SNR >= -6, heard within an interval, never the weak one, a Hub or a revoked node; already-relaying first, then best SNR, then lowest node) to relay.
4. An order lasts max(15 min, 2 x check-in interval), capped at 60. It is renewed in its last interval once at least one interval old. Call `plan()` when `due()` is true (a check-in since the last plan, or an interval passed).
5. A member's `RelayState` turns relaying on when an order for it arrives (ignored if the order's frame time + minutes has already passed) and off again by itself at that time; a failed switch-off is retried. `stop()` turns it off for good when the unit is revoked. A member silent over 6 intervals is dropped from planning.

The planner uses the hub's own receive time for check-ins, not the frame time.

### Node behaviours worth remembering

- Own echoed frames (a relay repeating your frame) are dropped.
- Frames other than Roster and Revocation dated more than `MAX_AGE` (900 s) before `now` are refused as `stale` at
  receipt (frames released from the pending queue were checked when they arrived).
- A Verdict closer than 570 s (by the sender's clock, either direction) to that sender's last accepted Verdict of
  the same kind is refused as `rate_limited`, after the replay check.
- Counters are time-based at 1 per second. A unit that reboots within a few seconds of a burst (for example the hub
  just after a roster broadcast) reuses counters already seen, so its first frames are briefly dropped as replays.
- `Node::send` of a Revocation applies it locally (`last_send_revoked()` says which target). Feed `Inbound::Revoked` to your `Corroborator` and `RelayPlanner` yourself.
- `add_card(card, now)` returns `CardLearned` for a newly learned card, then the Inbounds released from the pending
  queue; nothing for an identical card or a revoked node. Feed it to the planner (the sim does).
- A known node's card is never replaced by a different key (counted as a signature rejection); an identical card is a no-op; a revoked node stays revoked.
- The pending queue dedupes: the same frame heard through several relays takes one slot.
- `send_verdict` enforces 1 per kind per 600 s and strips the tag for Light nodes and for network kinds; plain
  `send` does not rate-limit.
- `Debug` on a `Kit` redacts the device seed and tag secret.
- Cards and the kit are clamped to the event expiry; after expiry nothing is accepted or sent.

Reject counters (`Node::rejected()`): `wire`, `signature`, `unknown_sender`, `not_allowed`, `replay`, `future`,
`expired`, `revoked`, `pending_dropped`, `rate_limited`, `stale`. Counts only, never frame bytes.

### What never goes on the air

- Cell IDs, PLMN, TAC, ECI, PCI, EARFCN. The only tower data is the 8-byte HMAC tower tag (Full nodes only).
- Position of any kind. No structured field carries one, but Directive text is free text and can: organisers must not
  type locations (use the kit's points table). `no_position_on_air` checks every transmitted frame decodes.
- Names. Nothing in the core stores one; node keys are throwaway per event.
- The event key. It stays on the organiser device; the hub holds its own key and public cards.
- The kit, the device seed and the tag secret. Kits go in person (NFC/USB), never over the mesh.
- Raw captures or analyser detail. Only a kind, a level and an optional tag.

## Running things

| What | Command (from the repo root `wt-reveal`) |
|---|---|
| Core tests | `cd fleet-core && cargo test` |
| no_std build check | `cd fleet-core && ~/.cargo/bin/cargo +1.98.0 build --target thumbv7em-none-eabihf --no-default-features` |
| Simulator, all scenarios | `cd fleet-sim && cargo test` |
| Airtime numbers | `cd fleet-sim && cargo test -- --nocapture quiet_mesh_airtime` |
| Hostile-frame / relay finding | `cd fleet-sim && cargo test -- --nocapture hostile_frames_hub_in_range` |

One-time setup for the no_std check: `~/.cargo/bin/rustup target add thumbv7em-none-eabihf --toolchain 1.98.0`.
Format only files you changed: `rustfmt --edition 2024 <file>`. Never `cargo fmt` in the repo root.

Simulator scenarios (`fleet-sim/tests/scenarios.rs`): `corroborated_alert_end_to_end`,
`light_only_weaker_end_to_end`, `hub_off_alerts_continue`, `replayed_frame_rejected`, `revoked_node_cut_off`,
`organiser_applies_own_revocation`, `expired_event_silent`, `hostile_frames`, `hostile_frames_hub_in_range`,
`area_outage_end_to_end`, `drifting_node_gets_relay`, `relay_expires`, `relay_held_for_an_hour_at_default_checkin`,
`forged_relay_order_ignored`, `revoked_unit_stops_relaying`, `relayed_duplicate_counts_once`, `quiet_mesh_airtime`,
`no_position_on_air`, `broadcast_gaps_are_jittered`, `pending_frame_waits_out_a_long_roster_gap`.

## Open for 3b

| Question | State |
|---|---|
| `MAX_FRAME` 184 vs the real radios | 184 was chosen to fit under both Meshtastic's and MeshCore's payloads, but not measured against real headers. Check after each layer's headers and encryption overhead (spec 13, question f). The 64-byte signature and 12-byte header are fixed, so any shrink means a smaller body or a wire-format change. |
| Radio adapter | None yet. Implement `transport::Transport` (`send`, `set_relay`) for Meshtastic or MeshCore (spec 13). Apply `transport::check_len` in `send`. Not yet decided which. |
| Relays repeat undecodable frames | The sim's relay (modelled on managed flooding) rebroadcasts anything it hears: 1,000 injected hostile frames (406 undecodable) caused 2,886 transmissions, and the hub repeated all 406 undecodable ones. Relaying only frames that verify needs our own relay layer, not stock rebroadcast. Hostile traffic is amplified by every relay. |
| Toggling rebroadcast without a restart | Unanswered. `Transport::set_relay` assumes stock firmware can switch rebroadcast on and off live (spec 12 spike question). If it cannot, relaying must be done by our own layer, which also solves the row above. |
| Airtime baseline (`quiet_mesh_airtime`) | 30-minute script, 8 members, 15-minute check-ins, 3 verdicts, 2 directives, one weak member. Muted members + on-demand relays: 119 transmissions / 13,799 bytes. Everyone relaying: 468 transmissions / 60,966 bytes. By frame type (muted): Verdict 8, CheckIn 48, Directive 6, Roster 45, RelayOrder 12. All-relay: Verdict 27, CheckIn 144, Directive 18, Roster 243, RelayOrder 36. About 4x fewer transmissions and 4.4x fewer bytes. Re-measured after the final-review fixes: unchanged. After randomised timing (rosters 5-15 min, check-ins [1/2, 1] x interval): muted 137 / 15,185 B (CheckIn 48 -> 66, Roster still 45), all-relay 513 / 64,431 B (CheckIn 189); about 3.7x fewer transmissions, 4.2x fewer bytes. Simulated only; real range and airtime are for 3e. |
| Roster traffic | Roster is the biggest single type in both runs (45 of 137 muted). One card per frame; check whether batching or slower repeats are needed before 3c. The back-to-back burst of one frame per card also reveals the member count, even with randomised gaps. |
| Hub health to organisers only | The core delivers HubHealth to everyone; filter by role in the app (3d). |
