# Rayhunter archive (Home Assistant add-on)

Pulls the Rayhunter captures off the M2100 every 15 minutes, keeps them on the Yellow, and only then
deletes them from the unit. Reports health to Home Assistant over MQTT.

`<yellow>` below is the Yellow's LAN address (192.0.2.20 on the bench).

## Cheat sheet

| I want to... | Do this |
|---|---|
| Use the owner page | HA sidebar, **Sentinel** (the add-on's Ingress panel; a tap-to-open link from the phone notification is pending, added once the companion-app notify service is confirmed on the Yellow). Sections: status (what is active now, whether the unit still sees it: "no sign since HH:MM", or "live: unknown" if the unit cannot be reached or is not recording in Fixed: the live view checks nothing in Mobile); timeline of the alert's findings; follow-up box with presets (false alarm, watching, phones off, all clear) that fill the text for you to edit; the Sent log (what went on air and any override); and the Rayhunter UI itself, read-only, under `/rayhunter/`. Nothing goes on air from tapping a preset: only an explicit Send posts the final text. **All clear** unlocks once no unit has seen the trigger for `all_clear_hours` (default 3 h); before that, tick "send anyway" (every override is logged). False alarm and All clear close the alert and change nothing else (no tower learned, no check muted). **Practice:** with no open alert, a TEST alert that closed less than 30 min ago (`test`, from `live_test_alert`) is the page's target, labelled TEST; follow-ups to it really go on air, marked "TEST: " (added unless the text already starts with TEST; the 200-byte limit counts it), All clear has the same gate and override log as a real alert (a TEST alert is last seen when it opens, so practising All clear needs "send anyway"), and a follow-up never closes it again. Follow-up text is checked first (see Security properties). |
| Build the binary | `./build.sh` (needs Docker). Prints `ARM aarch64, statically linked` and a sha256. Output: `addon/m2100-archive` and `addon/m2100-decoder.wasm` (not committed; both must be installed together, the binary refuses any other guest) |
| Install on the Yellow | Copy `config.yaml`, `Dockerfile`, the built `m2100-archive` and `m2100-decoder.wasm` from `addon/` into the local apps folder: `/mnt/data/supervisor/apps/local/rayhunter_archive/` from the host shell (`ssh -p 22222 root@<yellow>`; newer HA calls add-ons "apps"), or the `addons` Samba share. Then `ha store reload`, `ha apps install local_rayhunter_archive`. Paste the token from `pair` into its Configuration in HA, then Start. After changing files, bump `version` in config.yaml and `ha apps rebuild local_rayhunter_archive`. |
| Pair with the unit | Read the token on the M2100 at `/data/rayhunter/.api_token` (64 hex chars). Paste it into the add-on option `device_token`, then restart the add-on. |
| Change the unit's address | Add-on option `device_url` (default `http://192.168.1.1:8080`), then restart. |
| See what it is doing | Add-on Log tab (`RUST_LOG=info`). |
| Change when All clear unlocks | Add-on option `all_clear_hours` (hours, 1..=24, default 3; out of range is clamped with a log warning), then restart. The owner page's All clear stays locked until no unit has seen the trigger for that long; "send anyway" overrides it and is logged. An unknown live view (unit unreachable, or recording in a profile other than Fixed) never unlocks it. |
| Turn on the alert summary | Add-on options `summary_api_key` (an Anthropic API key; **unset = off**, the default) and optionally `summary_model` (default `claude-opus-5-5`; it must be a model that supports server-side fallback, because every request sends `fallbacks: "default"`; others may be refused by the API and show "Unexpected reply from the API."), then restart. A **Summary** button appears under "Look closer" while an alert is the page's target. Tap it: a short plain-language read of the evidence, how unusual it is against the baseline, and which follow-up fits. Advice only ("Advice only. You decide what to send."): it never sends anything and never fills the follow-up box. The page shows the tokens used so far. See "Alert summary (optional)". |
| Force "go to Fixed" | Press the "Rayhunter: go to Fixed" button entity; the "Last Fixed request" sensor shows the result. |
| Find the files | Captures `/data/archive/{name}-{start}.qmdl.gz` and `{name}-{start}.ndjson` (`{start}` = unix seconds; a `-2`, `-3`... suffix if two share a name and second); bad-hash and unverified copies `/data/archive/mismatch/`; index `/data/index.sqlite` (column `file` is the name a capture is stored under) |
| Is it backed up? | Index yes. The archive is excluded from HA backups (it is big) via `backup_exclude: [archive/*, archive/*/*, cwasm-cache/*]` (relative patterns, matched against the Supervisor's host-side path). |
| What gets decoded | Every archived capture, once, at most 3 per 15-minute cycle (so a backlog clears over a few hours), after the pulls and deletes. Only the verified archive copy is decoded, inside a wasmtime sandbox (512 MB, 120 s, no files, no network). Each decode is then judged against the profile's baseline (see Check ids below); findings are stored; notify-level ones are also sent to HA as events (see Notifications). |
| Where decode results live | Table `decodes` in `/data/index.sqlite` (one row per capture, `status` = `ok` / `decoder_failure` / `archive_corrupt` / `archive_missing`, plus `profile` = `fixed` or `mobile`, the counts, `decoder_hash`, and a short `detail` for failures). Compiled-module cache: `/data/cwasm-cache` (excluded from backups; files for an older guest or wasmtime are deleted at start-up). |
| Is decoding off? | Log tab at start-up: `decoder ready (guest <sha256>)` = on; `decoding is off: ...` = off (guest file `/usr/local/share/m2100-archive/m2100-decoder.wasm` missing, or its hash is not the one this binary was built with). Pulling and archiving carry on either way. The "Decoder unavailable" sensor is ON when it is off. In the index: `SELECT COUNT(*) FROM captures c WHERE file IS NOT NULL AND NOT EXISTS (SELECT 1 FROM decodes d WHERE d.device=c.device AND d.name=c.name AND d.start=c.start)` = captures still waiting. |
| A capture shows `decoder_failure` | It crashed, timed out, printed output that broke the schema, or hit a safety cap (`detail` starts `capped:`: a decompression bomb or event flood, so its counts are partial); it is recorded once with the counts seen before that and not retried. `detail` says why. |
| Which profile was used | The unit's `GET /api/m2100/capture-profiles`, by capture name; `mixed` or missing = `mobile`. If the unit cannot be asked, the capture waits up to 4 more cycles, then is decoded as `mobile`. |
| Get told about a finding | A notify-level finding becomes one MQTT event (entity "Rayhunter finding", topic `rayhunter_archive/unit1/finding`, never retained). Attributes: `event_type` (the check id), `label`, `capture` (name, or `?` if it is not 1-12 digits), `profile`, `switched`, `count`, `found`, `towers` (`known` if every fully identified tower in the capture was already in that profile's baseline, `unknown` if one was not; null for the new-tower checks and `tower_flood`, and for captures with no fully identified tower. Known = seen here before, NOT legitimate: a fake cell can copy a real one). The package automation `rayhunter_finding_notify` in `ha/rayhunter.yaml` triggers on that MQTT topic (D8) and sends it to your phone (`notify.mobile_app_<your_phone>`). Health alerts (`decoder_failure`, `archive_corrupt`) go out at most once an hour each; events wait in the outbox while HA is offline. |
| Did a finding notify? | See Notifications below: query the `notifications` table (`outcome` `sent` / `expired` / `merged` (a health alert inside the 1 h cooldown, not sent) / empty = still queued). |
| What a check id means, and its level | See the table below this one. |
| Send events to Cribl | Optional, off by default. Set all three add-on options, then restart: `cribl_url` (e.g. `https://192.0.2.10:9443/cribl/_bulk`; **https only**, an `http://` URL, or one with `user:pass@` or a `?query`, is refused and the output stays off), `cribl_token` (the Cribl HTTP source's auth token, sent as the raw `Authorization` header), `cribl_ca` (the Cribl certificate's PEM, `cribl.crt`; pasting it into the one-line field is fine, the newlines are rebuilt). Any missing or unparsable = off, with one `Cribl output off: ...` warning at start-up naming the option (never its value). The certificate is **pinned**: only that exact certificate is accepted (no system CAs, nothing it signed), so a `CA:TRUE` self-signed cert from `openssl req -x509` works; re-pin after regenerating it. Best effort: one POST per cycle after the MQTT publish, 10 s timeout, unsent events kept (newest 1000) for the next cycle; it never delays pulls, judging, MQTT or alerts. Never sent: a finding's `detail`, tower keys or identities (PLMN/TAC/cell/PCI/EARFCN; only tower counts), location, tokens, file paths, capture bytes. Event types: see Cribl output below. Log: `Cribl: ...; N event(s) kept` = a failed send (the log never shows the URL or token). |
| Capture rotation | Rayhunter only starts a new capture when recording restarts, so the add-on restarts it: each cycle, before the pull, once the current capture is `rotate_hours` old (default 6; `0` = rotation off, the disk rule too), or once it is at least 1 h old AND the unit's capture storage `used_percent` is at least `rotate_disk_pct` (default 70, 50..=95), it POSTs stop-recording, waits 2 s, POSTs start-recording and checks a NEW current capture runs; the finished one is pulled and judged in that same cycle. Age is on the **Yellow's** clock (from when the add-on first saw that capture name current, kept in the index `meta` table, so it survives restarts); only the capture's name is read from the unit, never its times (1970/2099 change nothing). At most one rotation per 10 minutes. Disk rule: off while pulls are paused (Yellow under 5 GB free: nothing would be pulled or deleted, and the unit refuses to start when its own space is low); and if the next reading after a disk rotation is still at the threshold, the storage is not full of captures: one warning `unit storage stays full ... not captures`, and disk rotations pause until it drops below (the age rule carries on). Never left stopped on purpose: the intent is saved before the stop, so a failed start, or the add-on dying between stop and start, is retried at once and then every cycle whatever the thresholds, until a capture runs (log `ERROR capture rotation (...) failed`). A unit that refuses stop/start (403 in debug mode, 409 busy) and keeps recording the old capture: one warning, no rotation for 1 h. Unit unreachable or its manifest unreadable = no rotation that cycle. Cost: a rotation delays that cycle's pull by about 2 s, a failing one by up to a few minutes in the worst case (each unit call has a 30 s timeout). Log: `capture rotation: reason age/disk/retry, ok true/false`. Sensor "Last rotation"; Cribl event `rotation`. Out of range options are clamped with a log warning. |
| How long it learns before it can notify | Towers and identity rhythm: `fixed_learning_days` (default 14) of Fixed history, counted from the first clean Fixed capture judged. Decode-failure spikes: 48 hours of history in the previous 7 days AND, in Fixed, that same learning period (D1). While learning, a check is `count` only. A capture with any identity stamp missing, unparseable or in the future teaches no rhythm (D3); its towers and failure hours still learn. |
| Stop the "all quiet" pings buzzing (keep alerts loud) | On each receiver: mute the household channel and turn on External Notification `alert_bell_buzzer`. See "Quiet pings, loud alerts" under Household sentinel. |
| Is the "all quiet" ping still going out? | Owner page, above the Sent log: "All-quiet pings: last HH:MM · N today", plus "Last skipped/failed HH:MM (reason)" when the newest ping record was not a send, and a warning when no ping record at all (sent, skipped or failed) has appeared for longer than the schedule allows (12 h 30 m at 3 a day) since the last one or the add-on's start. Every attempt is in the transmission log (table `radio_events`, Cribl `radio`); see "Transmission log" under Household sentinel. |
| Shorten/lengthen Fixed's learning period | Add-on option `fixed_learning_days` (days, 7..=60, default 14; out of range is clamped with a log warning). A quiet rural spot with a handful of towers is well covered in 7; a city with many towers (some only at busy times) wants 14 or more. Shorter = more chance a normal tower first shows up after learning and notifies once. Calendar time from the first clean Fixed capture; a change applies when the add-on restarts (lowering it can end learning at once). It does not restart learning after a move. |
| Widen/narrow the identity-rhythm window | Add-on option `rhythm_tolerance_min` (minutes, 5..=60, default 15; out of range is clamped with a log warning). Off rhythm = gap outside expected +/- this, or two requests within 30 min. Expected = 108 min until the learning period is over and at least 10 Fixed gaps, then their median (gaps from the 30 days before now). |
| Which timestamps count | "Synced" = from 2020 up to one day past the add-on's own clock. Earlier ones (1970, clock never synced) are only compared within one capture; later ones (a fake base station can set the unit's clock to 2099 by NITZ) are ignored: never measured, never learned. A gap across two captures needs both synced, back to back (within 5 min) and the same profile. |
| What `suppressed`, `spans_switch`, `flagged` mean | `suppressed = 1`: a backfilled (pre-2b) capture's finding, stored but never to be notified. `spans_switch = 1`: the capture includes a Fixed/Mobile switch, so it was judged as Mobile; a High may be self-inflicted by the teardown. `flagged = 1` (on `captures`): it has a notify-level finding, so it is never pruned at 90 days. |

### Check ids (table `findings`, column `check_id`)

| check_id | In plain words | Fixed | Mobile | Live |
|---|---|---|---|---|
| `analyser_high` | Rayhunter's analysers raised a High warning; one finding per analyser per capture (`{analyser}: {n} high warning(s); first: {msg}`) | notify | notify | Fixed only |
| `analyser_overflow` | More than 16 analysers with High warnings in one capture; the 17th onward fold into this one finding. Rayhunter ships fewer, so only a compromised decoder gets here. Not in any 24 h sensor | notify | notify | Fixed only |
| `analyser_other` | Medium/Low analyser warnings (Info is not a finding) | count | count | no |
| `new_tower` | A tower with full SIB1 identity not yet in this profile's baseline. In Fixed after learning it is **held** for 7 days (table `held_towers`) instead of learned | count | count | no |
| `new_tower_identity` | Fixed after learning: an identity request 0-10 min after a new tower's first sighting (what a catcher does to get the IMSI) | notify (count while learning) | count | Fixed only |
| `new_tower_recur` | Fixed after learning: a held tower seen again in a later capture within 7 days; it is learned then | notify (count while learning) | count | Fixed only |
| `new_tower_weak` | A new tower known only by PCI+EARFCN | count | count | no |
| `new_tower_sector` | Fixed after learning: a new SIB1 tower on a site already in the baseline (same network, area and eNodeB = cell id >> 8; another antenna face of a known tower). Learned at once, never held, so it never becomes `new_tower_recur`; an identity request 0-10 min after it still raises `new_tower_identity` | count | n/a | no |
| `identity_off_rhythm` | An identity request outside expected +/- tolerance, or two within 30 min | notify (count while learning) | count | no |
| `failure_spike` | An hour's decode-failure rate above 10x the median of the previous 7 days; only hours with at least 100 frames and 50 failures are judged (history hours need 100 frames). In Fixed it also waits for the learning period (D1) | notify (count while learning) | count | no |
| `decoder_failure` | The decoder crashed, timed out or hit a cap; checks cover what arrived | notify | notify | no |
| `archive_corrupt` | Archive copy no longer matches its hash | notify | notify | no |
| `archive_missing` | Archive copy is gone | count | count | no |
| `tower_flood` | More than 200 distinct SIB1 towers in one capture (PCI-only keys do not count); it teaches no baseline | notify | notify | Fixed only |

Live: whether the live view (`device_token` set, polled every `live_poll_secs`) also raises the check from the recording in progress, so its stage 1 radio message goes out within a poll instead of after rotation. Only while the recording is Fixed; `new_tower_identity` and `new_tower_recur` only after learning. If the unit is switched Mobile to Fixed inside one recording, that recording reads `mixed` and live judging stays off until the next rotation.

Learning: towers and rhythm `fixed_learning_days` (default 14, Fixed only); spikes 48 h of history and, in Fixed, the same period. Analyser, overflow, decoder, corrupt and flood are never "learning". Only `ok` decodes teach baselines, and a capture with any missing, unparseable or future identity stamp teaches no rhythm (its towers and failure hours still learn).

## Reading findings

`detail` can hold cell IDs, PLMN/TAC, PCI, EARFCN and timestamps. It must never be shared, pasted into an issue, or exported. It is printable ASCII and at most 1 KiB; a long list ends `... +N more`. The add-on log names only the check id, one line per check id per capture.

Copy the index off the Yellow safely. The WAL file holds recent writes, so take `index.sqlite` AND `index.sqlite-wal` in the same `tar` (a piecemeal copy once gave a stale snapshot):

```
ssh -p 22222 root@<yellow> 'cd /mnt/data/supervisor/apps/data/local_rayhunter_archive/ && tar cf - index.sqlite index.sqlite-wal' > idx.tar
mkdir idx && tar xf idx.tar -C idx
```

Then, read-only:

```
# findings per capture
sqlite3 -readonly idx/index.sqlite "SELECT name, check_id, level, profile, spans_switch, suppressed FROM findings ORDER BY found_at DESC LIMIT 50"

# notify-level findings (the ones that would alert), with detail (private)
sqlite3 -readonly idx/index.sqlite "SELECT name, check_id, profile, suppressed, detail FROM findings WHERE level='notify' ORDER BY found_at DESC"

# towers per profile
sqlite3 -readonly idx/index.sqlite "SELECT profile, strength, COUNT(*) FROM towers GROUP BY 1,2"
```

## Notifications

- One event per capture per check, with a count ("Analyser High warning x3"), at most 8 per capture (D4).
- Phone: the package automation `rayhunter_finding_notify` in `ha/rayhunter.yaml` triggers on the MQTT topic `rayhunter_archive/unit1/finding` (D8, not on the event entity) and notifies the Pixel only (D7). The push does not yet link to the owner page: that link is pending, added once the companion-app notify service is confirmed (`notify.send_message` rejects `clickAction`/`url`).
- Admin notices use the same topic and fields (`capture` empty, `count` 1, `towers` null) so the same automation sends them. Event types: `live_unknown` (Live view unavailable: 3 live polls in a row failed), `not_recording` (Unit not recording: 2 live polls in a row showed no recording, so the one poll that can land in rotation's stop/start gap raises nothing), `low_disk` (Unit storage nearly full: the unit's capture storage `used_percent` is at least 90, checked each cycle), `decoding_off` (Decoding paused: the Yellow is under 5 GB free, the "Pulling paused" state, so nothing new is pulled or judged), `live_unconfirmed` (Live alert not confirmed by full capture: once the recording is judged, a live finding raised during it has no closed finding of the same check sharing a tower, or of the same check if it named no tower; one notice per capture at most), `test_alert` (Home sentinel TEST alert, once per start with `live_test_alert`). Each kind goes out at most once an hour (as health alerts; `test_alert` is one-shot), carries the unit's last seen profile, and is never queued: one not delivered because MQTT or HA is down is dropped. The entity declares 15 event types.
- Health alerts (`decoder_failure`, `archive_corrupt`) go out at most once an hour per check: a row of one of them is retired as `outcome = 'merged'` (never sent) if the same check was sent in the last hour or is already in this cycle's batch. A decoder failing on every capture (3 decodes per 15-minute cycle) therefore pages once an hour, not up to about 12 times. Catcher signals (towers, rhythm, analysers, spikes, flood) are never held back. The 24 h sensors still count every finding.
- Events go out only while Home Assistant is online (its `homeassistant/status` birth/last-will): while HA restarts they wait in the outbox, since an event HA does not see runs no automation. States are still published. Every broker (re)connect counts as HA online again, since a birth message sent while the add-on was reconnecting is not retained and would otherwise hold events until they expire.
- Delivered through an outbox (table `notifications`): at most 10 per cycle, oldest first, only while MQTT is connected; a row is marked sent once the client accepts it. Just before publishing, rows another publish stage already marked are dropped from the batch, so an event is not sent twice. If the broker is known to be down when a cycle ends, nothing is published (states go out next cycle) and the events wait in the outbox for the next connected cycle. Limit: an event accepted in the ~30-60 s before a broker drop is noticed (keep-alive) can be lost, though it is already marked sent; the 24 h sensors still count it. Rows unsent after 24 h are dropped (`outcome = 'expired'`), logged, and still counted by the sensors. Backfill findings never enter the outbox. Events are never retained, so an HA restart cannot replay them (D5).
- Anything from a capture that reaches MQTT is validated. Capture name rule: 1 to 12 ASCII digits (Rayhunter names captures by number), else it is sent as `?`; so `310-260-21891-1234` or `a_b-C` show as `?`. Digits can still carry data from a compromised unit, so the name is a hint, not proof. No cell IDs, PLMN/TAC, PCI, EARFCN, signal or location is ever published, and `detail` is never read here (D9).

Read the outbox (no `detail` column involved; on the copied index, see Reading findings):

```
sqlite3 -readonly idx/index.sqlite "SELECT name, check_id, count, found_at, outcome, sent_at FROM notifications ORDER BY found_at DESC LIMIT 20"
```

## Sensors (device "Rayhunter archive (unit 1)")

| Entity | Meaning |
|---|---|
| Backlog | Captures still on the unit, not yet safely archived (or flagged). |
| Oldest backlog | Start time of the oldest of those. A very old value means pulls are stuck. |
| Last successful pull | Last cycle that reached the unit. Blank after an add-on restart until the first cycle. |
| Hash mismatches | Running total of copies whose hash disagreed with the unit's. One retry, then the capture is flagged and left alone on the unit. |
| Recording gap (24 h) | Minutes in the last 24 h with no capture covering them (the recording in progress counts as a gap until archived). |
| Longest recording gap (24 h) | Longest single such stretch, minutes. |
| Archive size | MB held in `/data/archive` (including `mismatch/`). |
| Yellow free | GB free on `/data`. |
| Days covered | Days of capture history held. Captures the unit stamped before 2020 (recorded before its clock synced; they show as 1970) have no known time and are left out, here and in the gap sensors. |
| Pulling paused | ON = under 5 GB free on `/data`: nothing new is pulled, so nothing new is deleted from the unit. Deletes of captures already verified and archived still go out (they free the unit, not the Yellow). Free space (or lower retention) and pulling resumes on the next cycle. |
| Analyser High warnings (24 h) / Analyser other warnings (24 h) | Findings of those checks judged in the last 24 h (backfill excluded). |
| New towers (24 h) | Towers first learned in the last 24 h, across both profiles (so a Mobile drive raises it). A deploy's backfill can inflate it once. |
| Identity requests off rhythm (24 h) / Decode failure spikes (24 h) / Decoder failures (24 h) / Archive corrupt (24 h) | Findings of that check judged in the last 24 h (backfill excluded). These count even when the check is only `count` level, and every health finding counts even when its alert was merged into the hourly one. `analyser_overflow` is in no sensor. |
| Towers seen (24 h) | Distinct towers sighted in the last 24 h. |
| Decoder unavailable | ON = no decoder guest loaded (see "Is decoding off?"). Problem class. |
| Fixed baseline learning | ON while the Fixed baseline is still inside its learning window (notify checks are `count` only until then). |
| Last rotation | Last successful capture rotation (Yellow clock). Blank until the first. A failed one leaves it unchanged (see the log and the Cribl `rotation` event). Not updated in a cycle where the index cannot be read. |
| Last Fixed request | Result of the last button press: `ok`, `failed`, `refused`, `busy` (rate limited), `not paired` (no token set), `unreachable`. |

## Cribl output

One POST per cycle to `cribl_url`, `Content-Type: application/json`, one JSON object per line (NDJSON), every field top level. Every event has `type`, `time` (RFC 3339, the **Yellow's** clock at the cycle; never a unit timestamp), `device` (`unit1`), `addon_version`, and `_raw` (a short summary, e.g. `finding analyser_high in 532174`). Capture names are the unit's text, printable ASCII, cut to 64 chars.

| `type` | When | Fields |
|---|---|---|
| `cycle` | Every cycle | `pulled`, `deleted`, `mismatches`, `missing`, `backlog`, `reached_device`, `free_bytes`, `cycle_ms` |
| `decode` | Each capture judged this cycle | `capture`, `status`, `profile`, `switched`, `frames`, `failures`, `towers` (a count), `identity_requests`, `warnings_high`, `warnings_other` |
| `finding` | Each finding of those captures, any level | `capture`, `check`, `level`, `profile`, `switched`, `suppressed`, `towers_known` (`known` / `unknown` / null), `found` |
| `notification` | An outbox row retired | `capture`, `check`, `count`, `outcome` (`sent` / `expired` / `merged` / `unsendable`) |
| `health` | Every cycle | The sensor values: `analyser_high_24h`, `analyser_other_24h`, `new_towers_24h`, `off_rhythm_24h`, `failure_spikes_24h`, `decoder_failures_24h`, `archive_corrupt_24h`, `towers_seen_24h`, `learning` (these 9 left out if the report failed), `decoder_unavailable`, `archive_mb`, `free_gb`, `days_covered`, `gap_24h_min`, `longest_gap_24h_min`, `backlog`, `mismatches_total`, `paused` |
| `rotation` | A capture rotation attempt (see Capture rotation) | `reason` (`age` / `disk` / `retry`), `ok`, `previous` (the stopped capture; on a `retry`, the add-on's tracked copy of the old name, printable and cut to 128 before the 64 cut; null if none was tracked), `current` (the new one, null if none started, including when the old one is still recording), `used_percent` (null if unknown), `age_hours` (Yellow clock, one decimal; null for a retry) |
| `radio` | Every radio text attempted, and every due quiet ping that did not go out (see Transmission log under Household sentinel) | `kind`, `outcome` (`sent` / `failed` / `skipped`), `reason` (null when sent), `alert_id` (null if none), `bell`, `hash` (first 12 hex digits of the text's sha256, without the bell). Never the text. Stamped when it happened; sent with the next cycle's POST (the mesh step runs after the Cribl step). |
| `lifecycle` | Start-up and MQTT changes | `event`: `start`, `decoder_ready` / `decoder_unavailable`, `mqtt_connected`, `mqtt_lost` (once per outage). Queued, sent with the next cycle's POST. |

Times: `sent` notification events and `lifecycle` events are stamped with the Yellow's clock when they happen (after the publish stage; at start-up or the MQTT change); every other event carries the cycle's time.

`towers_known` here is the capture's plain fact (also for `new_tower`/`tower_flood`, where the phone alert leaves it out). Known = seen here before, NOT legitimate.

## Household sentinel (mesh)

Optional, off unless `mesh_port` is set. A Meshtastic radio on the Yellow's USB port sends short, fixed-text messages to the household's private channel, so a phone with the Meshtastic app (or another node) hears an alert even when Home Assistant or the internet is down.

**What goes out.** Only these fixed sentences, nothing else: no capture names, cell data, times or counts. Only Fixed-profile findings that did not span a Fixed/Mobile switch. At most 3 outbox rows per cycle, oldest first (owed stage 1 texts go out beside them); a finding older than 24 h is never sent. Mesh delivery is tracked separately from MQTT (notice rows: column `mesh_at`; strong rows: their alert's `stage1_at`), so the mesh does not depend on Home Assistant being up. Alerts lag captures by up to `rotate_hours`, because a capture is judged only after it is rotated, pulled and decoded.

| Check id | Level | Text |
|---|---|---|
| `analyser_high` | strong | Home alert (strong): suspicious cell activity near home |
| `analyser_overflow` | strong | Home alert (strong): many suspicious cell warnings near home |
| `tower_flood` | strong | Home alert (strong): many new cell towers at once near home |
| `new_tower_identity` | strong | Home alert (strong): new cell tower asked phones for ID |
| `new_tower_recur` | strong | Home alert (strong): new cell tower is back near home |
| `new_tower` | all | Home notice: new cell tower near home |
| `new_tower_weak` | all | Home notice: new cell tower near home (weak signal) |
| `new_tower_sector` | all | Home notice: new antenna on a known tower near home |
| `identity_off_rhythm` | all | Home notice: phones asked for ID at an unusual time |
| `failure_spike` | all | Home notice: unusual cell errors near home |
| `analyser_other` | all | Home notice: minor cell warning near home |
| (quiet ping) | n/a | Home sentinel: all quiet |
| (test) | n/a | Home sentinel: test message |

**Alerts (one at a time).** Strong findings are grouped into alerts (tables `alerts`, `alert_events`): the first strong finding opens an alert, later ones join the open alert's timeline instead of raising another, and the same tower (or, without towers, the same finding in the same recording) within 24 h is a duplicate and adds nothing. Within one recording a strong tower check (`new_tower_identity`, `new_tower_recur`, `tower_flood`) sharing a tower with any earlier one, of any age and whatever became of its alert, is a duplicate too: the closed pass re-judging what the live view saw never sends it again. An alert closes (`expired`) 24 h after the last finding that opened or joined it (column `last_finding_at`). Activity on its towers is recorded (`last_seen_at`, the owner page's "no sign since") but does not keep it open: a real tower near home stays visible for ever. Both the live view and the closed pass (the judged capture) feed the same alerts: after judging, every strong, Fixed, switch-free outbox row is passed through the alerts exactly once, whether or not a radio is configured (column `alert_at` is stamped then, whatever the outcome, and `mesh_at` with it, as 0.5.3 did after sending, so a rollback to 0.5.3 on this database does not send the row again; a store error leaves it for the next cycle). If it opens an alert, that alert's stage 1 text goes out; if the live view already raised it, or another alert is open, nothing goes on the radio (log `mesh: already covered by alert N`). `mesh_level: all` notice rows are not alerts: they go out as their own sentence, as before.

**Stage 1 text.** The one radio message an alert sends is its first check's sentence above plus " Stay calm, avoid sensitive calls, wait for an update." (at most 199 bytes: the radio takes 200, and the last is the alert bell, see below), whether the live view or the closed pass opened it. It is owed by the alert, not the row: a failed send is retried by every live poll and cycle for up to 24 hours from when the alert opened, then given up (logged `stage 1 for alert N never went out; given up`). The live view and the 15-minute cycle never open the radio at the same time; a cycle sends owed stage 1 texts first, then notice rows, in one send. No "all quiet" ping goes out while any alert is open (stage 1 sent or not), since fresh evidence may still be joining it; an alert closes 24 h after its last finding. An alert past both 24 h windows is given up (logged) before it expires.

**Quiet ping.** `mesh_quiet_per_day` times a day, at randomised gaps (0.5 to 1.5 times the even spacing), when nothing else is being sent this cycle, the add-on sends "all quiet". It is withheld if the unit has not been reached for 2 hours: the silence is the signal that the detector is down. `0` = no pings. During `mesh_quiet_hours` (local time, e.g. `22-7`) a due ping is skipped and rescheduled, not saved for the morning; alerts are never held.

**Options** (all optional):

| Option | Values | Default |
|---|---|---|
| `mesh_port` | The radio's path under `/dev/serial/by-id/` (a plain path; anything else is refused and the mesh stays off) | unset = mesh off |
| `mesh_level` | `strong` (the first five rows) or `all` (every row) | `strong` |
| `mesh_quiet_per_day` | 0..6 | 3 |
| `mesh_send_test` | Send "Home sentinel: test message" once each time the add-on starts | false |
| `mesh_quiet_hours` | Local hours with no "all quiet" pings, like `22-7` (wraps past midnight); alerts still go out | unset (none) |
| `live_poll_secs` | How often the unit's live view is polled (needs `device_token`), 30..=600 seconds; out of range is clamped with a log warning | 60 |
| `live_test_alert` | Once per start, when the mesh is on and no alert is open: open a TEST alert and send "Home sentinel TEST alert. Stay calm, avoid sensitive calls, wait for an update." over the radio, plus a `test_alert` phone notice. It closes as soon as it is sent and never takes in a real finding | false |

The add-on declares `uart: true` (serial access) and not `devices:`, so it still starts with the radio unplugged.

**Radio settings it expects.** Meshtastic firmware, set up beforehand with the Meshtastic app: the household's private channel as channel 0 (the add-on sends on channel 0 and cannot choose another), and GPS/position broadcasting off. The add-on never changes the radio's settings, and it discards everything the radio sends back: it does not read, store or log any message, node or position.

**Quiet pings, loud alerts (0.8.2).** Every text the add-on sends ends in an ASCII BEL (0x07), except the "all quiet" ping. The bell is invisible on the T-Deck and the Pager, and it is the last of the radio's 200 bytes, so owner follow-ups are limited to 199. Set up each receiver once so that only belled texts make a sound:

| Receiver | Setting | Where |
|---|---|---|
| Any node with a buzzer | External Notification: `alert_bell_buzzer` on (keep `alert_message_buzzer` as it is) | phone app or client.meshtastic.org (Module Config); the device menus do not show it |
| Any node | Mute the household channel (`module_settings.is_muted`; the per-channel bell icon on the T-Deck) | device or app |
| Pager (2.8.1) | Do NOT rely on Notification Sounds = "DMs Only": it still beeps for ordinary messages, because the 60 s nag is armed before the DMs-only check. Mute the channel instead. That menu also has "Notifications" next to "DMs Only"; a mis-click saves at once | device |

Then the ping arrives silently (look at the channel to see when the last one came), and alerts, follow-ups and TEST texts buzz through the mute. DMs still buzz, as the mute is per channel. Verified 2026-10-26 on firmware 2.7.15 (T-Deck) and 2.8.1 (Pager). Phone apps are not covered: muting the channel there may silence alerts too.

**Transmission log (0.8.3).** Every radio text the add-on attempts, and every due quiet ping that did not go out, is one row in table `radio_events` (kept 7 days, pruned with the mesh log) and one Cribl `radio` event. The text itself is never in either: `hash` (sha256 of the text without the bell, first 12 hex digits) matches it to the owner page's Sent log, or to a known sentence, without carrying it.

| `kind` | What |
|---|---|
| `stage1` | An alert's stage 1 text (live view or cycle) |
| `test` | `mesh_send_test`'s message, or `live_test_alert`'s TEST alert |
| `notice` | A `mesh_level: all` notice row |
| `quiet` | The "all quiet" ping |
| `false_alarm`, `watching`, `phones_off`, `all_clear` | An owner-page follow-up (`reason` `override` = All clear sent before its gate) |

`outcome` `failed` reasons: `no_radio`, `no_answer` (handshake timeout), `error`, `not_sent` (the radio took fewer texts than were sent). `skipped` (quiet pings only) reasons: `not_watching` (unit not reached for 2 h, no decoder, or pulls paused for disk), `alert_open`, `busy` (other texts went out that cycle), `quiet_hours`, `radio_busy` (another stage held the radio), `stale` (the cycle's batch was over 5 minutes old by the time the radio was free), `store_error`. A ping that is not due yet writes nothing; a restart reschedules the next ping, so the page warns only when no record at all has appeared for 1.5 x the even spacing plus 30 minutes.

**Failure.** A missing radio, a handshake timeout (10 s) or an I/O error is one warning in the log (`mesh: not sent ...`); notice rows stay unsent and are tried again next cycle, and an alert's stage 1 stays owed and is tried again by every live poll and cycle for up to 24 h from when the alert opened, then given up with a log warning (a repeat beats a silent loss). Pulls, judging and MQTT are unaffected. The log shows outcomes and counts only, never message contents.

## Alert summary (optional)

Off unless `summary_api_key` is set. With no key there is no button and the add-on makes no outbound API call, ever. The alert flow (detection, the radio, the follow-up box) never depends on it; if the API is down, out of credit or the internet is gone, the page says so and everything else works as before.

**On tap only.** Nothing calls the API when an alert opens or when the page loads. One tap, one call to `POST https://api.anthropic.com/v1/messages` (no retries; 30 s timeout).

**What is sent: an allowlist, not a scrubbed copy.** The record is built only from these fields, and no type in it can hold free text:
- check names from the known list (anything else is `"other"`) and each check's class (`alert`/`admin`)
- event times as whole minutes after the alert opened, event counts, source (`live`/`closed`) and `timeline_only` flags
- the alert's age and minutes since last seen, and the live state word (`ok`/`unknown`/`not_recording`/`off`)
- which follow-ups were already sent, by kind name only (never their text), and whether the alert is a practice TEST
- baseline numbers: identity requests in the last 24 h, the mean per day over the 7 days before, strong alerts opened in the last 30 days, and the profile word (`fixed`/`mobile`/`learning`)
- the unit count

Never sent: detail text, tower keys, recording names, cell IDs, PCI, EARFCN, TAC, PLMN, IMSI/IMEI, clock times, dates, locations. The API key goes only into one request header; it is never logged, shown on the page or included in an error message, and requests do not follow redirects.

**Budget guards.**
- One cached summary per (alert, number of timeline events): a repeat tap returns the cache; a new event makes the next tap ask again.
- At most one new API call per 5 minutes overall (taps from two tabs included); inside the gap the page says "One summary per 5 minutes; try again at HH:MM".
- Every call's input and output tokens are stored in the `summary_log` table, and the page shows the running totals.
- The reply is shown as text, never as HTML.

**Errors on the page.** Key refused (401/403); out of API credit (402); busy or down (429, 529, any 5xx, a timeout); no internet. None is retried automatically.

## Security properties

Ingress (`ingress: true`, port 8099, HA sidebar panel "Sentinel") is a deliberate exception to the earlier "no ingress" property. It carries the owner page and a read-only view of the unit's own UI. What it does and does not do:

| Property | What the code does |
|---|---|
| Who may connect | Only the Supervisor's Ingress peer `172.30.32.2` (also as `::ffff:172.30.32.2`). Any other peer gets a 403. HA's own login protects the panel. No port is published. |
| Proxy to the unit | `GET` only, and only an allowlist of paths: `index.html`, `api/analysis`, `api/analyzers`, `api/config`, `api/log`, `api/qmdl-manifest`, `api/system-stats`, `api/time`, `api/update-status`, `api/wifi-status`, `api/m2100/profile`, `api/m2100/capture-profiles`, `api/analysis-report/<name>` (letters, digits, `-_.`), and three images. Everything else is refused, including every POST and any path with `..`, a backslash or a leading `/`. |
| No downloads | Captures (`/api/pcap/`, `/api/qmdl/`, `/api/zip/`) are refused. |
| No location | `/api/gps` (GET and POST) is refused: it carries location. The UI's GPS panel shows an error through the page. |
| Filtered config | `api/config` is passed through with these keys removed at any depth: `webdav` (the whole object), `ntfy_url`, `gps_fixed_latitude`, `gps_fixed_longitude`, `wifi_ssid`, `wifi_password`. If it cannot be parsed the page returns 502. |
| Token | The unit's `device_token` is added by the proxy and never reaches the browser. Proxied responses carry `X-Content-Type-Options: nosniff`, and everything except the index also `Content-Security-Policy: sandbox`. Timeouts: 5 s connect, 10 s read. |
| No external fetches | The page uses no CDN, fonts or images from elsewhere. |
| Follow-up text | Passes a privacy check before the radio, and the server re-checks what it sends. Blocked: a run of 5 or more digits; `PCI`, `ECI`, `TAC` or `EARFCN` (any case) followed by a number; anything that looks like coordinates (decimal pairs, degrees, N/S/E/W forms). The box shows the standing line "No cell IDs, no places." Radio text is at most 200 bytes (UTF-8 bytes, not characters). Digits split by spaces (47 291 396) are not caught. |
| Sending | One send at a time. The same text for the same alert within 60 s goes on air once. If the cycle or live loop holds the radio, the send waits up to 30 s, then refuses (503, "radio busy, try again"). After waiting, the send is checked again against the alert: if it closed meanwhile, it is refused ("Alert already closed.") and nothing goes on air. |

**Accepted risk.** The proxied Rayhunter UI is the unit's own script, and it runs in Home Assistant's Ingress origin. A compromised unit, or someone altering the plain-HTTP link between the Yellow and the unit, could run script inside HA's origin (for example post a follow-up, or read HA's browser storage). Accepted for v1: the bundle is built from the unit's own firmware and the link is a point-to-point USB network. Revisit if the unit is ever reached over a shared network.

## Details

- One cycle every 15 minutes, single-flight: if a cycle is still running when the next tick arrives,
  that tick is dropped (never queued). A cycle starts by clearing `archive/.tmp`, so two must never overlap.
- A capture is its name plus its start time, not its name: the unit names recordings started before
  its clock syncs from seconds since boot, so "31" comes back every boot. A listed entry with an
  unseen start is a new capture, even if that name was archived before.
- Delete safety: a capture is deleted from the unit only after the local copy is recorded in the index
  and its hash equals the hash the unit reports for it, and only if, asked again right before the
  delete, the unit still hashes the name to that value (a reused name, or the recording in progress,
  which answers 409, is left alone). The recording in progress is never touched.
- The unit's delete also removes the analysis, so while a capture's `.ndjson` is missing the delete
  waits and the analysis is retried, once a cycle for up to 3 cycles; then the delete goes ahead.
- A capture that vanishes from the unit between download and hash is kept as
  `mismatch/{name}-{start}.unverified.qmdl.gz` and flagged. If even that move fails, the copy is
  parked in `.tmp` under that name and moved on a later cycle; it is never wiped.
- A capture deleted by hand on the unit before it was pulled is recorded as missing; no retries.
- Retention is 90 days from when a capture was archived (this machine's clock, never the unit's, which
  says 1970 before it syncs), pruned once a day (first cycle after start, then every 24 h). Kept or
  flagged captures are never pruned.
- If the unit cannot be reached, Backlog and Oldest backlog keep showing the last known values.
- MQTT credentials come from the Supervisor (`mqtt:need`); discovery is published (retained) on connect
  and whenever Home Assistant announces `online`. Any payload on the button topic counts as a press.
- Nothing about cells, signal or serving towers is published. There is no open port and no host network. The one exception to "no ingress" is the owner page (0.7.0), see Security properties.
- MQTT over TLS (only if the Supervisor reports `ssl: true`) trusts the container's system CA store, using rustls with the ring provider; with no CA store it logs an error and retries instead of crashing.
- Build detail: `rust-musl-cross` Docker image, target `aarch64-unknown-linux-musl`; bundled SQLite needs
  the C cross compiler. The add-on Dockerfile only copies the binary onto the Home Assistant base image.
- Tests: `cargo test`.
