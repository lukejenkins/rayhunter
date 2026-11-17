# Changelog

What changed on this fork, newest first. The device-side work (the touchscreen UI, panic lockdown,
profiles) is listed by date; the Home Assistant add-on (`m2100-archive`) has its own version numbers.
Everything below was developed privately and published together in November 2026.

## Home Assistant add-on (`m2100-archive`)

### 0.8.4 (2026-11-11)
- A new sector of a tower site the unit already knows is learned, not held as suspicious.

### 0.8.3 (2026-10-26)
- Transmission log: every mesh send, failure and skipped "all quiet" ping is recorded (table
  `radio_events`, Cribl event `radio`); never the message text.
- Owner page: "All-quiet pings: last HH:MM · N today", and a warning when pings are overdue.

### 0.8.2 (2026-10-26)
- The alert bell rings on every mesh message except the quiet ping.

### 0.8.1 (2026-10-26)
- The owner page's proxy answers the unit's GPS endpoint with 404, so nothing location-related
  passes through it.

### 0.8.0 (2026-10-25)
- Optional alert summary on the owner page (off by default): a short plain-language read of an
  alert's evidence, using Anthropic's API. Advice only; it never sends or fills anything. Cell
  identities and coordinates are removed before anything leaves the add-on.

### 0.7.0 (2026-10-25)
- Owner page: what is active now, a timeline of the alert's findings, follow-up presets, the Sent
  log, and the Rayhunter UI read-only.

### 0.6.0 – 0.6.1 (2026-10-25)
- A closed pass goes through alerts; low-disk and decoding-off notices.
- Live events wait until MQTT and Home Assistant can take them.

### 0.5.0 – 0.5.3 (2026-10-22 – 10-23)
- Household sentinel over Meshtastic (USB serial): alerts and randomised "all quiet" pings on a
  household channel, with health sensors.
- Quiet hours for the pings.
- New towers notify only when corroborated or recurring.
- A replugged radio reads as OK, not as a stale "radio missing".

### 0.4.0 – 0.4.3 (2026-10-12 – 10-15)
- Findings published to Home Assistant as sensors and events.
- The Fixed learning period is an option; alerts say whether the capture's towers were already known.
- Optional event output to Cribl, over TLS with a pinned certificate.
- Capture rotation by age and by the unit's disk use.

### 0.2.0 – 0.3.0 (2026-10-11)
- Captures are decoded in a WebAssembly sandbox (no files, no network) and judged against a
  learned baseline: towers, identity-request rhythm, decode-failure spikes.
- README cheat sheet for check ids and reading findings.

### 0.1.0 (2026-10-09)
- First version: pulls captures off the unit every 15 minutes, verifies and archives them, and
  only then deletes them from the unit. 90-day retention (kept longer if flagged). Health over MQTT,
  and a "go to Fixed" button.

## Device (M2100)

### 2026-11-04 (merged 2026-11-17)
- Diag: every logging-mode ioctl attempt is zero-padded, and diag setup failures are logged
  instead of swallowed. The ioctl carries no length, so the shorter attempts handed the driver
  stack junk; that, not boot timing, is why Rayhunter could hang when started after the vendor
  modem stack. Commits [`9f85107`](https://github.com/mallorybowes/rayhunter/commit/9f85107),
  [`9b0da46`](https://github.com/mallorybowes/rayhunter/commit/9b0da46).

### 2026-10-16
- `fleet-core` and `fleet-sim`: an early protocol for a group of sentinels (signed, revocable
  messages) and a simulator. No radio adapter yet.

### 2026-10-09 – 10-10
- Profiles: **Fixed** (hotspot off, cellular data firewalled for IPv4 and IPv6) and **Mobile**,
  switched on the panel; re-applied at boot once the vendor stack is up.
- A paired, token-gated endpoint lets Home Assistant switch the unit to Fixed.
- Each capture records which profile it was made in.
- The decoder library builds for WebAssembly.

### 2026-10-06 – 10-08
- The Rayhunter UI is hidden behind the stock Inseego screen and revealed only by your own gesture
  (5–8 moves), set up over USB with LED and buzzer cues.
- Settings screen: change the gesture or PIN (after performing the current one), buzzer on/off.
- The panic PIN is stored salted and hashed.
- Panic is confirmed by the vendor's startup chime and a short burst of LED blinks.
- Notifications name the analyser and the time; the panel shows the cell.
- `rayhunter-m2100` helper: status, enrol, pair, reset; it never handles a secret.

### 2026-09-25 – 09-28
- Touchscreen UI on the M2100 panel, via the vendor's display commit ioctl, with a toggle back to
  the stock UI and an idle fade back to it.
- Live status panel: serving cell, band and RAT from QMI, an RSRP sparkline.
- Panic lockdown with a PIN unlock, off unless armed.
- LED heartbeat; battery support.
- The parser keeps log payloads whose version it doesn't know (also published earlier, `aa04b06`).
