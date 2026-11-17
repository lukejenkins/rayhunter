> [!IMPORTANT]
> **This is an unofficial fork of [EFF's Rayhunter](https://github.com/EFForg/rayhunter) for the Inseego MiFi M2100 5G UW.**
> It is not affiliated with or endorsed by EFF, and the M2100 is not a supported Rayhunter device.
> For EFF's official releases and supported hardware, use the upstream project.

## Rayhunter on the Inseego M2100

This branch (`m2100-support`) runs Rayhunter on the M2100: it captures and analyses live LTE traffic and alerts on detections. The story of the port, including what we found, what we verified and where we stopped, is in the write-up: **[Rayhunter on the Inseego M2100: field notes from a port](https://tpc.institute/projects/rayhunter-m2100)**.

It is a proof of concept meant for a household: one sentinel unit on a shelf, reporting to Home Assistant. What changed between releases is in [CHANGELOG.md](CHANGELOG.md).

### What's here

| Part | What it does | Where |
| --- | --- | --- |
| Parser and diag fixes | The 24-byte msm-4.14 diag ioctl; strip the multi-radio header; keep log versions the parser doesn't know. Zero-pad every logging-mode ioctl attempt (the ioctl carries no length, so shorter attempts handed the driver stack junk and it could hang when Rayhunter started after the vendor modem stack), and log diag setup failures. Reported upstream in [discussion #560](https://github.com/EFForg/rayhunter/discussions/560). | `lib/`, `daemon/src/diag.rs` |
| Device support | LED and buzzer alerts, battery. | `daemon/` |
| Touchscreen UI | A live status panel (serving cell, band, RSRP sparkline), settings, and alerts that name the analyser and time. Hidden behind the stock Inseego screen until you perform your own reveal gesture. | `daemon/src/display/` |
| Panic lockdown | Off unless you arm it. Locked, the unit offers no ADB and no web interface, so it looks like an ordinary MiFi; an invisible PIN pad on the screen unlocks it. Forget the PIN and the only way back is a reflash. Captures stay unencrypted on flash. | `daemon/src/display/m2100_panic.rs` |
| Profiles | **Fixed** (a stationary sentinel: hotspot off, cellular data firewalled, IPv4 and IPv6) or **Mobile**. Switched on the panel, or by Home Assistant over a paired, token-gated endpoint. | `daemon/` |
| Setup helper | `rayhunter-m2100` sets the gesture and PIN, pairs with Home Assistant and resets a forgotten secret, over USB. It never sees a secret. | `dist/m2100/` |
| Home Assistant add-on | Pulls captures off the unit, archives and verifies them, decodes them in a sandbox, judges them against a learned baseline, and alerts through Home Assistant. Owner page; optional Cribl output, Meshtastic household mesh and alert summary. | `m2100-archive/` |
| Sandboxed decoder | The capture decoder, built as WebAssembly so the add-on runs it with no files and no network. | `m2100-decoder/` |
| Fleet protocol (early) | Signed, revocable messages for a group of sentinels, and a simulator. No radio adapter yet. | `fleet-core/`, `fleet-sim/` |

### Cheat sheet

| I want to... | Read |
| --- | --- |
| Set the reveal gesture, panic PIN and profile | [`dist/m2100/INSTALL-gesture.md`](dist/m2100/INSTALL-gesture.md) (quick reference at the top) |
| Install and run the Home Assistant add-on | [`m2100-archive/README.md`](m2100-archive/README.md) (cheat sheet at the top) |
| Know what a finding or check id means | `m2100-archive/README.md`, "Check ids" |
| See the fleet frame format | [`fleet-core/README.md`](fleet-core/README.md) |
| Report a bug or ask a public question | Open an issue on this fork |

### Before you try this

- **There is no installer.** Getting a root shell on the M2100 currently needs third-party firmware, which also changes settings in the modem itself. We describe what we checked and what we could not, but we do not recommend it to anyone at risk. See [Verifying the firmware](https://tpc.institute/projects/rayhunter-m2100) in the write-up.
- **LTE only, and T-Mobile in practice.** Rayhunter's analysers read LTE; the M2100 has a manual LTE-only mode. AT&T rejects the device.
- **Built and tested on our own hardware:** two M2100 units and one Home Assistant Yellow. Expect to adapt it.
- **The hidden UI and the panic lockdown are meant to get past a quick look, not a forensic examination.** Now that the code is public, assume anyone who knows to look for it can recognise it. In some places, wiping or locking a device before a search is itself an offence; read EFF's and CPJ's guidance for where you are.
- **The alert summary is off by default.** If you turn it on, it sends an alert's evidence to Anthropic's API, after removing cell identities and coordinates. Leave it off if that isn't acceptable.

**Contact.** For technical questions that can be public, open an issue here. For anything else, write to research@tpc.institute.

Code in this fork was written with the help of Claude (Anthropic) and tested on two M2100 units. Licensed GPL-3.0, like upstream.

---

# Rayhunter
![Tests](https://github.com/EFForg/rayhunter/actions/workflows/main.yml/badge.svg)

![Rayhunter Logo - An Orca taking a bite out of a cellular signal bar](https://www.eff.org/files/styles/media_browser_preview/public/banner_library/rayhunter-banner.png)

Rayhunter is a project for detecting IMSI catchers, also known as cell-site simulators or stingrays. It was first designed to run on a cheap mobile hotspot called the Orbic RC400L, but thanks to community efforts, it can [support some other devices as well](https://efforg.github.io/rayhunter/supported-devices.html).
It's also designed to be as easy to install and use as possible, regardless of your level of technical skills, and to minimize false positives. 

&rarr;  Check out the [installation guide](https://efforg.github.io/rayhunter/installation.html) to get started.

&rarr; To learn more about the aim of the project, and about IMSI catchers in general, please check out our [introductory blog post](https://www.eff.org/deeplinks/2025/03/meet-rayhunter-new-open-source-tool-eff-detect-cellular-spying). 

&rarr; For discussion, help, or to join the mattermost channel and get involved with the project and community check out the [many ways listed here](https://efforg.github.io/rayhunter/support-feedback-community.html)!

&rarr; To learn more about the project in general check out the [Rayhunter Book](https://efforg.github.io/rayhunter/).

**LEGAL DISCLAIMER:** Use this program at your own risk. We believe running this program does not currently violate any laws or regulations in the United States. However, we are not responsible for civil or criminal liability resulting from the use of this software. If you are located outside of the US please consult with an attorney in your country to help you assess the legal risks of running this program.

*Good Hunting!*
