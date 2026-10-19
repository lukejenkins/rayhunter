# qmiloc (vendored)

Apache-2.0 QMI-LOC client, vendored as a standalone crate. It was written
independently of rayhunter, without reference to any GPL source, and keeps its
own license (see `LICENSE`).

`Cargo.toml` is rewritten only to replace workspace-inherited fields with their
values, and two comments in `src/` were edited for publication; otherwise the
files match the original crate. Please don't make functional changes here: send
them to the crate itself so the two copies stay in step.
