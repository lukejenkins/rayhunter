# qmiloc (vendored)

Apache-2.0 QMI-LOC client, vendored as a standalone crate. It was written
independently of rayhunter, without reference to any GPL source, and keeps its
own license (see `LICENSE`).

`Cargo.toml` is rewritten only to replace workspace-inherited fields with their
values; `src/` and `LICENSE` are byte-identical to the original crate. `rustfmt.toml` is the crate's own formatting config: without it, rayhunter's default 100-column style re-wraps `src/` and `cargo fmt --check` fails on code that must stay byte-identical. Please don't make functional changes here: send
them to the crate itself so the two copies stay in step.
