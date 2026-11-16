//! m2100-decoder: reads one gzipped QMDL capture on stdin, writes JSON-line
//! events on stdout (see decode.rs and events.rs). Built for wasm32-wasip1
//! and run inside the archive add-on's sandbox.

mod decode;
mod events;

#[cfg(test)]
mod tests;

fn main() {
    let outcome = decode::run(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        decode::Caps::default(),
    );
    std::process::exit(match outcome {
        decode::Outcome::OutputError => 1,
        _ => 0,
    });
}
