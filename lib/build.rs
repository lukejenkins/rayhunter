use std::process::Command;

// Embed an identifier for the exact source a binary was built from, so a
// custom or development build can be told apart from a release that shares
// its cargo version. `RAYHUNTER_BUILD_ID` overrides it; otherwise use
// `git describe` (e.g. "v0.13.0-26-ga78af59-dirty"). Outside a git checkout
// (e.g. a crates.io source tarball) no build id is set.
fn main() {
    println!("cargo:rerun-if-env-changed=RAYHUNTER_BUILD_ID");

    let build_id = std::env::var("RAYHUNTER_BUILD_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .or_else(git_describe);

    if let Some(build_id) = build_id {
        println!("cargo:rustc-env=RAYHUNTER_BUILD_ID={build_id}");
    }
}

fn git_describe() -> Option<String> {
    let git_dir = run_git(&["rev-parse", "--absolute-git-dir"])?;
    // Rebuild when HEAD moves or the index changes (commits, checkouts,
    // staging), so the embedded id doesn't go stale.
    println!("cargo:rerun-if-changed={git_dir}/HEAD");
    println!("cargo:rerun-if-changed={git_dir}/index");
    run_git(&["describe", "--tags", "--always", "--dirty"])
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let out = String::from_utf8(output.stdout).ok()?;
    let out = out.trim();
    (!out.is_empty()).then(|| out.to_owned())
}
