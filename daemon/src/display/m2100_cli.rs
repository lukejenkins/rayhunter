//! Running the vendor's command-line tools (and a few system ones). The vendor
//! CLIs prompt for their arguments on stdin, and some hang forever on this
//! firmware (modem2_cli's band commands), so every call has a timeout and the
//! child is killed when it overruns.

use std::time::Duration;

use async_trait::async_trait;

/// One finished command: whether it exited 0, its exit code (`None` if a
/// signal ended it), and what it printed.
#[derive(Clone, Debug, PartialEq)]
pub struct Out {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
}

#[async_trait]
pub trait Runner: Send + Sync {
    /// `None` if the command could not start or overran the timeout.
    async fn run(&self, cmd: &str, args: &[&str], stdin: &str) -> Option<Out>;
}

/// Bounds every call: `modem2_cli` has commands that never return.
pub const VENDOR_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the vendor's CLIs live, and the libraries they load. Neither is in
/// the daemon's environment (PATH=/sbin:/usr/sbin:/bin:/usr/bin, no
/// LD_LIBRARY_PATH), so a bare name that exists in VENDOR_BIN runs from there
/// with VENDOR_LIB, as the vendor's own init scripts set them.
pub const VENDOR_BIN: &str = "/opt/nvtl/bin";
pub const VENDOR_LIB: &str = "/opt/nvtl/lib";

fn command_in(dir: &str, cmd: &str, args: &[&str]) -> std::process::Command {
    let full = format!("{dir}/{cmd}");
    let mut c = if !cmd.contains('/') && std::path::Path::new(&full).exists() {
        let mut c = std::process::Command::new(full);
        c.env("LD_LIBRARY_PATH", VENDOR_LIB);
        c
    } else {
        std::process::Command::new(cmd)
    };
    c.args(args);
    c
}

pub struct System {
    pub timeout: Duration,
}

impl System {
    pub fn new() -> System {
        System {
            timeout: VENDOR_TIMEOUT,
        }
    }
}

#[async_trait]
impl Runner for System {
    async fn run(&self, cmd: &str, args: &[&str], stdin: &str) -> Option<Out> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::from(command_in(VENDOR_BIN, cmd, args))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        if let Some(mut input) = child.stdin.take() {
            let _ = input.write_all(stdin.as_bytes()).await;
            // Dropped here, so the tool sees the end of its input.
        }
        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(o)) => Some(Out {
                ok: o.status.success(),
                code: o.status.code(),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            }),
            Ok(Err(e)) => {
                log::warn!("m2100: {cmd} failed: {e}");
                None
            }
            Err(_) => {
                log::warn!("m2100: {cmd} timed out after {:?}", self.timeout);
                None
            }
        }
    }
}

/// A scripted stand-in for tests: records each call as one line,
/// `"<cmd> <args...> <<stdin with newlines as commas>"`, and answers from a
/// closure over that line.
#[cfg(test)]
pub struct Fake {
    calls: std::sync::Mutex<Vec<String>>,
    respond: Box<dyn Fn(&str) -> Option<Out> + Send + Sync>,
}

#[cfg(test)]
impl Fake {
    pub fn new(respond: impl Fn(&str) -> Option<Out> + Send + Sync + 'static) -> Fake {
        Fake {
            calls: std::sync::Mutex::new(vec![]),
            respond: Box::new(respond),
        }
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl Runner for Fake {
    async fn run(&self, cmd: &str, args: &[&str], stdin: &str) -> Option<Out> {
        let line = format!("{cmd} {} <{}", args.join(" "), stdin.replace('\n', ","));
        self.calls.lock().unwrap().push(line.clone());
        (self.respond)(&line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stdin_reaches_the_command_and_stdout_comes_back() {
        let r = System {
            timeout: Duration::from_secs(5),
        };
        let o = r.run("sh", &["-c", "cat"], "startup\n1\n").await.unwrap();
        assert!(o.ok);
        assert_eq!(o.stdout, "startup\n1\n");
    }

    #[tokio::test]
    async fn a_command_that_overruns_is_cut_off() {
        let r = System {
            timeout: Duration::from_millis(200),
        };
        let t = std::time::Instant::now();
        assert_eq!(r.run("sleep", &["5"], "").await, None);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[tokio::test]
    async fn a_non_zero_exit_is_reported() {
        let o = System::new()
            .run("sh", &["-c", "echo no; exit 1"], "")
            .await
            .unwrap();
        assert!(!o.ok);
        assert_eq!(o.code, Some(1));
        assert_eq!(o.stdout, "no\n");
    }

    #[tokio::test]
    async fn a_missing_command_is_none() {
        assert_eq!(
            System::new().run("no-such-command-xyz", &[], "").await,
            None
        );
    }

    #[test]
    fn vendor_tools_run_from_their_dir_with_their_libraries() {
        // The daemon starts with PATH=/sbin:/usr/sbin:/bin:/usr/bin and no
        // LD_LIBRARY_PATH; the vendor's CLIs live in /opt/nvtl/bin and exit
        // 127 without /opt/nvtl/lib (found on unit 1).
        let dir = std::env::temp_dir().join(format!("rh-bin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ccm2_cli"), "").unwrap();
        let d = dir.to_str().unwrap();
        let lib = |c: &std::process::Command| {
            c.get_envs()
                .find(|(k, _)| *k == "LD_LIBRARY_PATH")
                .and_then(|(_, v)| v.map(|v| v.to_str().unwrap().to_string()))
        };
        let v = command_in(d, "ccm2_cli", &["get_wwan_ac"]);
        assert_eq!(v.get_program(), format!("{d}/ccm2_cli").as_str());
        assert_eq!(lib(&v).as_deref(), Some(VENDOR_LIB));
        let ipt = command_in(d, "iptables", &["-w"]);
        assert_eq!(ipt.get_program(), "iptables");
        assert_eq!(lib(&ipt), None);
        assert_eq!(command_in(d, "/bin/sh", &[]).get_program(), "/bin/sh");
        assert_eq!((VENDOR_BIN, VENDOR_LIB), ("/opt/nvtl/bin", "/opt/nvtl/lib"));
    }
}
