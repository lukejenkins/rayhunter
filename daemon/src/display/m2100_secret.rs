//! Salted, iterated SHA-256 secrets, shared by the panic PIN and the reveal
//! gesture. Each is stored only as a hash: pulling the file does not reveal it.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Rounds of SHA-256 over salt + previous output. Same value the PIN has always
/// used, so existing `.panic` files keep matching.
pub const KDF_ROUNDS: u32 = 50_000;

pub fn derive(salt: &[u8], data: &[u8]) -> Vec<u8> {
    let mut acc = Sha256::new();
    acc.update(salt);
    acc.update(data);
    let mut out = acc.finalize().to_vec();
    for _ in 1..KDF_ROUNDS {
        let mut h = Sha256::new();
        h.update(salt);
        h.update(&out);
        out = h.finalize().to_vec();
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 16 bytes from the kernel RNG; the clock only if that is unavailable.
/// NB: read a fixed number of bytes. `/dev/urandom` has no EOF.
pub fn new_salt() -> Vec<u8> {
    (|| {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").ok()?;
        let mut b = [0u8; 16];
        f.read_exact(&mut b).ok()?;
        Some(b.to_vec())
    })()
    .unwrap_or_else(|| {
        log::warn!("secret: no urandom, salting from the clock");
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        seed.to_le_bytes().to_vec()
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    /// Stored because the rolling-window matchers need it.
    pub len: usize,
}

impl Secret {
    pub fn create(data: &[u8]) -> Secret {
        let salt = new_salt();
        let hash = derive(&salt, data);
        Secret {
            salt,
            hash,
            len: data.len(),
        }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() == self.len && derive(&self.salt, data) == self.hash
    }

    pub fn to_lines(&self) -> String {
        format!(
            "salt = {}\nhash = {}\nlen = {}\n",
            hex(&self.salt),
            hex(&self.hash),
            self.len
        )
    }

    /// Ignores keys it doesn't know (the PIN file also carries `dev`).
    pub fn from_lines(body: &str) -> Option<Secret> {
        let (mut salt, mut hash, mut len) = (None, None, None);
        for line in body.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "salt" => salt = unhex(v.trim()),
                "hash" => hash = unhex(v.trim()),
                "len" => len = v.trim().parse::<usize>().ok(),
                _ => {}
            }
        }
        let s = Secret {
            salt: salt?,
            hash: hash?,
            len: len?,
        };
        (s.len > 0 && !s.salt.is_empty() && !s.hash.is_empty()).then_some(s)
    }
}

/// Write via a temp file and rename, so a power cut mid-write leaves either the
/// old file or the new one, never half of one.
pub fn write_atomic(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(body.as_bytes())?;
    // On disk before the rename, so a power cut can't leave an empty file in
    // its place; then the directory, so the rename itself survives.
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_matches_only_its_own_data() {
        let s = Secret::create(&[1, 2, 3, 4]);
        assert!(s.matches(&[1, 2, 3, 4]));
        assert!(!s.matches(&[1, 2, 3, 5]));
        assert!(!s.matches(&[1, 2, 3]), "a prefix must not match");
    }

    #[test]
    fn two_secrets_of_the_same_data_have_different_salts() {
        let a = Secret::create(&[4, 4, 4, 4]);
        let b = Secret::create(&[4, 4, 4, 4]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn a_secret_survives_serialisation_and_never_contains_the_data() {
        let s = Secret::create(&[9, 8, 7, 6, 5, 4]);
        let body = s.to_lines();
        assert!(!body.contains("987654"));
        let back = Secret::from_lines(&body).expect("round trip");
        assert!(back.matches(&[9, 8, 7, 6, 5, 4]));
    }

    #[test]
    fn a_damaged_file_is_rejected_not_half_loaded() {
        assert!(Secret::from_lines("salt = zz\nhash = 00\nlen = 4\n").is_none());
        assert!(Secret::from_lines("hash = 0011\nlen = 4\n").is_none());
        assert!(Secret::from_lines("salt = 0011\nhash = 0011\nlen = 0\n").is_none());
    }

    #[test]
    fn an_atomic_write_never_leaves_a_partial_file() {
        let dir = std::env::temp_dir().join(format!("rh-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(".reveal");
        std::fs::write(&p, "old").unwrap();
        write_atomic(&p, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        assert!(
            !dir.join(".reveal.tmp").exists(),
            "temp file must be renamed away"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
