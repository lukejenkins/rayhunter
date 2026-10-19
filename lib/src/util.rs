use serde::{Deserialize, Serialize};

#[cfg(target_family = "unix")]
use nix::sys::utsname::uname;

/// Expose binary and system information.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct RuntimeMetadata {
    /// The cargo package version from this library's cargo.toml, e.g., "1.2.3".
    pub rayhunter_version: String,
    /// Identifies the exact source the binary was built from, e.g.
    /// "v0.13.0-26-ga78af59" from `git describe`, or the value of
    /// `RAYHUNTER_BUILD_ID` at build time. `None` if neither was available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// The operating system `sysname` and optionally `release`. e.g., "Linux 3.18.48" or "linux".
    pub system_os: String,
    /// The CPU architecture in use. e.g., "armv7l" or "arm".
    pub arch: String,
}

impl Default for RuntimeMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMetadata {
    /// Return the binary and system information, attempting to retrieve
    /// attributes from `uname(2)` and falling back to values from
    /// `std::env::consts`.
    pub fn new() -> Self {
        let build_target = RuntimeMetadata {
            rayhunter_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_id: option_env!("RAYHUNTER_BUILD_ID").map(str::to_owned),
            arch: std::env::consts::ARCH.to_string(),
            system_os: std::env::consts::OS.to_string(),
        };

        #[cfg(target_family = "windows")]
        return build_target;

        #[cfg(target_family = "unix")]
        match uname() {
            Ok(utsname) => RuntimeMetadata {
                rayhunter_version: env!("CARGO_PKG_VERSION").to_owned(),
                build_id: option_env!("RAYHUNTER_BUILD_ID").map(str::to_owned),
                arch: format!("{}", utsname.machine().to_string_lossy()),
                system_os: format!(
                    "{} {}",
                    utsname.sysname().to_string_lossy(),
                    utsname.release().to_string_lossy(),
                ),
            },
            Err(_) => build_target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_without_build_id_still_parses() {
        // Analysis reports written before build_id existed must still load.
        let json = r#"{"rayhunter_version":"0.13.0","system_os":"Linux 3.18.48","arch":"armv7l"}"#;
        let metadata: RuntimeMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.build_id, None);
    }

    #[test]
    fn missing_build_id_is_not_serialized() {
        let metadata = RuntimeMetadata {
            rayhunter_version: "0.13.0".to_owned(),
            build_id: None,
            system_os: "linux".to_owned(),
            arch: "arm".to_owned(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(!json.contains("build_id"));
    }
}
