use std::path::Path;

use crate::{
    battery::{BatteryState, get_level_from_percentage_file, is_plugged_in_from_file},
    error::RayhunterError,
};

const BATTERY_LEVEL_FILE: &str = "/sys/kernel/chg_info/level";
const PLUGGED_IN_STATE_FILE: &str = "/sys/kernel/chg_info/chg_en";

/// Orbic hotspots without `/sys/kernel/chg_info` (e.g. the R500L5) expose the
/// standard power_supply class instead.
const POWER_SUPPLY_DIR: &str = "/sys/class/power_supply";

pub async fn get_battery_state() -> Result<BatteryState, RayhunterError> {
    get_battery_state_from(Path::new(BATTERY_LEVEL_FILE), Path::new(POWER_SUPPLY_DIR)).await
}

async fn get_battery_state_from(
    chg_info_level: &Path,
    power_supply_dir: &Path,
) -> Result<BatteryState, RayhunterError> {
    if tokio::fs::try_exists(chg_info_level).await.unwrap_or(false) {
        get_chg_info_battery_state().await
    } else {
        get_power_supply_battery_state(power_supply_dir).await
    }
}

async fn get_chg_info_battery_state() -> Result<BatteryState, RayhunterError> {
    Ok(BatteryState {
        level: match tokio::fs::read_to_string(&BATTERY_LEVEL_FILE)
            .await
            .map_err(RayhunterError::TokioError)?
            .chars()
            .next()
        {
            Some('1') => Ok(10),
            Some('2') => Ok(25),
            Some('3') => Ok(50),
            Some('4') => Ok(75),
            Some('5') => Ok(100),
            _ => Err(RayhunterError::BatteryLevelParseError),
        }?,
        is_plugged_in: is_plugged_in_from_file(Path::new(PLUGGED_IN_STATE_FILE)).await?,
    })
}

/// The level is `battery/capacity`. The device counts as plugged in when any
/// supply reports `online` = 1; a supply without an `online` attribute (the
/// battery itself, a BMS) says nothing about external power.
async fn get_power_supply_battery_state(dir: &Path) -> Result<BatteryState, RayhunterError> {
    let level = get_level_from_percentage_file(&dir.join("battery").join("capacity")).await?;

    let mut is_plugged_in = false;
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if let Ok(true) = is_plugged_in_from_file(&entry.path().join("online")).await {
            is_plugged_in = true;
            break;
        }
    }

    Ok(BatteryState {
        level,
        is_plugged_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lay out a power_supply directory: `(supply, attribute, value)`.
    fn power_supply(files: &[(&str, &str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (supply, attribute, value) in files {
            let supply_dir = dir.path().join(supply);
            std::fs::create_dir_all(&supply_dir).unwrap();
            std::fs::write(supply_dir.join(attribute), value).unwrap();
        }
        dir
    }

    // The supplies an Orbic R500L5 exposes, with the host USB cable attached.
    // Its `usb` (USB_PD) supply reads online = 0; `pc_port` (USB) reads 1.
    const R500L5: &[(&str, &str, &str)] = &[
        ("battery", "capacity", "100\n"),
        ("battery", "status", "Full\n"),
        ("bms", "capacity", "100\n"),
        ("dc", "online", "0\n"),
        ("pc_port", "online", "1\n"),
        ("usb", "online", "0\n"),
        ("usb", "present", "1\n"),
    ];

    #[tokio::test]
    async fn reads_level_and_external_power() {
        let dir = power_supply(R500L5);
        let state = get_power_supply_battery_state(dir.path()).await.unwrap();
        assert_eq!(
            state,
            BatteryState {
                level: 100,
                is_plugged_in: true
            }
        );
    }

    #[tokio::test]
    async fn not_plugged_in_when_no_supply_is_online() {
        let dir = power_supply(&[
            ("battery", "capacity", "42\n"),
            ("pc_port", "online", "0\n"),
            ("usb", "online", "0\n"),
        ]);
        let state = get_power_supply_battery_state(dir.path()).await.unwrap();
        assert_eq!(
            state,
            BatteryState {
                level: 42,
                is_plugged_in: false
            }
        );
    }

    #[tokio::test]
    async fn uses_power_supply_when_chg_info_is_absent() {
        let dir = power_supply(R500L5);
        let missing = dir.path().join("no_chg_info_level");
        let state = get_battery_state_from(&missing, dir.path()).await.unwrap();
        assert_eq!(state.level, 100);
    }

    #[tokio::test]
    async fn missing_battery_capacity_is_an_error() {
        let dir = power_supply(&[("pc_port", "online", "1\n")]);
        assert!(get_power_supply_battery_state(dir.path()).await.is_err());
    }
}
