//! macOS monitor-mode setup — **without** the removed `airport` CLI.
//!
//! ## Approach
//!
//! 1. Detect the WiFi interface via `networksetup -listallhardwareports`.
//! 2. Bring the interface down with `ifconfig <iface> down`.
//! 3. Enable monitor mode:  `ifconfig <iface> monitor`.
//! 4. Set the channel:      `ifconfig <iface> channel <N>`.
//! 5. Bring the interface up: `ifconfig <iface> up`.
//!
//! All of these require **root** (`sudo`).  The binary will exit with a
//! clear error message if the commands fail due to insufficient privileges.
//!
//! ## Teardown
//!
//! `disable_monitor_mode` removes monitor mode and re-associates with the
//! previous network by toggling Wi-Fi power via `networksetup`.

use std::io;
use std::process::Command;

use super::WifiMonitor;

pub struct MacOsMonitor;

impl MacOsMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Run a command, returning an `io::Error` on non-zero exit.
    fn run(cmd: &str, args: &[&str]) -> io::Result<String> {
        let output = Command::new(cmd).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("`{cmd} {}` failed: {stderr}", args.join(" ")),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl WifiMonitor for MacOsMonitor {
    fn detect_interface(&self) -> io::Result<String> {
        // `networksetup -listallhardwareports` output looks like:
        //
        //   Hardware Port: Wi-Fi
        //   Device: en0
        //   Ethernet Address: ...
        //
        let output = Self::run("networksetup", &["-listallhardwareports"])?;
        let mut found_wifi = false;
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Hardware Port:") && trimmed.contains("Wi-Fi") {
                found_wifi = true;
                continue;
            }
            if found_wifi && trimmed.starts_with("Device:") {
                if let Some(dev) = trimmed.strip_prefix("Device:") {
                    return Ok(dev.trim().to_string());
                }
            }
            if found_wifi && trimmed.is_empty() {
                break;
            }
        }
        // Fallback — `en0` is the WiFi interface on the vast majority of Macs.
        log::warn!("Could not auto-detect WiFi interface; falling back to en0");
        Ok("en0".to_string())
    }

    fn enable_monitor_mode(&self, iface: &str, channel: u8) -> io::Result<()> {
        log::info!("Bringing {iface} down …");
        Self::run("ifconfig", &[iface, "down"])?;

        log::info!("Enabling monitor mode on {iface} …");
        Self::run("ifconfig", &[iface, "monitor"])?;

        log::info!("Setting channel {channel} on {iface} …");
        let ch = channel.to_string();
        Self::run("ifconfig", &[iface, "channel", &ch])?;

        log::info!("Bringing {iface} up …");
        Self::run("ifconfig", &[iface, "up"])?;

        Ok(())
    }

    fn disable_monitor_mode(&self, iface: &str) -> io::Result<()> {
        log::info!("Removing monitor mode on {iface} …");
        // Bring interface down, remove monitor, bring back up.
        let _ = Self::run("ifconfig", &[iface, "down"]);
        let _ = Self::run("ifconfig", &[iface, "-monitor"]);
        let _ = Self::run("ifconfig", &[iface, "up"]);

        // Toggle Wi-Fi power so macOS re-associates automatically.
        log::info!("Cycling Wi-Fi power to re-associate …");
        let _ = Self::run("networksetup", &["-setairportpower", iface, "off"]);
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = Self::run("networksetup", &["-setairportpower", iface, "on"]);

        Ok(())
    }
}
