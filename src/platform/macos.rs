//! macOS monitor-mode setup — **without** the removed `airport` CLI.
//!
//! ## Approach
//!
//! Monitor mode must be enabled **manually** by the user before launching
//! this tool (e.g. via Wireless Diagnostics, `wdutil`, or a third-party
//! tool like `iw`/KisMac).  This module only detects the WiFi interface
//! and verifies that it is already in monitor mode.
//!
//! ## Teardown
//!
//! `disable_monitor_mode` toggles Wi-Fi power via `networksetup` to
//! re-associate with the previous network.

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
        // Verify the interface is already in monitor mode by checking
        // `ifconfig <iface>` output for the "MONITOR" flag.
        log::info!("Checking that {iface} is already in monitor mode …");
        let output = Self::run("ifconfig", &[iface])?;
        if !output.to_uppercase().contains("MONITOR") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "{iface} is NOT in monitor mode.\n\
                     Please enable monitor mode manually before running this tool.\n\
                     \n\
                     Example (macOS Sonoma+):\n\
                     \n\
                     # Option A — Wireless Diagnostics:\n\
                     #   Open Wireless Diagnostics → Window → Sniffer\n\
                     #   Select channel {channel}, width 20 MHz, and capture.\n\
                     \n\
                     # Option B — wdutil (requires SIP adjustment):\n\
                     #   sudo wdutil sniff --channel {channel} --width 20\n\
                     \n\
                     Then re-run this tool."
                ),
            ));
        }

        log::info!("{iface} is in monitor mode ✓");
        log::info!("Note: make sure you have set channel {channel} (20 MHz) manually.");
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
