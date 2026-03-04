//! Linux monitor-mode setup via `iw` and `ip`.
//!
//! ## Prerequisites
//!
//! * A WiFi adapter whose driver supports monitor mode (most Atheros, Intel,
//!   and Realtek chipsets do).
//! * The `iw` and `ip` command-line utilities (installed by default on most
//!   distributions).
//! * Root privileges (`sudo`).
//!
//! ## Approach
//!
//! 1. Detect the primary wireless interface via `/sys/class/net/*/wireless`.
//! 2. Create (or reuse) a monitor-mode virtual interface (`<iface>mon`) using
//!    `iw dev <iface> interface add <iface>mon type monitor`.
//! 3. Bring the monitor interface up and set the requested channel.
//! 4. On teardown, delete the monitor interface and bring the original back.
//!
//! If the adapter only supports a single virtual interface (no VIF), we fall
//! back to switching the primary interface directly into monitor mode.

use std::fs;
use std::io;
use std::process::Command;

use super::WifiMonitor;

pub struct LinuxMonitor;

impl LinuxMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Run a command, returning stdout on success or an `io::Error` on
    /// non-zero exit.
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

    /// Derive monitor interface name from the base interface (e.g. `wlan0` →
    /// `wlan0mon`).
    fn mon_iface(iface: &str) -> String {
        format!("{iface}mon")
    }

    /// Check whether an interface currently exists.
    fn iface_exists(iface: &str) -> bool {
        fs::metadata(format!("/sys/class/net/{iface}")).is_ok()
    }
}

impl WifiMonitor for LinuxMonitor {
    fn detect_interface(&self) -> io::Result<String> {
        // Walk /sys/class/net/*/wireless — any directory that has a
        // `wireless` sub-entry is a WiFi adapter.
        let entries = fs::read_dir("/sys/class/net").map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot read /sys/class/net: {e}"),
            )
        })?;

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let wireless_path = format!("/sys/class/net/{name}/wireless");
            if fs::metadata(&wireless_path).is_ok() {
                log::info!("Auto-detected WiFi interface: {name}");
                return Ok(name);
            }
        }

        // Fallback: try `iw dev` output.
        if let Ok(output) = Self::run("iw", &["dev"]) {
            for line in output.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Interface ") {
                    if let Some(iface) = trimmed.strip_prefix("Interface ") {
                        let iface = iface.trim();
                        if !iface.is_empty() {
                            log::info!("Detected WiFi interface via `iw dev`: {iface}");
                            return Ok(iface.to_string());
                        }
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No wireless interface found. Is a WiFi adapter connected?",
        ))
    }

    fn enable_monitor_mode(&self, iface: &str, channel: u8) -> io::Result<()> {
        let mon = Self::mon_iface(iface);

        // If a monitor interface already exists, try to reuse it.
        if Self::iface_exists(&mon) {
            log::info!("Monitor interface {mon} already exists — reusing.");
            // Make sure it's up and on the right channel.
            let _ = Self::run("ip", &["link", "set", &mon, "up"]);
            let ch = channel.to_string();
            if let Err(e) = Self::run("iw", &["dev", &mon, "set", "channel", &ch]) {
                log::warn!("Could not set channel {channel} on {mon}: {e}");
            }
            return Ok(());
        }

        // Strategy 1: create a separate monitor VIF.
        log::info!("Creating monitor interface {mon} from {iface} …");
        match Self::run(
            "iw",
            &["dev", iface, "interface", "add", &mon, "type", "monitor"],
        ) {
            Ok(_) => {
                // Bring the monitor VIF up.
                Self::run("ip", &["link", "set", &mon, "up"])?;
                let ch = channel.to_string();
                if let Err(e) = Self::run("iw", &["dev", &mon, "set", "channel", &ch]) {
                    log::warn!("Could not set channel {channel} on {mon}: {e}");
                }
                log::info!("Monitor mode enabled on {mon}, channel {channel}.");
                return Ok(());
            }
            Err(e) => {
                log::warn!(
                    "Could not create monitor VIF ({e}); falling back to \
                     switching {iface} directly."
                );
            }
        }

        // Strategy 2: switch the primary interface into monitor mode.
        log::info!("Switching {iface} to monitor mode directly …");
        // Managed → down → monitor → up.
        let _ = Self::run("ip", &["link", "set", iface, "down"]);

        // Kill processes that might interfere (NetworkManager, wpa_supplicant).
        let _ = Self::run("airmon-ng", &["check", "kill"]);

        Self::run("iw", &["dev", iface, "set", "type", "monitor"])?;
        Self::run("ip", &["link", "set", iface, "up"])?;

        let ch = channel.to_string();
        if let Err(e) = Self::run("iw", &["dev", iface, "set", "channel", &ch]) {
            log::warn!("Could not set channel {channel} on {iface}: {e}");
        }

        log::info!("Monitor mode enabled on {iface}, channel {channel}.");
        Ok(())
    }

    fn disable_monitor_mode(&self, iface: &str) -> io::Result<()> {
        let mon = Self::mon_iface(iface);

        if Self::iface_exists(&mon) {
            // We created a monitor VIF — remove it.
            log::info!("Removing monitor interface {mon} …");
            let _ = Self::run("ip", &["link", "set", &mon, "down"]);
            let _ = Self::run("iw", &["dev", &mon, "del"]);
            log::info!("Monitor interface {mon} removed.");
        } else {
            // We switched the primary interface — restore it.
            log::info!("Restoring {iface} to managed mode …");
            let _ = Self::run("ip", &["link", "set", iface, "down"]);
            let _ = Self::run("iw", &["dev", iface, "set", "type", "managed"]);
            let _ = Self::run("ip", &["link", "set", iface, "up"]);

            // Restart NetworkManager if available.
            let _ = Self::run("systemctl", &["restart", "NetworkManager"]);
        }

        Ok(())
    }
}

/// Return the actual capture interface name.  On Linux, if a separate monitor
/// VIF was created (e.g. `wlan0mon`), we need to capture on that — not on the
/// original managed interface.
pub fn capture_interface(iface: &str) -> String {
    let mon = LinuxMonitor::mon_iface(iface);
    if LinuxMonitor::iface_exists(&mon) {
        mon
    } else {
        iface.to_string()
    }
}
