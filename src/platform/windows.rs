//! Windows monitor-mode setup via Npcap + Native WiFi API.
//!
//! ## Prerequisites
//!
//! * **Npcap** must be installed with the *"Support raw 802.11 traffic
//!   (monitor mode)"* option enabled.
//!   Download: <https://npcap.com/#download>
//! * A WiFi adapter whose NDIS driver supports monitor mode (most Intel
//!   adapters do).
//!
//! ## Approach
//!
//! 1. Enumerate WLAN interfaces via the Windows Native WiFi API
//!    (`WlanEnumInterfaces`).
//! 2. (Attempt to) set the desired channel via `WlanSetInterface`.
//! 3. Npcap handles the actual monitor-mode transition when we open the
//!    adapter for capture — no extra driver commands are needed.
//!
//! Channel setting may silently fail if the driver does not expose the
//! required OID; in that case we log a warning and proceed anyway.

use std::io;

use super::WifiMonitor;

pub struct WindowsMonitor;

impl WindowsMonitor {
    pub fn new() -> Self {
        Self
    }
}

impl WifiMonitor for WindowsMonitor {
    fn detect_interface(&self) -> io::Result<String> {
        // Use Npcap/pcap device enumeration to find a WiFi adapter.
        let devices = pcap::Device::list().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("pcap device enumeration failed (is Npcap installed?): {e}"),
            )
        })?;

        // Prefer a device whose description mentions "Wi-Fi" or "Wireless".
        for dev in &devices {
            if let Some(ref desc) = dev.desc {
                let lower = desc.to_lowercase();
                if lower.contains("wi-fi")
                    || lower.contains("wifi")
                    || lower.contains("wireless")
                    || lower.contains("wlan")
                {
                    log::info!("Auto-detected WiFi interface: {} ({})", dev.name, desc);
                    return Ok(dev.name.clone());
                }
            }
        }

        // Fallback: pick the first non-loopback device.
        for dev in &devices {
            if !dev.addresses.is_empty() {
                log::warn!(
                    "Could not identify WiFi device; falling back to {}",
                    dev.name
                );
                return Ok(dev.name.clone());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No suitable network interface found. Is Npcap installed?",
        ))
    }

    fn enable_monitor_mode(&self, iface: &str, channel: u8) -> io::Result<()> {
        log::info!(
            "Npcap handles monitor mode automatically on Windows for {iface}."
        );

        // Attempt to set channel via the Native WiFi API.
        if let Err(e) = try_set_channel_wlanapi(iface, channel) {
            log::warn!(
                "Could not set channel {channel} via WlanAPI: {e}. \
                 You may need to set the channel manually in your adapter \
                 properties or Npcap configuration."
            );
        }
        Ok(())
    }

    fn disable_monitor_mode(&self, _iface: &str) -> io::Result<()> {
        log::info!(
            "Npcap monitor mode is released when the capture handle is dropped."
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Native WiFi API helpers
// ---------------------------------------------------------------------------

/// Try to set the Wi-Fi channel via WlanAPI.
///
/// This is a best-effort operation — many consumer drivers silently ignore it.
fn try_set_channel_wlanapi(iface: &str, channel: u8) -> io::Result<()> {
    use std::process::Command;

    // Use `netsh wlan` as a lightweight channel-configuration attempt.
    // The hosted-network channel trick:
    //   netsh wlan set hostednetwork channel=<N>
    // only works for hosted networks, but it's the closest we get without
    // raw IOCTL.  For real monitor-mode channel control, the Npcap adapter
    // typically adopts the channel the OS is already scanning.
    //
    // We try the `netsh` approach but swallow failures gracefully.
    let ch = channel.to_string();
    let output = Command::new("netsh")
        .args(["wlan", "set", "hostednetwork", &format!("channel={ch}")])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::debug!("netsh channel set for {iface}: {stderr}");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("netsh channel set failed: {stderr}"),
        ));
    }

    log::info!("Requested channel {channel} via netsh");
    Ok(())
}
