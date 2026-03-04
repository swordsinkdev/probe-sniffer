//! Platform-specific WiFi monitor-mode helpers.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

use std::io;

/// Trait that each platform module implements.
pub trait WifiMonitor {
    /// Detect (or confirm) the WiFi interface name.
    fn detect_interface(&self) -> io::Result<String>;

    /// Put the interface into monitor mode on the given channel.
    fn enable_monitor_mode(&self, iface: &str, channel: u8) -> io::Result<()>;

    /// Restore the interface to managed (normal) mode.
    fn disable_monitor_mode(&self, iface: &str) -> io::Result<()>;
}

/// Return the platform-appropriate [`WifiMonitor`].
pub fn create_monitor() -> Box<dyn WifiMonitor> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsMonitor::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsMonitor::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxMonitor::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        compile_error!("Unsupported platform — only macOS, Windows, and Linux are supported");
    }
}

/// Return the actual capture interface name for the given base interface.
///
/// On Linux, if a separate monitor VIF was created (e.g. `wlan0mon`), we
/// need to capture on that instead of the original managed interface.
/// On other platforms, the base interface is used directly.
pub fn capture_interface(iface: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        linux::capture_interface(iface)
    }
    #[cfg(not(target_os = "linux"))]
    {
        iface.to_string()
    }
}
