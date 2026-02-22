//! # probe-sniffer
//!
//! Cross-platform (macOS + Windows) WiFi probe-request sniffer.
//!
//! Listens on a specified channel for 802.11 probe requests targeting a
//! given SSID.  Because modern devices randomize their MAC addresses, unique
//! devices are estimated by **clustering on signal strength (RSSI)** rather
//! than counting distinct MACs.  Each cluster's distance from the receiver
//! is estimated with the log-distance path-loss model.
//!
//! ## Requirements
//!
//! | Platform | Prerequisites |
//! |----------|---------------|
//! | macOS    | Run as **root** (`sudo`).  Uses `ifconfig` to enable monitor mode (no `airport` CLI needed). |
//! | Windows  | Install **Npcap** with *"Support raw 802.11 traffic"* enabled.  Run as **Administrator**. |
//!
//! ## Examples
//!
//! ```text
//! sudo cargo run -- --ssid "MyNetwork"
//! sudo cargo run -- --ssid "MyNetwork" --channel 6 --interface en0
//! ```

mod capture;
mod cluster;
mod parser;
mod platform;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

#[derive(Parser)]
#[command(name = "probe-sniffer")]
#[command(version, about = "WiFi probe request sniffer with signal-strength device clustering")]
struct Cli {
    /// Target SSID to filter for.
    #[arg(short, long)]
    ssid: String,

    /// WiFi channel to sniff (1–14 for 2.4 GHz, 36–165 for 5 GHz).
    #[arg(short, long, default_value_t = 8)]
    channel: u8,

    /// Channel width in MHz (informational; capture is always 20 MHz primary).
    #[arg(short = 'w', long, default_value_t = 20)]
    channel_width: u16,

    /// Network interface to use.  Auto-detected if omitted.
    #[arg(short, long)]
    interface: Option<String>,

    /// RSSI bandwidth (dBm) for clustering.  Two readings within this
    /// tolerance are considered the same device.
    #[arg(short = 'b', long, default_value_t = 5.0)]
    rssi_bandwidth: f64,

    /// Assumed TX power at 1 m reference distance (dBm).
    #[arg(short = 'p', long, default_value_t = -40.0)]
    tx_power: f64,

    /// Path-loss exponent (2.0 = free-space, 2.7–4.0 = indoors).
    #[arg(short = 'n', long, default_value_t = 3.0)]
    path_loss_exp: f64,

    /// Device cluster time-to-live in seconds.  A cluster not seen for this
    /// long is considered gone.
    #[arg(short = 't', long, default_value_t = 60)]
    ttl_secs: u64,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    // ── Platform setup ──────────────────────────────────────────────────
    let monitor = platform::create_monitor();

    let iface = match &cli.interface {
        Some(name) => name.clone(),
        None => match monitor.detect_interface() {
            Ok(name) => name,
            Err(e) => {
                log::error!("Failed to detect WiFi interface: {e}");
                std::process::exit(1);
            }
        },
    };

    if let Err(e) = monitor.enable_monitor_mode(&iface, cli.channel) {
        log::error!("Failed to enable monitor mode: {e}");
        log::error!(
            "Make sure you are running as root/Administrator and that your \
             adapter supports monitor mode."
        );
        std::process::exit(1);
    }

    // ── Ctrl-C handler ──────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        let iface_clone = iface.clone();
        ctrlc::set_handler(move || {
            log::info!("Interrupt received — shutting down …");
            running.store(false, Ordering::Relaxed);
            // Give the capture loop a moment to finish, then clean up.
            std::thread::sleep(Duration::from_millis(200));
            let m = platform::create_monitor();
            if let Err(e) = m.disable_monitor_mode(&iface_clone) {
                log::warn!("Cleanup error: {e}");
            }
        })
        .expect("Failed to set Ctrl-C handler");
    }

    // ── Capture loop ────────────────────────────────────────────────────
    let capture_cfg = capture::CaptureConfig {
        interface: iface.clone(),
        ssid: cli.ssid,
        channel: cli.channel,
        channel_width: cli.channel_width,
        cluster_cfg: cluster::ClusterConfig {
            rssi_bandwidth: cli.rssi_bandwidth,
            tx_power: cli.tx_power,
            path_loss_exp: cli.path_loss_exp,
            ttl: Duration::from_secs(cli.ttl_secs),
        },
    };

    if let Err(e) = capture::run(capture_cfg, Arc::clone(&running)) {
        log::error!("Capture failed: {e}");
        let _ = monitor.disable_monitor_mode(&iface);
        std::process::exit(1);
    }

    // ── Teardown ────────────────────────────────────────────────────────
    if let Err(e) = monitor.disable_monitor_mode(&iface) {
        log::warn!("Cleanup error: {e}");
    }
    log::info!("Done.");
}
