//! # probe-sniffer
//!
//! Cross-platform (macOS + Windows + Linux) WiFi probe-request sniffer.
//!
//! Listens on a specified channel for 802.11 probe requests targeting a
//! given SSID.  Because modern devices randomize their MAC addresses, unique
//! devices are estimated by **clustering on signal strength (RSSI)** rather
//! than counting distinct MACs.  Each cluster's distance from the receiver
//! is estimated with the log-distance path-loss model.
//!
//! ## Multi-card mode
//!
//! Connect 3 or 4 WiFi adapters arranged in a triangle or square layout and
//! use `--multi` with `--interfaces` to enable **trilateration**: the tool
//! will estimate each device's 2D position (distance + compass direction)
//! by combining RSSI readings from all receivers.
//!
//! ## Requirements
//!
//! | Platform | Prerequisites |
//! |----------|---------------|
//! | macOS    | Run as **root** (`sudo`).  Enable monitor mode manually before running. |
//! | Windows  | Install **Npcap** with *"Support raw 802.11 traffic"* enabled.  Run as **Administrator**. |
//! | Linux    | Run as **root** (`sudo`).  Needs `iw` and `ip` (installed by default on most distros). |
//!
//! ## Examples
//!
//! ```text
//! # List available capture interfaces:
//! cargo run -- --list-interfaces
//!
//! # Sniff on auto-detected interface (single card):
//! sudo cargo run -- --ssid "MyNetwork"
//!
//! # Sniff on a specific interface and channel:
//! sudo cargo run -- --ssid "MyNetwork" --channel 6 --interface en0
//!
//! # Multi-card triangulation (3 receivers, triangle layout, 1 m spacing):
//! sudo cargo run -- --ssid "MyNetwork" --multi \
//!     --interfaces wlan0,wlan1,wlan2 --layout triangle --spacing 1.0
//!
//! # Multi-card with 4 receivers in a square:
//! sudo cargo run -- --ssid "MyNetwork" --multi \
//!     --interfaces wlan0,wlan1,wlan2,wlan3 --layout square --spacing 0.5
//! ```

mod capture;
mod cluster;
mod multi_capture;
mod parser;
mod platform;
mod triangulation;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

#[derive(Parser)]
#[command(name = "probe-sniffer")]
#[command(version, about = "WiFi probe request sniffer with signal-strength device clustering and multi-card triangulation")]
struct Cli {
    /// List all available capture interfaces and exit.
    #[arg(short = 'l', long)]
    list_interfaces: bool,

    /// Target SSID to filter for.
    #[arg(short, long, required_unless_present = "list_interfaces")]
    ssid: Option<String>,

    /// WiFi channel to sniff (1–14 for 2.4 GHz, 36–165 for 5 GHz).
    #[arg(short, long, default_value_t = 8)]
    channel: u8,

    /// Channel width in MHz (informational; capture is always 20 MHz primary).
    #[arg(short = 'w', long, default_value_t = 20)]
    channel_width: u16,

    /// Network interface to use (single-card mode).  Auto-detected if omitted.
    #[arg(short, long)]
    interface: Option<String>,

    // ── Multi-card / triangulation options ───────────────────────────────

    /// Enable multi-card triangulation mode.
    #[arg(short = 'm', long)]
    multi: bool,

    /// Comma-separated list of interface names for multi-card mode.
    /// Example: --interfaces wlan0,wlan1,wlan2
    #[arg(long, value_delimiter = ',')]
    interfaces: Option<Vec<String>>,

    /// Receiver layout shape (triangle or square).
    #[arg(long, value_enum, default_value_t = triangulation::Layout::Triangle)]
    layout: triangulation::Layout,

    /// Side length of the receiver layout in metres (distance between
    /// adjacent receivers).
    #[arg(long, default_value_t = 1.0)]
    spacing: f64,

    // ── Clustering / estimation parameters ──────────────────────────────

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

    /// Minimum number of probe requests before a cluster is reported as a
    /// confirmed device.  Increase to prune noisy one-off readings.
    #[arg(long, default_value_t = 3)]
    min_probes: u64,

    /// Minimum confidence score (0.0–∞) to report a cluster as a real device.
    /// Higher values prune transient or weak clusters.
    #[arg(long, default_value_t = 0.5)]
    min_confidence: f64,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    // ── List interfaces mode ────────────────────────────────────────────
    if cli.list_interfaces {
        if let Err(e) = capture::list_interfaces() {
            log::error!("Failed to list interfaces: {e}");
            std::process::exit(1);
        }
        return;
    }

    let ssid = cli.ssid.clone().expect("SSID is required when not using --list-interfaces");

    // ── Shared cluster config ───────────────────────────────────────────
    let cluster_cfg = cluster::ClusterConfig {
        rssi_bandwidth: cli.rssi_bandwidth,
        tx_power: cli.tx_power,
        path_loss_exp: cli.path_loss_exp,
        ttl: Duration::from_secs(cli.ttl_secs),
        min_probes: cli.min_probes,
        min_confidence: cli.min_confidence,
    };

    // ── Dispatch: multi-card or single-card mode ────────────────────────
    if cli.multi {
        run_multi_card(cli, ssid, cluster_cfg);
    } else {
        run_single_card(cli, ssid, cluster_cfg);
    }
}

// ========================================================================
// Single-card mode (original behaviour)
// ========================================================================

fn run_single_card(cli: Cli, ssid: String, cluster_cfg: cluster::ClusterConfig) {
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

    // On Linux, capture may need the monitor VIF name (e.g. wlan0mon).
    let capture_iface = platform::capture_interface(&iface);

    // ── Ctrl-C handler ──────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        let iface_clone = iface.clone();
        ctrlc::set_handler(move || {
            log::info!("Interrupt received — shutting down …");
            running.store(false, Ordering::Relaxed);
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
        interface: capture_iface,
        ssid,
        channel: cli.channel,
        channel_width: cli.channel_width,
        cluster_cfg,
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

// ========================================================================
// Multi-card triangulation mode
// ========================================================================

fn run_multi_card(cli: Cli, ssid: String, cluster_cfg: cluster::ClusterConfig) {
    let interfaces = match cli.interfaces {
        Some(ifaces) if !ifaces.is_empty() => ifaces,
        _ => {
            log::error!(
                "Multi-card mode requires --interfaces (comma-separated list)."
            );
            log::error!(
                "Example: --interfaces wlan0,wlan1,wlan2"
            );
            std::process::exit(1);
        }
    };

    let n = interfaces.len();
    let receiver_positions = triangulation::layout_positions(cli.layout, cli.spacing);
    if n > receiver_positions.len() {
        log::error!(
            "Layout {:?} provides {} positions but {} interfaces were given.",
            cli.layout,
            receiver_positions.len(),
            n,
        );
        std::process::exit(1);
    }
    // Trim positions to match the number of interfaces.
    let positions: Vec<_> = receiver_positions.into_iter().take(n).collect();

    log::info!(
        "Receiver positions ({:?} layout, {:.2} m spacing):",
        cli.layout,
        cli.spacing,
    );
    for p in &positions {
        log::info!("  Rx#{}: ({:.3}, {:.3}) m", p.id, p.x, p.y);
    }

    // ── Platform setup for each interface ───────────────────────────────
    let monitor = platform::create_monitor();
    let mut active_ifaces: Vec<String> = Vec::new();

    for iface in &interfaces {
        if let Err(e) = monitor.enable_monitor_mode(iface, cli.channel) {
            log::error!("Failed to enable monitor mode on {iface}: {e}");
            // Clean up any interfaces we already set up.
            for a in &active_ifaces {
                let _ = monitor.disable_monitor_mode(a);
            }
            std::process::exit(1);
        }
        active_ifaces.push(iface.clone());
    }

    // Resolve capture interface names (Linux may use <iface>mon).
    let capture_ifaces: Vec<String> = interfaces
        .iter()
        .map(|i| platform::capture_interface(i))
        .collect();

    // ── Ctrl-C handler ──────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = Arc::clone(&running);
        let ifaces_clone = interfaces.clone();
        ctrlc::set_handler(move || {
            log::info!("Interrupt received — shutting down …");
            running.store(false, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(200));
            let m = platform::create_monitor();
            for iface in &ifaces_clone {
                if let Err(e) = m.disable_monitor_mode(iface) {
                    log::warn!("Cleanup error on {iface}: {e}");
                }
            }
        })
        .expect("Failed to set Ctrl-C handler");
    }

    // ── Build trilaterator ──────────────────────────────────────────────
    let trilaterator = triangulation::Trilaterator::new(
        positions,
        cli.tx_power,
        cli.path_loss_exp,
    );

    let multi_cfg = multi_capture::MultiCaptureConfig {
        interfaces: capture_ifaces,
        ssid,
        channel: cli.channel,
        channel_width: cli.channel_width,
        cluster_cfg,
        trilaterator,
    };

    if let Err(e) = multi_capture::run(multi_cfg, Arc::clone(&running)) {
        log::error!("Multi-card capture failed: {e}");
        for iface in &interfaces {
            let _ = monitor.disable_monitor_mode(iface);
        }
        std::process::exit(1);
    }

    // ── Teardown ────────────────────────────────────────────────────────
    for iface in &interfaces {
        if let Err(e) = monitor.disable_monitor_mode(iface) {
            log::warn!("Cleanup error on {iface}: {e}");
        }
    }
    log::info!("Done.");
}
