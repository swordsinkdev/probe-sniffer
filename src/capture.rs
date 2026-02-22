//! Platform-agnostic packet capture loop.
//!
//! Opens the monitor-mode interface with libpcap, reads packets, parses
//! probe requests, feeds them into the clustering engine, and periodically
//! prints a summary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::Colorize;
use pcap::{Capture, Device};

use crate::cluster::{ClusterConfig, ClusterEngine};
use crate::parser::{self, ProbeRequest};

/// Configuration for the capture loop.
pub struct CaptureConfig {
    /// Interface name to capture on.
    pub interface: String,
    /// Target SSID to filter for.
    pub ssid: String,
    /// Channel number (for display only — the platform layer already set it).
    pub channel: u8,
    /// Channel width in MHz (for display only).
    pub channel_width: u16,
    /// Clustering parameters.
    pub cluster_cfg: ClusterConfig,
}

/// Run the capture loop until interrupted.
pub fn run(cfg: CaptureConfig, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    // Open the interface in promiscuous + immediate mode.
    let device = Device::from(cfg.interface.as_str());

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000) // 1-second read timeout so we can check `running`
        .immediate_mode(true)
        .open()?;

    // Attempt to set monitor mode on the pcap handle (works on some systems).
    // Errors are non-fatal — the platform layer already did its best.
    #[cfg(not(target_os = "windows"))]
    {
        if let Err(e) = cap.set_datalink(pcap::Linktype(127)) {
            log::debug!("Could not request radiotap datalink via pcap: {e}");
        }
    }

    let dlt = cap.get_datalink().0;
    log::info!("Datalink type: {dlt}");

    if dlt != 127 && dlt != 105 {
        log::warn!(
            "Unexpected datalink type {dlt}. Expected 127 (Radiotap) or 105 (raw 802.11). \
             Capture may not work correctly."
        );
    }

    // Optional BPF filter — try to pre-filter on type/subtype if possible.
    // Not all platforms support this filter syntax on radiotap captures, so
    // we swallow errors.
    if let Err(e) = cap.filter("type mgt subtype probe-req", true) {
        log::debug!("BPF filter not applied (will filter in software): {e}");
    }

    println!(
        "\n{}",
        format!(
            "  Sniffing on {} — channel {} ({} MHz) — filtering SSID \"{}\"",
            cfg.interface, cfg.channel, cfg.channel_width, cfg.ssid
        )
        .bold()
    );
    println!(
        "  {}",
        "Press Ctrl-C to stop and restore the interface.\n"
            .dimmed()
    );

    let mut engine = ClusterEngine::new(cfg.cluster_cfg);
    let mut last_summary = Instant::now();
    let summary_interval = Duration::from_secs(5);

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(probe) = parser::parse_probe_request(packet.data, dlt) {
                    handle_probe(&probe, &cfg.ssid, &mut engine);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Expected — just loop and check the running flag.
            }
            Err(e) => {
                log::error!("Capture error: {e}");
                break;
            }
        }

        // Periodic summary.
        if last_summary.elapsed() >= summary_interval {
            engine.print_summary(&cfg.ssid);
            last_summary = Instant::now();
        }
    }

    // Final summary.
    println!("\n{}", "  ── Final summary ──".bold().cyan());
    engine.print_summary(&cfg.ssid);

    Ok(())
}

/// Process a single parsed probe request.
fn handle_probe(probe: &ProbeRequest, target_ssid: &str, engine: &mut ClusterEngine) {
    // Only consider probes for our target SSID (case-insensitive match).
    if !probe.ssid.eq_ignore_ascii_case(target_ssid) {
        return;
    }

    let rssi = match probe.signal_dbm {
        Some(r) => r,
        None => {
            log::debug!(
                "Probe request from {} has no signal info — skipping",
                parser::format_mac(&probe.source_mac)
            );
            return;
        }
    };

    let cluster_id = engine.observe(rssi, probe.source_mac);
    let mac_str = parser::format_mac(&probe.source_mac);
    let rand_tag = if parser::is_randomized_mac(&probe.source_mac) {
        " (randomized)".dimmed().to_string()
    } else {
        String::new()
    };

    println!(
        "  {} SSID={:?}  MAC={}{}  RSSI={} dBm  → cluster #{}  (devices: {})",
        "PROBE".green().bold(),
        probe.ssid,
        mac_str.yellow(),
        rand_tag,
        rssi,
        cluster_id,
        engine.device_count(),
    );
}
