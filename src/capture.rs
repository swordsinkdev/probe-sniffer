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

/// List all pcap-visible interfaces with their descriptions.
pub fn list_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    let devices = Device::list()?;
    if devices.is_empty() {
        println!("  No capture interfaces found. Is Npcap/libpcap installed?");
        return Ok(());
    }
    println!("\n  {:<6} {:<45} {}", "#", "Name", "Description");
    println!("  {}", "-".repeat(90));
    for (i, dev) in devices.iter().enumerate() {
        let desc = dev.desc.as_deref().unwrap_or("(no description)");
        println!("  {:<6} {:<45} {}", i, dev.name, desc);
    }
    println!();
    Ok(())
}

/// Run the capture loop until interrupted.
pub fn run(cfg: CaptureConfig, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    // Open the interface with rfmon (monitor mode) requested via libpcap.
    let device = Device::from(cfg.interface.as_str());

    let inactive = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000) // 1-second read timeout so we can check `running`
        .immediate_mode(true);

    // Request monitor mode via libpcap's pcap_set_rfmon().
    // This is the proper cross-platform way to get raw 802.11 + radiotap.
    // Note: rfmon() is not available on Windows (Npcap handles it differently).
    #[cfg(not(target_os = "windows"))]
    let inactive = {
        log::info!("Requesting monitor mode (rfmon) via libpcap.");
        inactive.rfmon(true)
    };

    #[cfg(target_os = "windows")]
    let inactive = {
        log::info!("Skipping rfmon (not supported on Windows — Npcap handles monitor mode).");
        inactive
    };

    let mut cap = inactive.open()?;

    // Log all available datalink types for debugging.
    let available_dlts: Vec<_> = cap
        .list_datalinks()
        .unwrap_or_default()
        .iter()
        .map(|l| (l.0, dlt_name(l.0)))
        .collect();
    log::info!("Available datalink types: {:?}", available_dlts);

    // Try to set radiotap (DLT 127), then raw 802.11 (DLT 105).
    if let Err(e) = cap.set_datalink(pcap::Linktype(127)) {
        log::debug!("Could not set DLT_IEEE802_11_RADIO (127): {e}");
        if let Err(e2) = cap.set_datalink(pcap::Linktype(105)) {
            log::debug!("Could not set DLT_IEEE802_11 (105): {e2}");
        }
    }

    let dlt = cap.get_datalink().0;
    log::info!("Active datalink type: {} ({})", dlt, dlt_name(dlt));

    if dlt != 127 && dlt != 105 {
        log::error!(
            "Datalink type is {} ({}) — expected 127 (Radiotap) or 105 (raw 802.11).",
            dlt,
            dlt_name(dlt)
        );
        log::error!(
            "This means the interface is NOT in monitor mode. Possible fixes:"
        );
        log::error!("  • macOS: Enable monitor mode first via Wireless Diagnostics");
        log::error!("    (Window → Sniffer), or `sudo wdutil sniff --channel N --width 20`.");
        log::error!("  • Windows: Reinstall Npcap with 'Support raw 802.11 traffic'.");
        log::error!("  • Use --list-interfaces to verify you picked the right adapter.");
        log::error!("  • Use --interface <NAME> to specify the correct adapter.");
        return Err(format!(
            "Cannot capture probe requests with datalink type {} ({}). \
             Monitor mode is required.",
            dlt,
            dlt_name(dlt)
        )
        .into());
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

/// Human-readable name for common DLT values.
fn dlt_name(dlt: i32) -> &'static str {
    match dlt {
        0 => "NULL/Loopback",
        1 => "Ethernet (EN10MB)",
        6 => "IEEE 802.5 Token Ring",
        9 => "PPP",
        12 => "Raw IP",
        105 => "IEEE 802.11 (raw)",
        127 => "IEEE 802.11 Radiotap",
        119 => "IEEE 802.11 PrismHeader",
        _ => "Unknown",
    }
}
