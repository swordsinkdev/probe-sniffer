//! Multi-card (multi-receiver) capture coordinator.
//!
//! Manages N WiFi adapters capturing simultaneously on the same channel.
//! Each adapter runs its own capture thread; observations are funnelled
//! through an MPSC channel into a shared correlation engine that:
//!
//! 1. Maintains a per-receiver [`ClusterEngine`] for RSSI-based device
//!    counting.
//! 2. Correlates clusters across receivers (matching by MAC address within
//!    a time window) to produce multi-distance readings.
//! 3. Feeds those readings into the [`Trilaterator`] for 2D position
//!    estimation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use colored::Colorize;
use pcap::{Capture, Device};

use crate::cluster::{ClusterConfig, ClusterEngine};
use crate::parser::{self, ProbeRequest};
use crate::triangulation::{DeviceLocation, DistanceReading, Trilaterator};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration for multi-card capture.
pub struct MultiCaptureConfig {
    /// Interface names for each receiver (index matches receiver id).
    pub interfaces: Vec<String>,
    /// Target SSID to filter for.
    pub ssid: String,
    /// Channel number.
    pub channel: u8,
    /// Channel width in MHz (informational).
    pub channel_width: u16,
    /// Clustering parameters (shared across all receivers).
    pub cluster_cfg: ClusterConfig,
    /// Trilateration engine (owns receiver positions & path-loss params).
    pub trilaterator: Trilaterator,
}

/// A tagged observation from one receiver thread.
#[derive(Debug, Clone)]
struct TaggedProbe {
    /// Which receiver captured this.
    receiver_id: usize,
    /// The parsed probe request.
    probe: ProbeRequest,
    /// Wall-clock capture timestamp.
    timestamp: Instant,
}

// ---------------------------------------------------------------------------
// Correlation engine
// ---------------------------------------------------------------------------

/// Correlates probe requests across receivers to build multi-distance
/// readings for trilateration.
///
/// Key insight: even though MACs are randomized, if the *same* randomized
/// MAC appears on multiple receivers within a short time window, it is
/// almost certainly the same burst from the same device.  We use this
/// MAC + time correlation to associate RSSI readings across receivers.
struct Correlator {
    /// Per-receiver clustering engine.
    engines: Vec<ClusterEngine>,
    /// Recent observations keyed by MAC address.
    /// Value: Vec<(receiver_id, rssi, timestamp)>.
    recent: HashMap<[u8; 6], Vec<(usize, f64, Instant)>>,
    /// Maximum age of an entry in `recent` before it is evicted.
    correlation_window: Duration,
    /// Trilaterator for position estimation.
    trilaterator: Trilaterator,
    /// Number of receivers.
    num_receivers: usize,
    /// Located devices: MAC → most recent location.
    pub located_devices: HashMap<[u8; 6], DeviceLocation>,
}

impl Correlator {
    fn new(
        num_receivers: usize,
        cluster_cfg: ClusterConfig,
        trilaterator: Trilaterator,
    ) -> Self {
        let engines = (0..num_receivers)
            .map(|_| ClusterEngine::new(cluster_cfg.clone()))
            .collect();
        Self {
            engines,
            recent: HashMap::new(),
            correlation_window: Duration::from_secs(2),
            trilaterator,
            num_receivers,
            located_devices: HashMap::new(),
        }
    }

    /// Process a tagged probe from one receiver.
    fn ingest(&mut self, tagged: &TaggedProbe, target_ssid: &str) {
        // Filter by SSID.
        if !tagged.probe.ssid.eq_ignore_ascii_case(target_ssid) {
            return;
        }

        let rssi = match tagged.probe.signal_dbm {
            Some(r) => r,
            None => return,
        };

        // Feed into per-receiver cluster engine.
        let _cluster_id = self.engines[tagged.receiver_id].observe(rssi, tagged.probe.source_mac);

        // Store in recent-observations map for cross-receiver correlation.
        let entry = self
            .recent
            .entry(tagged.probe.source_mac)
            .or_insert_with(Vec::new);
        entry.push((tagged.receiver_id, rssi as f64, tagged.timestamp));

        // Prune old entries.
        let cutoff = tagged.timestamp - self.correlation_window;
        entry.retain(|(_, _, ts)| *ts > cutoff);

        // Check if we have readings from enough distinct receivers.
        let mut seen_receivers: Vec<bool> = vec![false; self.num_receivers];
        let mut readings: Vec<DistanceReading> = Vec::new();

        for &(rid, r, _) in entry.iter() {
            if !seen_receivers[rid] {
                seen_receivers[rid] = true;
                // Retrieve per-receiver RSSI variance from the cluster
                // engine so the WLS solver can weight this reading.
                let variance = self.engines[rid]
                    .variance_for_mac(&tagged.probe.source_mac)
                    .unwrap_or(0.0);
                readings.push(
                    self.trilaterator
                        .reading_from_rssi_with_variance(rid, r, variance),
                );
            }
        }

        let distinct = readings.len();
        if distinct >= 3 {
            if let Some(loc) = self.trilaterator.locate(&readings) {
                self.located_devices
                    .insert(tagged.probe.source_mac, loc);
            }
        }
    }

    /// Print a summary of located devices.
    fn print_location_summary(&self, target_ssid: &str) {
        if self.located_devices.is_empty() {
            println!(
                "{}",
                "  No devices located yet (need ≥3 receivers to see the same probe)."
                    .dimmed()
            );
            return;
        }

        println!(
            "\n{}",
            format!(
                "  ── Located devices probing for \"{}\":  {} ──",
                target_ssid,
                self.located_devices.len(),
            )
            .bold()
            .cyan()
        );
        println!(
            "  {:>18}  {:>10}  {:>8}  {:>7}  {:>7}  {:>8}",
            "MAC".bold(),
            "Distance".bold(),
            "Bearing".bold(),
            "Dir".bold(),
            "X (m)".bold(),
            "Y (m)".bold(),
        );

        let mut entries: Vec<_> = self.located_devices.iter().collect();
        entries.sort_by(|a, b| {
            a.1.distance_m
                .partial_cmp(&b.1.distance_m)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (mac, loc) in &entries {
            let mac_str = parser::format_mac(mac);
            println!(
                "  {:>18}  {:>10}  {:>8}  {:>7}  {:>7.2}  {:>8.2}",
                mac_str.yellow(),
                format!("{:.1} m", loc.distance_m).magenta(),
                format!("{:.0}°", loc.bearing_deg).green(),
                loc.compass(),
                loc.x,
                loc.y,
            );
        }
        println!();
    }

    /// Print per-receiver cluster summaries.
    fn print_per_receiver_summary(&self, target_ssid: &str) {
        for (i, engine) in self.engines.iter().enumerate() {
            println!(
                "{}",
                format!("  ── Receiver #{i} ──").bold()
            );
            engine.print_summary(target_ssid);
        }
    }
}

// ---------------------------------------------------------------------------
// Capture thread
// ---------------------------------------------------------------------------

/// Spawn a capture thread for one receiver.
fn spawn_capture_thread(
    receiver_id: usize,
    interface: String,
    tx: Sender<TaggedProbe>,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(e) = capture_loop(receiver_id, &interface, &tx, &running) {
            log::error!("Receiver #{receiver_id} ({interface}) failed: {e}");
        }
    })
}

fn capture_loop(
    receiver_id: usize,
    interface: &str,
    tx: &Sender<TaggedProbe>,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::from(interface);

    let inactive = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true);

    #[cfg(not(target_os = "windows"))]
    let inactive = {
        log::info!("[Rx#{receiver_id}] Requesting rfmon on {interface}.");
        inactive.rfmon(true)
    };
    #[cfg(target_os = "windows")]
    let inactive = {
        log::info!("[Rx#{receiver_id}] Skipping rfmon (Npcap handles it).");
        inactive
    };

    let mut cap = inactive.open()?;

    // Try radiotap → raw 802.11.
    if let Err(e) = cap.set_datalink(pcap::Linktype(127)) {
        log::debug!("[Rx#{receiver_id}] Could not set DLT 127: {e}");
        if let Err(e2) = cap.set_datalink(pcap::Linktype(105)) {
            log::debug!("[Rx#{receiver_id}] Could not set DLT 105: {e2}");
        }
    }

    let dlt = cap.get_datalink().0;
    log::info!(
        "[Rx#{receiver_id}] Capturing on {interface}, DLT={dlt}"
    );

    if dlt != 127 && dlt != 105 {
        return Err(format!(
            "Receiver #{receiver_id}: DLT {dlt} — monitor mode required."
        )
        .into());
    }

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(probe) = parser::parse_probe_request(packet.data, dlt) {
                    let tagged = TaggedProbe {
                        receiver_id,
                        probe,
                        timestamp: Instant::now(),
                    };
                    if tx.send(tagged).is_err() {
                        break; // receiver dropped
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                log::error!("[Rx#{receiver_id}] Capture error: {e}");
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run multi-card capture until interrupted.
pub fn run(
    cfg: MultiCaptureConfig,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let n = cfg.interfaces.len();
    if n < 3 {
        log::warn!(
            "Multi-card mode works best with ≥3 receivers for trilateration. \
             Got {n} — distance will still be estimated per-receiver but \
             direction cannot be determined."
        );
    }

    println!(
        "\n{}",
        format!(
            "  Multi-card capture — {} receivers — channel {} ({} MHz) — SSID \"{}\"",
            n, cfg.channel, cfg.channel_width, cfg.ssid
        )
        .bold()
    );
    for (i, iface) in cfg.interfaces.iter().enumerate() {
        println!("    Receiver #{i}: {iface}");
    }
    println!(
        "  {}",
        "Press Ctrl-C to stop and restore all interfaces.\n"
            .dimmed()
    );

    // MPSC channel for all capture threads → correlator.
    let (tx, rx): (Sender<TaggedProbe>, Receiver<TaggedProbe>) = mpsc::channel();

    // Spawn one capture thread per receiver.
    let handles: Vec<_> = cfg
        .interfaces
        .iter()
        .enumerate()
        .map(|(id, iface)| {
            let iface = iface.clone();
            let tx = tx.clone();
            let running = Arc::clone(&running);
            spawn_capture_thread(id, iface, tx, running)
        })
        .collect();

    // Drop our copy of the sender so the channel closes when all threads exit.
    drop(tx);

    // Main correlation loop.
    let mut correlator = Correlator::new(n, cfg.cluster_cfg, cfg.trilaterator);
    let mut last_summary = Instant::now();
    let summary_interval = Duration::from_secs(5);
    let mut total_probes: u64 = 0;
    let mut matching_probes: u64 = 0;

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(tagged) => {
                total_probes += 1;
                if tagged.probe.ssid.eq_ignore_ascii_case(&cfg.ssid) {
                    matching_probes += 1;

                    let mac_str = parser::format_mac(&tagged.probe.source_mac);
                    let rssi = tagged.probe.signal_dbm.unwrap_or(0);
                    println!(
                        "  {} [Rx#{}] SSID={:?}  MAC={}  RSSI={} dBm",
                        "PROBE".green().bold(),
                        tagged.receiver_id,
                        tagged.probe.ssid,
                        mac_str.yellow(),
                        rssi,
                    );
                }
                correlator.ingest(&tagged, &cfg.ssid);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if !running.load(Ordering::Relaxed) {
            break;
        }

        if last_summary.elapsed() >= summary_interval {
            log::info!(
                "Multi-card stats: {} probes, {} matching SSID \"{}\"",
                total_probes,
                matching_probes,
                cfg.ssid,
            );
            correlator.print_location_summary(&cfg.ssid);
            correlator.print_per_receiver_summary(&cfg.ssid);
            last_summary = Instant::now();
        }
    }

    // Wait for threads.
    for h in handles {
        let _ = h.join();
    }

    // Final summary.
    println!("\n{}", "  ── Final multi-card summary ──".bold().cyan());
    println!(
        "  {} probes captured across {} receivers, {} matching SSID {:?}",
        total_probes, n, matching_probes, cfg.ssid,
    );
    correlator.print_location_summary(&cfg.ssid);
    correlator.print_per_receiver_summary(&cfg.ssid);

    Ok(())
}
