//! Signal-strength-based device clustering.
//!
//! Since modern devices randomize their MAC addresses when sending probe
//! requests, we cannot rely on the source address to count unique devices.
//! Instead we cluster observations by RSSI: devices at approximately the same
//! physical distance produce signals in a narrow dBm band. Each cluster
//! represents one *estimated* unique device.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::parser;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single captured observation (one probe request).
#[derive(Debug, Clone)]
pub struct Observation {
    pub timestamp: Instant,
    pub rssi: i8,
    pub mac: [u8; 6],
}

/// A cluster of observations believed to originate from one device.
#[derive(Debug)]
pub struct DeviceCluster {
    /// Monotonically increasing cluster identifier.
    pub id: usize,
    /// Exponential moving average of RSSI values in this cluster.
    pub center_rssi: f64,
    /// Total number of probe requests attributed to this cluster.
    pub observation_count: u64,
    /// Set of *distinct* MAC addresses observed (shows randomization).
    pub mac_addresses: HashSet<[u8; 6]>,
    /// Timestamp of the most recent observation.
    pub last_seen: Instant,
    /// Estimated distance in metres (updated on each observation).
    pub estimated_distance_m: f64,
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Maximum RSSI difference (dBm) for two readings to be considered the
    /// same device.
    pub rssi_bandwidth: f64,
    /// Assumed transmit power at 1 m reference distance (dBm).  A typical
    /// smartphone emits roughly −40 dBm at 1 m.
    pub tx_power: f64,
    /// Path-loss exponent.  ~2.0 for free-space, 2.7–4.0 indoors.
    pub path_loss_exp: f64,
    /// How long a cluster survives without new observations before it is
    /// pruned.
    pub ttl: Duration,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            rssi_bandwidth: 5.0,
            tx_power: -40.0,
            path_loss_exp: 3.0,
            ttl: Duration::from_secs(60),
        }
    }
}

// ---------------------------------------------------------------------------
// Cluster engine
// ---------------------------------------------------------------------------

pub struct ClusterEngine {
    cfg: ClusterConfig,
    clusters: Vec<DeviceCluster>,
    next_id: usize,
}

impl ClusterEngine {
    pub fn new(cfg: ClusterConfig) -> Self {
        Self {
            cfg,
            clusters: Vec::new(),
            next_id: 1,
        }
    }

    /// Feed a new observation into the engine.  Returns the cluster it was
    /// assigned to (by id).
    pub fn observe(&mut self, rssi: i8, mac: [u8; 6]) -> usize {
        let now = Instant::now();

        // Prune stale clusters first.
        self.clusters.retain(|c| now.duration_since(c.last_seen) < self.cfg.ttl);

        // Find the closest cluster within the bandwidth.
        let rssi_f = rssi as f64;
        let mut best_idx: Option<usize> = None;
        let mut best_dist = f64::MAX;

        for (i, cluster) in self.clusters.iter().enumerate() {
            let d = (cluster.center_rssi - rssi_f).abs();
            if d < self.cfg.rssi_bandwidth && d < best_dist {
                best_dist = d;
                best_idx = Some(i);
            }
        }

        match best_idx {
            Some(idx) => {
                let cluster = &mut self.clusters[idx];
                // Exponential moving average (α = 0.3).
                const ALPHA: f64 = 0.3;
                cluster.center_rssi =
                    ALPHA * rssi_f + (1.0 - ALPHA) * cluster.center_rssi;
                cluster.observation_count += 1;
                cluster.mac_addresses.insert(mac);
                cluster.last_seen = now;
                cluster.estimated_distance_m =
                    estimate_distance(cluster.center_rssi, self.cfg.tx_power, self.cfg.path_loss_exp);
                cluster.id
            }
            None => {
                let id = self.next_id;
                self.next_id += 1;
                let estimated_distance_m =
                    estimate_distance(rssi_f, self.cfg.tx_power, self.cfg.path_loss_exp);
                let mut macs = HashSet::new();
                macs.insert(mac);
                self.clusters.push(DeviceCluster {
                    id,
                    center_rssi: rssi_f,
                    observation_count: 1,
                    mac_addresses: macs,
                    last_seen: now,
                    estimated_distance_m,
                });
                id
            }
        }
    }

    /// Number of active (non-expired) device clusters.
    pub fn device_count(&self) -> usize {
        let now = Instant::now();
        self.clusters
            .iter()
            .filter(|c| now.duration_since(c.last_seen) < self.cfg.ttl)
            .count()
    }

    /// Snapshot of all active clusters, sorted by distance.
    pub fn clusters(&self) -> Vec<&DeviceCluster> {
        let now = Instant::now();
        let mut out: Vec<&DeviceCluster> = self
            .clusters
            .iter()
            .filter(|c| now.duration_since(c.last_seen) < self.cfg.ttl)
            .collect();
        out.sort_by(|a, b| {
            a.estimated_distance_m
                .partial_cmp(&b.estimated_distance_m)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    /// Print a summary table to stdout.
    pub fn print_summary(&self, target_ssid: &str) {
        use colored::Colorize;

        let clusters = self.clusters();
        if clusters.is_empty() {
            println!(
                "{}",
                "  No devices detected yet.".dimmed()
            );
            return;
        }

        println!(
            "\n{}",
            format!(
                "  ── Unique devices probing for \"{}\":  {} ──",
                target_ssid,
                clusters.len()
            )
            .bold()
            .cyan()
        );
        println!(
            "  {:>4}  {:>8}  {:>10}  {:>6}  {}",
            "ID".bold(),
            "RSSI".bold(),
            "Distance".bold(),
            "Probes".bold(),
            "MACs seen".bold(),
        );

        for c in &clusters {
            let rssi_str = format!("{:.0} dBm", c.center_rssi);
            let dist_str = if c.estimated_distance_m < 1.0 {
                format!("{:.2} m", c.estimated_distance_m)
            } else {
                format!("{:.1} m", c.estimated_distance_m)
            };
            let mac_list: Vec<String> = c
                .mac_addresses
                .iter()
                .take(3)
                .map(|m| parser::format_mac(m))
                .collect();
            let mac_str = if c.mac_addresses.len() > 3 {
                format!("{} (+{})", mac_list.join(", "), c.mac_addresses.len() - 3)
            } else {
                mac_list.join(", ")
            };
            let randomized = c
                .mac_addresses
                .iter()
                .any(|m| parser::is_randomized_mac(m));

            let mac_display = if randomized {
                format!("{} {}", mac_str, "(randomized)".dimmed())
            } else {
                mac_str
            };

            println!(
                "  {:>4}  {:>8}  {:>10}  {:>6}  {}",
                c.id.to_string().yellow(),
                rssi_str.green(),
                dist_str.magenta(),
                c.observation_count,
                mac_display,
            );
        }
        println!();
    }
}

// ---------------------------------------------------------------------------
// Distance estimation (log-distance path-loss model)
// ---------------------------------------------------------------------------

/// Estimate distance in metres from RSSI using the log-distance path-loss
/// model:
///
///   RSSI = tx_power − 10 · n · log₁₀(d)
///   ⟹  d = 10^((tx_power − RSSI) / (10 · n))
///
/// Returns a lower-bound estimate; real-world accuracy depends heavily on
/// the environment.
pub fn estimate_distance(rssi: f64, tx_power: f64, path_loss_exp: f64) -> f64 {
    let exponent = (tx_power - rssi) / (10.0 * path_loss_exp);
    10.0_f64.powf(exponent).max(0.1) // clamp to at least 10 cm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_at_reference() {
        // At RSI == tx_power the device is at the reference distance (1 m).
        let d = estimate_distance(-40.0, -40.0, 3.0);
        assert!((d - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_clustering_same_device() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            rssi_bandwidth: 5.0,
            ..Default::default()
        });
        // Two readings within 5 dBm → same cluster.
        let id1 = engine.observe(-50, [0xAA; 6]);
        let id2 = engine.observe(-52, [0xBB; 6]);
        assert_eq!(id1, id2);
        assert_eq!(engine.device_count(), 1);
    }

    #[test]
    fn test_clustering_different_devices() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            rssi_bandwidth: 5.0,
            ..Default::default()
        });
        let id1 = engine.observe(-40, [0xAA; 6]);
        let id2 = engine.observe(-60, [0xBB; 6]);
        assert_ne!(id1, id2);
        assert_eq!(engine.device_count(), 2);
    }
}
