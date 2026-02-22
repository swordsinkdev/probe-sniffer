//! Signal-strength-based device clustering.
//!
//! Since modern devices randomize their MAC addresses when sending probe
//! requests, we cannot rely on the source address to count unique devices.
//! Instead we cluster observations by RSSI: devices at approximately the same
//! physical distance produce signals in a narrow dBm band.  Each cluster
//! represents one *estimated* unique device.
//!
//! ## Pruning strategy
//!
//! Not every cluster is a real device.  Transient readings, multipath
//! reflections, and noise create short-lived low-count clusters.  The engine
//! applies several filters:
//!
//! 1. **Minimum observation threshold** — a cluster must accumulate at least
//!    `min_probes` observations before it is reported as a device.
//! 2. **TTL expiry** — clusters that haven't been seen for `ttl` seconds are
//!    removed entirely.
//! 3. **Merge guard** — if two clusters drift close enough together (within
//!    half the bandwidth), the weaker one is absorbed into the stronger.
//! 4. **Confidence score** — clusters are ranked by a score combining
//!    observation count, recency, and MAC diversity.  Only "confirmed"
//!    clusters (score ≥ threshold) are reported.

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
    /// Timestamp of the first observation.
    pub first_seen: Instant,
    /// Timestamp of the most recent observation.
    pub last_seen: Instant,
    /// Estimated distance in metres (updated on each observation).
    pub estimated_distance_m: f64,
    /// Running variance accumulator for RSSI (Welford's algorithm).
    rssi_m2: f64,
    /// Number of samples fed into the variance accumulator.
    rssi_n: u64,
    /// Running mean for Welford's.
    rssi_mean: f64,
}

impl DeviceCluster {
    /// RSSI standard deviation — a tight spread indicates a stationary device.
    pub fn rssi_std_dev(&self) -> f64 {
        if self.rssi_n < 2 {
            return f64::MAX;
        }
        (self.rssi_m2 / (self.rssi_n - 1) as f64).sqrt()
    }

    /// Confidence score: higher = more likely a real device.
    ///
    /// Factors:
    /// - observation count (log-scaled so bursts don't dominate)
    /// - recency (exponential decay)
    /// - low RSSI variance (tight cluster = more confidence)
    pub fn confidence(&self, now: Instant) -> f64 {
        let count_score = (self.observation_count as f64).ln_1p(); // log(1+n)
        let age_secs = now.duration_since(self.last_seen).as_secs_f64();
        let recency = (-age_secs / 30.0).exp(); // half-life ~20 s
        let variance_penalty = if self.rssi_std_dev() < 8.0 {
            1.0
        } else {
            0.5
        };
        count_score * recency * variance_penalty
    }
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
    /// Minimum number of probe requests before a cluster is reported as a
    /// confirmed device.  Set to 1 to disable this filter.
    pub min_probes: u64,
    /// Minimum confidence score to be reported as a device.
    pub min_confidence: f64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            rssi_bandwidth: 5.0,
            tx_power: -40.0,
            path_loss_exp: 3.0,
            ttl: Duration::from_secs(60),
            min_probes: 3,
            min_confidence: 0.5,
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

        // 1. Prune stale clusters.
        self.clusters.retain(|c| now.duration_since(c.last_seen) < self.cfg.ttl);

        // 2. Merge clusters that have drifted too close together.
        self.merge_overlapping(now);

        // 3. Find the closest cluster within the bandwidth.
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

                // Welford's online variance update.
                cluster.rssi_n += 1;
                let delta = rssi_f - cluster.rssi_mean;
                cluster.rssi_mean += delta / cluster.rssi_n as f64;
                let delta2 = rssi_f - cluster.rssi_mean;
                cluster.rssi_m2 += delta * delta2;

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
                    first_seen: now,
                    last_seen: now,
                    estimated_distance_m,
                    rssi_m2: 0.0,
                    rssi_n: 1,
                    rssi_mean: rssi_f,
                });
                id
            }
        }
    }

    /// Merge clusters whose centres have drifted within half the bandwidth.
    fn merge_overlapping(&mut self, now: Instant) {
        let merge_threshold = self.cfg.rssi_bandwidth * 0.5;
        let mut i = 0;
        while i < self.clusters.len() {
            let mut j = i + 1;
            while j < self.clusters.len() {
                let dist = (self.clusters[i].center_rssi - self.clusters[j].center_rssi).abs();
                if dist < merge_threshold {
                    // Keep the cluster with more observations (higher confidence).
                    let (keep, absorb) = if self.clusters[i].confidence(now)
                        >= self.clusters[j].confidence(now)
                    {
                        (i, j)
                    } else {
                        (j, i)
                    };

                    log::debug!(
                        "Merging cluster #{} into #{} (RSSI diff {:.1} dBm)",
                        self.clusters[absorb].id,
                        self.clusters[keep].id,
                        dist,
                    );

                    // Transfer data from absorbed → keeper.
                    let absorbed = self.clusters.remove(absorb);
                    let keeper = &mut self.clusters[if absorb < keep { keep - 1 } else { keep }];
                    keeper.observation_count += absorbed.observation_count;
                    for m in absorbed.mac_addresses {
                        keeper.mac_addresses.insert(m);
                    }
                    if absorbed.first_seen < keeper.first_seen {
                        keeper.first_seen = absorbed.first_seen;
                    }
                    if absorbed.last_seen > keeper.last_seen {
                        keeper.last_seen = absorbed.last_seen;
                    }

                    // Don't increment j — the vec shifted.
                    if absorb <= i && i > 0 {
                        i -= 1; // i shifted too
                    }
                    continue;
                }
                j += 1;
            }
            i += 1;
        }
    }

    /// Number of **confirmed** device clusters (meeting min_probes and
    /// min_confidence thresholds).
    pub fn device_count(&self) -> usize {
        let now = Instant::now();
        self.confirmed_clusters(now).len()
    }

    /// Number of raw (unfiltered) clusters, including unconfirmed ones.
    pub fn raw_cluster_count(&self) -> usize {
        let now = Instant::now();
        self.clusters
            .iter()
            .filter(|c| now.duration_since(c.last_seen) < self.cfg.ttl)
            .count()
    }

    /// Return only confirmed clusters — those meeting the minimum probe
    /// count and confidence thresholds.
    fn confirmed_clusters(&self, now: Instant) -> Vec<&DeviceCluster> {
        self.clusters
            .iter()
            .filter(|c| {
                now.duration_since(c.last_seen) < self.cfg.ttl
                    && c.observation_count >= self.cfg.min_probes
                    && c.confidence(now) >= self.cfg.min_confidence
            })
            .collect()
    }

    /// Snapshot of all **confirmed** clusters, sorted by distance.
    pub fn clusters(&self) -> Vec<&DeviceCluster> {
        let now = Instant::now();
        let mut out = self.confirmed_clusters(now);
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
        let raw = self.raw_cluster_count();
        let confirmed = clusters.len();

        if clusters.is_empty() {
            if raw > 0 {
                println!(
                    "{}",
                    format!(
                        "  {} raw cluster(s) detected, but none confirmed yet \
                         (need ≥{} probes per device).",
                        raw, self.cfg.min_probes
                    )
                    .dimmed()
                );
            } else {
                println!("{}", "  No devices detected yet.".dimmed());
            }
            return;
        }

        println!(
            "\n{}",
            format!(
                "  ── Unique devices probing for \"{}\":  {} confirmed  ({} raw clusters) ──",
                target_ssid, confirmed, raw,
            )
            .bold()
            .cyan()
        );
        println!(
            "  {:>4}  {:>8}  {:>10}  {:>6}  {:>5}  {:>6}  {}",
            "ID".bold(),
            "RSSI".bold(),
            "Distance".bold(),
            "Probes".bold(),
            "σ(dB)".bold(),
            "Score".bold(),
            "MACs seen".bold(),
        );

        for c in &clusters {
            let rssi_str = format!("{:.0} dBm", c.center_rssi);
            let dist_str = if c.estimated_distance_m < 1.0 {
                format!("{:.2} m", c.estimated_distance_m)
            } else {
                format!("{:.1} m", c.estimated_distance_m)
            };
            let std_str = if c.rssi_n >= 2 {
                format!("{:.1}", c.rssi_std_dev())
            } else {
                " -".to_string()
            };
            let score_str = format!("{:.2}", c.confidence(Instant::now()));
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
                "  {:>4}  {:>8}  {:>10}  {:>6}  {:>5}  {:>6}  {}",
                c.id.to_string().yellow(),
                rssi_str.green(),
                dist_str.magenta(),
                c.observation_count,
                std_str,
                score_str,
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
        // At RSSI == tx_power the device is at the reference distance (1 m).
        let d = estimate_distance(-40.0, -40.0, 3.0);
        assert!((d - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_clustering_same_device() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            rssi_bandwidth: 5.0,
            min_probes: 1,
            min_confidence: 0.0,
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
            min_probes: 1,
            min_confidence: 0.0,
            ..Default::default()
        });
        let id1 = engine.observe(-40, [0xAA; 6]);
        let id2 = engine.observe(-60, [0xBB; 6]);
        assert_ne!(id1, id2);
        assert_eq!(engine.device_count(), 2);
    }

    #[test]
    fn test_min_probes_filters_noise() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            rssi_bandwidth: 5.0,
            min_probes: 3,
            min_confidence: 0.0,
            ..Default::default()
        });
        // One observation → raw cluster exists but not confirmed.
        engine.observe(-50, [0xAA; 6]);
        assert_eq!(engine.raw_cluster_count(), 1);
        assert_eq!(engine.device_count(), 0);

        // Two more → confirmed.
        engine.observe(-51, [0xBB; 6]);
        engine.observe(-49, [0xCC; 6]);
        assert_eq!(engine.device_count(), 1);
    }

    #[test]
    fn test_merge_overlapping() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            rssi_bandwidth: 6.0,
            min_probes: 1,
            min_confidence: 0.0,
            ..Default::default()
        });
        // Two clusters at -50 and -53 → within half-bandwidth (3.0) → merge.
        engine.observe(-50, [0xAA; 6]);
        engine.observe(-53, [0xBB; 6]);
        // After merge there should only be 1 raw cluster.
        assert_eq!(engine.raw_cluster_count(), 1);
    }

    #[test]
    fn test_confidence_increases() {
        let mut engine = ClusterEngine::new(ClusterConfig {
            min_probes: 1,
            min_confidence: 0.0,
            ..Default::default()
        });
        engine.observe(-50, [0xAA; 6]);
        let c1 = engine.clusters[0].confidence(Instant::now());
        engine.observe(-51, [0xBB; 6]);
        let c2 = engine.clusters[0].confidence(Instant::now());
        assert!(c2 > c1, "confidence should increase with more observations");
    }
}
