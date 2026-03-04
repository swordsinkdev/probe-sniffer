//! Multi-card triangulation / trilateration.
//!
//! Given RSSI readings from 3 or 4 WiFi adapters arranged at known positions
//! (triangle or square layout), this module estimates the 2D position of a
//! transmitting device using **multilateration** (distance-only positioning).
//!
//! ## Algorithm
//!
//! 1. Each receiver converts RSSI → distance using the log-distance
//!    path-loss model (same formula as [`crate::cluster::estimate_distance`]).
//! 2. With 3+ distance estimates we solve a least-squares trilateration
//!    problem.  For $N$ receivers at positions $(x_i, y_i)$ with estimated
//!    distances $d_i$, we minimize:
//!
//! $$\sum_{i=1}^{N} \bigl((x - x_i)^2 + (y - y_i)^2 - d_i^2\bigr)^2$$
//!
//!    The system is linearized by subtracting the last equation from all
//!    others, yielding an over-determined $Ax = b$ solved via the
//!    pseudo-inverse $(A^T A)^{-1} A^T b$.
//!
//! 3. The result is a 2D coordinate $(x, y)$ relative to the receiver
//!    array's origin.  Direction (bearing) and absolute distance from a
//!    chosen reference point are derived from this coordinate.

use std::f64::consts::PI;

use crate::cluster::estimate_distance;

// ---------------------------------------------------------------------------
// Receiver layout
// ---------------------------------------------------------------------------

/// Position of a single receiver (WiFi adapter) in 2D space.
///
/// Units are metres; the coordinate system is arbitrary but should be
/// consistent across all receivers.
#[derive(Debug, Clone, Copy)]
pub struct ReceiverPosition {
    /// Receiver identifier (matches the interface index in multi-card mode).
    pub id: usize,
    /// X coordinate in metres.
    pub x: f64,
    /// Y coordinate in metres.
    pub y: f64,
}

/// Predefined receiver layouts.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Layout {
    /// Three receivers at the vertices of an equilateral triangle centred on
    /// the origin.
    Triangle,
    /// Four receivers at the corners of a square centred on the origin.
    Square,
}

/// Build receiver positions for a given layout and spacing (side length in
/// metres).
pub fn layout_positions(layout: Layout, side: f64) -> Vec<ReceiverPosition> {
    match layout {
        Layout::Triangle => {
            // Equilateral triangle centred at the origin.
            //
            //       (0)
            //      / \
            //    (1)——(2)
            //
            // Circumradius R = side / √3
            let r = side / 3.0_f64.sqrt();
            vec![
                ReceiverPosition {
                    id: 0,
                    x: 0.0,
                    y: r,
                },
                ReceiverPosition {
                    id: 1,
                    x: -side / 2.0,
                    y: -r / 2.0,
                },
                ReceiverPosition {
                    id: 2,
                    x: side / 2.0,
                    y: -r / 2.0,
                },
            ]
        }
        Layout::Square => {
            // Square centred at the origin.
            //
            //  (0)——(1)
            //   |    |
            //  (3)——(2)
            let half = side / 2.0;
            vec![
                ReceiverPosition {
                    id: 0,
                    x: -half,
                    y: half,
                },
                ReceiverPosition {
                    id: 1,
                    x: half,
                    y: half,
                },
                ReceiverPosition {
                    id: 2,
                    x: half,
                    y: -half,
                },
                ReceiverPosition {
                    id: 3,
                    x: -half,
                    y: -half,
                },
            ]
        }
    }
}

// ---------------------------------------------------------------------------
// Distance measurement from a single receiver
// ---------------------------------------------------------------------------

/// A distance reading from one receiver for a particular device cluster.
#[derive(Debug, Clone)]
pub struct DistanceReading {
    /// Receiver index (matches `ReceiverPosition::id`).
    pub receiver_id: usize,
    /// Estimated distance in metres (derived from RSSI).
    pub distance_m: f64,
    /// The RSSI value this distance was derived from (for diagnostics).
    pub rssi_dbm: f64,
    /// RSSI variance at this receiver (from Welford's); used as a
    /// weight in the weighted least-squares solver.  Lower variance →
    /// higher weight → more trusted reading.  Set to 0.0 if unknown.
    pub rssi_variance: f64,
}

impl DistanceReading {
    /// Create a reading by converting RSSI → distance.
    pub fn from_rssi(receiver_id: usize, rssi: f64, tx_power: f64, path_loss_exp: f64) -> Self {
        let distance_m = estimate_distance(rssi, tx_power, path_loss_exp);
        Self {
            receiver_id,
            distance_m,
            rssi_dbm: rssi,
            rssi_variance: 0.0,
        }
    }

    /// Create a reading with a known RSSI variance (for WLS weighting).
    pub fn from_rssi_with_variance(
        receiver_id: usize,
        rssi: f64,
        tx_power: f64,
        path_loss_exp: f64,
        variance: f64,
    ) -> Self {
        let distance_m = estimate_distance(rssi, tx_power, path_loss_exp);
        Self {
            receiver_id,
            distance_m,
            rssi_dbm: rssi,
            rssi_variance: variance,
        }
    }
}

// ---------------------------------------------------------------------------
// Trilateration result
// ---------------------------------------------------------------------------

/// Estimated 2D position of a device relative to the receiver array.
#[derive(Debug, Clone, Copy)]
pub struct DeviceLocation {
    /// X coordinate in metres.
    pub x: f64,
    /// Y coordinate in metres.
    pub y: f64,
    /// Absolute distance from the array centre (origin) in metres.
    pub distance_m: f64,
    /// Bearing in degrees clockwise from north (positive Y axis).
    /// Range: [0, 360).
    pub bearing_deg: f64,
    /// Residual error of the least-squares fit (lower = more confident).
    pub residual: f64,
}

// ---------------------------------------------------------------------------
// Trilateration solver
// ---------------------------------------------------------------------------

/// Trilateration engine.
///
/// Holds the receiver positions and path-loss parameters and provides a
/// `locate()` method that takes distance readings and returns a position
/// estimate.
#[derive(Debug, Clone)]
pub struct Trilaterator {
    /// Known receiver positions.
    pub receivers: Vec<ReceiverPosition>,
    /// TX power at 1 m reference distance (dBm).
    pub tx_power: f64,
    /// Path-loss exponent.
    pub path_loss_exp: f64,
}

impl Trilaterator {
    pub fn new(receivers: Vec<ReceiverPosition>, tx_power: f64, path_loss_exp: f64) -> Self {
        Self {
            receivers,
            tx_power,
            path_loss_exp,
        }
    }

    /// Convert an RSSI reading from a specific receiver into a
    /// `DistanceReading`.
    pub fn reading_from_rssi(&self, receiver_id: usize, rssi: f64) -> DistanceReading {
        DistanceReading::from_rssi(receiver_id, rssi, self.tx_power, self.path_loss_exp)
    }

    /// Like `reading_from_rssi`, but also supplies RSSI variance so
    /// that the WLS solver can weight this reading appropriately.
    pub fn reading_from_rssi_with_variance(
        &self,
        receiver_id: usize,
        rssi: f64,
        variance: f64,
    ) -> DistanceReading {
        DistanceReading::from_rssi_with_variance(
            receiver_id,
            rssi,
            self.tx_power,
            self.path_loss_exp,
            variance,
        )
    }

    /// Locate a device given distance readings from multiple receivers.
    ///
    /// Requires at least 3 readings from receivers whose positions are
    /// known.  Returns `None` if the system is under-determined or if the
    /// matrix inversion fails.
    ///
    /// ## Algorithm improvements (research-backed)
    ///
    /// 1. **Weighted Least Squares (WLS)**: each reading is weighted by
    ///    $1/\sigma_{\text{RSSI}}^2$ so that receivers with less noisy
    ///    RSSI contribute more to the solution.  This follows the WLS
    ///    positioning technique proposed by Mazuelas et al. (IEEE TSP,
    ///    2009) and ResearchGate weighted-trilateration studies (2019).
    ///
    /// 2. **Iterative Gauss-Newton refinement**: the linearized WLS
    ///    solution is used as an initial guess, then refined via 5
    ///    iterations of the Gauss-Newton method on the nonlinear circle
    ///    equations.  This significantly improves accuracy when distance
    ///    errors are large (as they typically are with RSSI-derived
    ///    distances).
    pub fn locate(&self, readings: &[DistanceReading]) -> Option<DeviceLocation> {
        if readings.len() < 3 {
            log::debug!(
                "Trilateration requires ≥3 readings, got {}",
                readings.len()
            );
            return None;
        }

        // Collect (x_i, y_i, d_i, w_i) tuples.
        let points: Vec<(f64, f64, f64, f64)> = readings
            .iter()
            .filter_map(|r| {
                self.receivers.iter().find(|p| p.id == r.receiver_id).map(|p| {
                    // Weight = 1/σ².  Fall back to uniform weight if
                    // variance is unknown or near-zero.
                    let w = if r.rssi_variance > 0.1 {
                        1.0 / r.rssi_variance
                    } else {
                        1.0
                    };
                    (p.x, p.y, r.distance_m, w)
                })
            })
            .collect();

        if points.len() < 3 {
            return None;
        }

        // ── Phase 1: Weighted linearized least-squares ──────────────
        let initial = self.weighted_linear_solve(&points)?;

        // ── Phase 2: Gauss-Newton iterative refinement ──────────────
        let (x, y) = self.gauss_newton_refine(initial.0, initial.1, &points, 5);

        // Compute residual (RMS of circle-equation errors).
        let residual = rms_residual(x, y, &points);

        let distance_m = (x * x + y * y).sqrt();
        let bearing_deg = bearing_from_origin(x, y);

        Some(DeviceLocation {
            x,
            y,
            distance_m,
            bearing_deg,
            residual,
        })
    }

    /// Weighted linearized least-squares solver (phase 1).
    ///
    /// Linearizes the circle equations by subtracting the last from each,
    /// then solves via the weighted pseudo-inverse $(A^T W A)^{-1} A^T W b$.
    fn weighted_linear_solve(
        &self,
        points: &[(f64, f64, f64, f64)],
    ) -> Option<(f64, f64)> {
        let n = points.len();
        let (xn, yn, dn, _wn) = points[n - 1];

        let rows = n - 1;
        let mut a = vec![0.0_f64; rows * 2];
        let mut b = vec![0.0_f64; rows];
        let mut w = vec![0.0_f64; rows]; // diagonal weights

        for i in 0..rows {
            let (xi, yi, di, wi) = points[i];
            a[i * 2] = 2.0 * (xn - xi);
            a[i * 2 + 1] = 2.0 * (yn - yi);
            b[i] = di * di - dn * dn - xi * xi + xn * xn - yi * yi + yn * yn;
            // Combine weights of both equations involved in subtraction.
            w[i] = (wi + _wn) / 2.0;
        }

        let (atwa, atwb) = atwa_atwb(&a, &b, &w, rows);
        solve_2x2(&atwa, &atwb)
    }

    /// Gauss-Newton iterative refinement (phase 2).
    ///
    /// Starting from an initial (x, y), iteratively minimises the
    /// weighted sum of squared residuals of the circle equations:
    ///
    /// $$r_i = \sqrt{(x-x_i)^2 + (y-y_i)^2} - d_i$$
    ///
    /// The Jacobian at each iteration is:
    /// $$J_{i,0} = \frac{x - x_i}{\hat{d}_i}, \quad
    ///   J_{i,1} = \frac{y - y_i}{\hat{d}_i}$$
    ///
    /// Update: $\Delta = (J^T W J)^{-1} J^T W r$
    fn gauss_newton_refine(
        &self,
        mut x: f64,
        mut y: f64,
        points: &[(f64, f64, f64, f64)],
        iterations: usize,
    ) -> (f64, f64) {
        for _ in 0..iterations {
            let n = points.len();
            // Build Jacobian (n×2), residual vector (n×1), weight (n×1).
            let mut jac = vec![0.0_f64; n * 2];
            let mut res = vec![0.0_f64; n];
            let mut wt = vec![0.0_f64; n];

            for (i, &(xi, yi, di, wi)) in points.iter().enumerate() {
                let dx = x - xi;
                let dy = y - yi;
                let d_hat = (dx * dx + dy * dy).sqrt().max(1e-6);
                jac[i * 2] = dx / d_hat;
                jac[i * 2 + 1] = dy / d_hat;
                res[i] = d_hat - di;
                wt[i] = wi;
            }

            // Solve (J^T W J) Δ = J^T W r  for Δ = [Δx, Δy].
            let (jtwj, jtwr) = atwa_atwb(&jac, &res, &wt, n);
            if let Some((dx, dy)) = solve_2x2(&jtwj, &jtwr) {
                x -= dx;
                y -= dy;
                // Convergence check.
                if dx * dx + dy * dy < 1e-8 {
                    break;
                }
            } else {
                break; // singular — stop iterating
            }
        }
        (x, y)
    }
}

// ---------------------------------------------------------------------------
// Linear-algebra helpers (2×2 only — no external dependency needed)
// ---------------------------------------------------------------------------

/// Compute AᵀA (2×2) and Aᵀb (2×1) for an (rows × 2) matrix A and (rows × 1)
/// vector b.
#[allow(dead_code)]
fn ata_atb(a: &[f64], b: &[f64], rows: usize, _cols: usize) -> ([f64; 4], [f64; 2]) {
    let mut ata = [0.0_f64; 4]; // row-major 2×2
    let mut atb = [0.0_f64; 2];

    for i in 0..rows {
        let a0 = a[i * 2];
        let a1 = a[i * 2 + 1];
        ata[0] += a0 * a0;
        ata[1] += a0 * a1;
        ata[2] += a1 * a0;
        ata[3] += a1 * a1;
        atb[0] += a0 * b[i];
        atb[1] += a1 * b[i];
    }

    (ata, atb)
}

/// Compute AᵀWA (2×2) and AᵀWb (2×1) for an (rows × 2) matrix A, (rows × 1)
/// vector b, and diagonal weight vector w.
fn atwa_atwb(a: &[f64], b: &[f64], w: &[f64], rows: usize) -> ([f64; 4], [f64; 2]) {
    let mut atwa = [0.0_f64; 4]; // row-major 2×2
    let mut atwb = [0.0_f64; 2];

    for i in 0..rows {
        let a0 = a[i * 2];
        let a1 = a[i * 2 + 1];
        let wi = w[i];
        atwa[0] += a0 * wi * a0;
        atwa[1] += a0 * wi * a1;
        atwa[2] += a1 * wi * a0;
        atwa[3] += a1 * wi * a1;
        atwb[0] += a0 * wi * b[i];
        atwb[1] += a1 * wi * b[i];
    }

    (atwa, atwb)
}

/// RMS of circle-equation residuals (how well the solution fits).
fn rms_residual(x: f64, y: f64, points: &[(f64, f64, f64, f64)]) -> f64 {
    let sum_sq: f64 = points
        .iter()
        .map(|&(xi, yi, di, _)| {
            let actual = ((x - xi).powi(2) + (y - yi).powi(2)).sqrt();
            (actual - di).powi(2)
        })
        .sum();
    (sum_sq / points.len() as f64).sqrt()
}

/// Solve a 2×2 system  M·x = v  via Cramer's rule.
/// Returns `None` if the determinant is (near) zero.
fn solve_2x2(m: &[f64; 4], v: &[f64; 2]) -> Option<(f64, f64)> {
    let det = m[0] * m[3] - m[1] * m[2];
    if det.abs() < 1e-12 {
        log::debug!("Trilateration matrix is singular (det={det:.2e})");
        return None;
    }
    let x = (v[0] * m[3] - v[1] * m[1]) / det;
    let y = (m[0] * v[1] - m[2] * v[0]) / det;
    Some((x, y))
}

/// Bearing in degrees clockwise from north (positive Y axis).
fn bearing_from_origin(x: f64, y: f64) -> f64 {
    let rad = x.atan2(y); // atan2(x, y) gives angle from +Y axis
    let deg = rad * 180.0 / PI;
    if deg < 0.0 {
        deg + 360.0
    } else {
        deg
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

impl DeviceLocation {
    /// Human-readable compass direction from bearing.
    pub fn compass(&self) -> &'static str {
        match self.bearing_deg {
            b if b < 22.5 || b >= 337.5 => "N",
            b if b < 67.5 => "NE",
            b if b < 112.5 => "E",
            b if b < 157.5 => "SE",
            b if b < 202.5 => "S",
            b if b < 247.5 => "SW",
            b if b < 292.5 => "W",
            _ => "NW",
        }
    }
}

impl std::fmt::Display for DeviceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({:.2}, {:.2}) m — {:.1} m @ {:.0}° {} (residual {:.2})",
            self.x,
            self.y,
            self.distance_m,
            self.bearing_deg,
            self.compass(),
            self.residual,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tri_receivers(side: f64) -> Vec<ReceiverPosition> {
        layout_positions(Layout::Triangle, side)
    }

    fn sq_receivers(side: f64) -> Vec<ReceiverPosition> {
        layout_positions(Layout::Square, side)
    }

    #[test]
    fn test_triangle_layout_centred() {
        let positions = tri_receivers(1.0);
        // Centroid should be near origin.
        let cx: f64 = positions.iter().map(|p| p.x).sum::<f64>() / 3.0;
        let cy: f64 = positions.iter().map(|p| p.y).sum::<f64>() / 3.0;
        assert!(cx.abs() < 1e-10);
        assert!(cy.abs() < 1e-10);
    }

    #[test]
    fn test_square_layout_centred() {
        let positions = sq_receivers(2.0);
        let cx: f64 = positions.iter().map(|p| p.x).sum::<f64>() / 4.0;
        let cy: f64 = positions.iter().map(|p| p.y).sum::<f64>() / 4.0;
        assert!(cx.abs() < 1e-10);
        assert!(cy.abs() < 1e-10);
    }

    #[test]
    fn test_trilat_known_point() {
        // Place receivers at a known triangle with side = 2 m.
        let receivers = vec![
            ReceiverPosition { id: 0, x: 0.0, y: 0.0 },
            ReceiverPosition { id: 1, x: 2.0, y: 0.0 },
            ReceiverPosition { id: 2, x: 1.0, y: 1.732 }, // ~√3
        ];
        let trilat = Trilaterator::new(receivers, -40.0, 3.0);

        // Simulated device at (1.0, 0.5).
        let target = (1.0_f64, 0.5_f64);
        let readings: Vec<DistanceReading> = trilat
            .receivers
            .iter()
            .map(|r| {
                let d = ((target.0 - r.x).powi(2) + (target.1 - r.y).powi(2)).sqrt();
                DistanceReading {
                    receiver_id: r.id,
                    distance_m: d,
                    rssi_dbm: -50.0, // dummy
                    rssi_variance: 0.0,
                }
            })
            .collect();

        let loc = trilat.locate(&readings).expect("should solve");
        assert!(
            (loc.x - target.0).abs() < 0.01,
            "x: expected {}, got {}",
            target.0,
            loc.x
        );
        assert!(
            (loc.y - target.1).abs() < 0.01,
            "y: expected {}, got {}",
            target.1,
            loc.y
        );
    }

    #[test]
    fn test_trilat_four_receivers() {
        let receivers = sq_receivers(2.0);
        let trilat = Trilaterator::new(receivers, -40.0, 3.0);

        let target = (0.3, -0.7);
        let readings: Vec<DistanceReading> = trilat
            .receivers
            .iter()
            .map(|r| {
                let d = ((target.0 - r.x).powi(2) + (target.1 - r.y).powi(2)).sqrt();
                DistanceReading {
                    receiver_id: r.id,
                    distance_m: d,
                    rssi_dbm: -50.0,
                    rssi_variance: 0.0,
                }
            })
            .collect();

        let loc = trilat.locate(&readings).expect("should solve");
        assert!(
            (loc.x - target.0).abs() < 0.01,
            "x: expected {}, got {}",
            target.0,
            loc.x
        );
        assert!(
            (loc.y - target.1).abs() < 0.01,
            "y: expected {}, got {}",
            target.1,
            loc.y
        );
    }

    #[test]
    fn test_bearing_north() {
        let b = bearing_from_origin(0.0, 1.0);
        assert!((b - 0.0).abs() < 0.1, "expected ~0° N, got {b}");
    }

    #[test]
    fn test_bearing_east() {
        let b = bearing_from_origin(1.0, 0.0);
        assert!((b - 90.0).abs() < 0.1, "expected ~90° E, got {b}");
    }

    #[test]
    fn test_bearing_south() {
        let b = bearing_from_origin(0.0, -1.0);
        assert!((b - 180.0).abs() < 0.1, "expected ~180° S, got {b}");
    }

    #[test]
    fn test_bearing_west() {
        let b = bearing_from_origin(-1.0, 0.0);
        assert!((b - 270.0).abs() < 0.1, "expected ~270° W, got {b}");
    }

    #[test]
    fn test_too_few_readings() {
        let receivers = tri_receivers(1.0);
        let trilat = Trilaterator::new(receivers, -40.0, 3.0);
        let readings = vec![
            DistanceReading { receiver_id: 0, distance_m: 1.0, rssi_dbm: -50.0, rssi_variance: 0.0 },
            DistanceReading { receiver_id: 1, distance_m: 1.0, rssi_dbm: -50.0, rssi_variance: 0.0 },
        ];
        assert!(trilat.locate(&readings).is_none());
    }

    #[test]
    fn test_compass_directions() {
        let loc = DeviceLocation { x: 0.0, y: 1.0, distance_m: 1.0, bearing_deg: 0.0, residual: 0.0 };
        assert_eq!(loc.compass(), "N");
        let loc = DeviceLocation { x: 1.0, y: 0.0, distance_m: 1.0, bearing_deg: 90.0, residual: 0.0 };
        assert_eq!(loc.compass(), "E");
        let loc = DeviceLocation { x: 0.0, y: -1.0, distance_m: 1.0, bearing_deg: 180.0, residual: 0.0 };
        assert_eq!(loc.compass(), "S");
        let loc = DeviceLocation { x: -1.0, y: 0.0, distance_m: 1.0, bearing_deg: 270.0, residual: 0.0 };
        assert_eq!(loc.compass(), "W");
    }
}
