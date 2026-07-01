//! Compact t-digest implementation for streaming latency quantiles.
//!
//! This implementation keeps weighted centroids and periodically compresses with
//! the standard t-digest invariant: centroid capacity shrinks near distribution
//! tails and grows near the median. It is deterministic, allocation-light, and
//! suitable for building p50/p90/p95/p99 summaries from streaming metrics.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Centroid {
    pub mean: f64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TDigest {
    compression: f64,
    centroids: Vec<Centroid>,
    count: f64,
    min: f64,
    max: f64,
    uncompressed: usize,
}

impl Default for TDigest {
    fn default() -> Self {
        Self::new(100.0)
    }
}

impl TDigest {
    pub fn new(compression: f64) -> Self {
        Self {
            compression: compression.max(20.0),
            centroids: Vec::new(),
            count: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            uncompressed: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.centroids.len()
    }

    pub fn count(&self) -> u64 {
        self.count as u64
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0.0
    }

    pub fn add(&mut self, value: f64) {
        self.add_weighted(value, 1.0);
    }

    pub fn add_weighted(&mut self, value: f64, weight: f64) {
        if !value.is_finite() || !weight.is_finite() || weight <= 0.0 {
            return;
        }
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.count += weight;
        self.centroids.push(Centroid { mean: value, weight });
        self.uncompressed += 1;
        if self.uncompressed > (self.compression as usize * 8).max(128) {
            self.compress();
        }
    }

    pub fn merge(&mut self, other: &TDigest) {
        for c in &other.centroids {
            self.add_weighted(c.mean, c.weight);
        }
        self.compress();
    }

    pub fn compress(&mut self) {
        if self.centroids.len() <= 1 {
            self.uncompressed = 0;
            return;
        }
        self.centroids.sort_by(|a, b| a.mean.total_cmp(&b.mean));
        let total = self.count.max(1.0);
        let mut compressed: Vec<Centroid> = Vec::with_capacity(self.centroids.len());
        let mut cumulative = 0.0;
        let mut current = self.centroids[0];

        for next in self.centroids.iter().copied().skip(1) {
            let proposed = current.weight + next.weight;
            let q = (cumulative + proposed / 2.0) / total;
            // The 4*n*q*(1-q)/delta rule is the common t-digest size bound.
            let max_weight = (4.0 * total * q * (1.0 - q) / self.compression).max(1.0);
            if proposed <= max_weight {
                current.mean = (current.mean * current.weight + next.mean * next.weight) / proposed;
                current.weight = proposed;
            } else {
                cumulative += current.weight;
                compressed.push(current);
                current = next;
            }
        }
        compressed.push(current);
        self.centroids = compressed;
        self.uncompressed = 0;
    }

    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count == 0.0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        if q == 0.0 {
            return Some(self.min);
        }
        if q == 1.0 {
            return Some(self.max);
        }

        let mut cents = self.centroids.clone();
        cents.sort_by(|a, b| a.mean.total_cmp(&b.mean));
        if cents.len() == 1 {
            return Some(cents[0].mean);
        }

        let rank = q * (self.count - 1.0);
        let mut prev_center = 0.0;
        let mut prev_mean = self.min;
        let mut cumulative = 0.0;

        for (i, c) in cents.iter().enumerate() {
            let center = cumulative + (c.weight - 1.0) / 2.0;
            if rank <= center {
                if i == 0 {
                    let denom = center.max(1e-12);
                    let t = (rank / denom).clamp(0.0, 1.0);
                    return Some(self.min + (c.mean - self.min) * t);
                }
                let denom = (center - prev_center).max(1e-12);
                let t = ((rank - prev_center) / denom).clamp(0.0, 1.0);
                return Some(prev_mean + (c.mean - prev_mean) * t);
            }
            prev_center = center;
            prev_mean = c.mean;
            cumulative += c.weight;
        }

        let last_center = self.count - 1.0;
        let denom = (last_center - prev_center).max(1e-12);
        let t = ((rank - prev_center) / denom).clamp(0.0, 1.0);
        Some(prev_mean + (self.max - prev_mean) * t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_quantiles_for_uniform_distribution() {
        let mut d = TDigest::new(100.0);
        for i in 1..=10_000 {
            d.add(i as f64);
        }
        d.compress();
        assert!(d.len() < 1_000, "digest should be compact, got {}", d.len());
        for (q, expected, tolerance) in [(0.50, 5_000.5, 55.0), (0.90, 9_000.1, 90.0), (0.95, 9_500.05, 100.0), (0.99, 9_900.01, 110.0)] {
            let got = d.quantile(q).unwrap();
            assert!((got - expected).abs() <= tolerance, "q={q}: got {got}, expected {expected}");
        }
    }

    #[test]
    fn merge_preserves_tail_accuracy() {
        let mut a = TDigest::new(120.0);
        let mut b = TDigest::new(120.0);
        for i in 1..=5_000 { a.add(i as f64); }
        for i in 5_001..=10_000 { b.add(i as f64); }
        a.merge(&b);
        assert!((a.quantile(0.99).unwrap() - 9_900.01).abs() < 100.0);
    }
}
