//! Exponential base-2 histogram for compact value distributions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramBucket {
    pub lower: f64,
    pub upper: f64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exp2Histogram {
    zero_count: u64,
    buckets: BTreeMap<i32, u64>,
}

impl Exp2Histogram {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        if value == 0.0 {
            self.zero_count += 1;
            return;
        }
        let idx = value.log2().floor() as i32;
        *self.buckets.entry(idx).or_insert(0) += 1;
    }

    pub fn total_count(&self) -> u64 {
        self.zero_count + self.buckets.values().sum::<u64>()
    }

    pub fn buckets(&self) -> Vec<HistogramBucket> {
        let mut out = Vec::new();
        if self.zero_count > 0 {
            out.push(HistogramBucket { lower: 0.0, upper: 0.0, count: self.zero_count });
        }
        out.extend(self.buckets.iter().map(|(idx, count)| HistogramBucket {
            lower: 2f64.powi(*idx),
            upper: 2f64.powi(*idx + 1),
            count: *count,
        }));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_values_by_powers_of_two() {
        let mut h = Exp2Histogram::new();
        for v in [0.0, 0.25, 0.5, 1.0, 1.9, 2.0, 3.99, 4.0, 8.0, 9.0] {
            h.record(v);
        }
        assert_eq!(h.total_count(), 10);
        let buckets = h.buckets();
        assert!(buckets.iter().any(|b| b.lower == 0.0 && b.upper == 0.0 && b.count == 1));
        assert!(buckets.iter().any(|b| b.lower == 1.0 && b.upper == 2.0 && b.count == 2));
        assert!(buckets.iter().any(|b| b.lower == 2.0 && b.upper == 4.0 && b.count == 2));
        assert!(buckets.iter().any(|b| b.lower == 8.0 && b.upper == 16.0 && b.count == 2));
    }
}
