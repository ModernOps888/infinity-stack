//! Simple per-IP fixed-window rate limiter (60s windows).
//!
//! Deliberately dependency-free and lock-light: a single mutex guarding a map
//! of `ip -> (window_start, count)`. Good enough to shield upstreams from
//! abusive spikes; swap for a distributed limiter (Redis/GCRA) at scale.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RateLimiter {
    limit: u32,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self { limit: limit_per_min, state: Mutex::new(HashMap::new()) }
    }

    /// Returns true if the request is allowed, false if the limit is exceeded.
    pub fn allow(&self, key: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let window = now / 60;
        let mut map = self.state.lock().unwrap();
        let entry = map.entry(key.to_string()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}
