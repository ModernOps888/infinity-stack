//! Global per-IP fixed-window rate limiting.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct IpRateLimiter {
    limit: u32,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self {
            limit: limit_per_min,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window = now / 60;
        let mut map = self.state.lock().unwrap();
        if map.len() > 100_000 {
            map.retain(|_, (w, _)| *w == window);
        }
        let entry = map.entry(ip.to_string()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}
