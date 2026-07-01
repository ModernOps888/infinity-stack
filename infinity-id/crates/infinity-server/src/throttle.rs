//! In-memory login throttling with temporary account lockout.
//!
//! Protects `/auth/login` and the password grant against online brute-force
//! attacks. Keyed by a caller-supplied identifier (email). Failures within a
//! rolling window accumulate; exceeding the threshold locks the key for a
//! cool-off period. Successful auth resets the counter.
//!
//! This is intentionally simple/in-process. For multi-node deployments back it
//! with a shared store (e.g. Redis) — see the deployment docs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct Entry {
    window_start: u64,
    fails: u32,
    locked_until: u64,
}

pub struct LoginThrottle {
    max_fails: u32,
    window_secs: u64,
    lockout_secs: u64,
    state: Mutex<HashMap<String, Entry>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

impl LoginThrottle {
    pub fn new(max_fails: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self { max_fails, window_secs, lockout_secs, state: Mutex::new(HashMap::new()) }
    }

    /// Returns `Err(retry_after_secs)` if the key is currently locked out.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = now();
        let map = self.state.lock().unwrap();
        if let Some(e) = map.get(key) {
            if e.locked_until > now {
                return Err(e.locked_until - now);
            }
        }
        Ok(())
    }

    /// Record a failed attempt; locks the key if the threshold is reached.
    pub fn record_failure(&self, key: &str) {
        let now = now();
        let mut map = self.state.lock().unwrap();
        let e = map.entry(key.to_string()).or_insert(Entry {
            window_start: now,
            fails: 0,
            locked_until: 0,
        });
        if now.saturating_sub(e.window_start) > self.window_secs {
            e.window_start = now;
            e.fails = 0;
        }
        e.fails += 1;
        if e.fails >= self.max_fails {
            e.locked_until = now + self.lockout_secs;
            e.fails = 0;
            e.window_start = now;
        }
    }

    /// Clear counters for a key after a successful authentication.
    pub fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        // 10 failures within 15 minutes -> 15 minute lockout.
        Self::new(10, 15 * 60, 15 * 60)
    }
}
