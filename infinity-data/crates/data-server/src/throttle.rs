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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl LoginThrottle {
    pub fn new(max_fails: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            max_fails,
            window_secs,
            lockout_secs,
            state: Mutex::new(HashMap::new()),
        }
    }

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

    pub fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new(10, 15 * 60, 15 * 60)
    }
}
