use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub const DEFAULT_DNS_RATE_LIMIT_PER_SEC: f64 = 100.0;
pub const DEFAULT_DNS_BURST_QUOTA: f64 = 150.0;
pub const IDLE_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct ClientBucket {
    tokens: f64,
    last_update: Instant,
}

pub struct DnsRateLimiter {
    clients: HashMap<Ipv4Addr, ClientBucket>,
    rate_per_sec: f64,
    max_burst: f64,
}

impl DnsRateLimiter {
    pub fn new(rate_per_sec: f64, max_burst: f64) -> Self {
        Self {
            clients: HashMap::new(),
            rate_per_sec: rate_per_sec.max(1.0),
            max_burst: max_burst.max(1.0),
        }
    }

    pub fn check(&mut self, client_ip: &Ipv4Addr) -> bool {
        let now = Instant::now();
        let rate_per_sec = self.rate_per_sec;
        let max_burst = self.max_burst;
        let bucket = self
            .clients
            .entry(*client_ip)
            .or_insert_with(|| ClientBucket {
                tokens: max_burst,
                last_update: now,
            });

        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.last_update = now;
        bucket.tokens = (bucket.tokens + elapsed * rate_per_sec).min(max_burst);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn retain_recent(&mut self) {
        let now = Instant::now();
        self.clients
            .retain(|_, bucket| now.duration_since(bucket.last_update) <= IDLE_CLIENT_TIMEOUT);
    }
}

impl Default for DnsRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_RATE_LIMIT_PER_SEC, DEFAULT_DNS_BURST_QUOTA)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_dns_rate_limiter_burst_and_blocking() {
        let mut limiter = DnsRateLimiter::new(10.0, 5.0);
        let client = Ipv4Addr::new(192, 168, 1, 100);

        // First 5 burst queries should be allowed
        for _ in 0..5 {
            assert!(limiter.check(&client), "Burst query should be allowed");
        }

        // 6th query immediately should be blocked
        assert!(
            !limiter.check(&client),
            "Query exceeding burst should be blocked"
        );
    }

    #[test]
    fn test_dns_rate_limiter_client_isolation() {
        let mut limiter = DnsRateLimiter::new(10.0, 2.0);
        let client_a = Ipv4Addr::new(192, 168, 1, 100);
        let client_b = Ipv4Addr::new(192, 168, 1, 101);

        assert!(limiter.check(&client_a));
        assert!(limiter.check(&client_a));
        assert!(!limiter.check(&client_a));

        // Client B should still be allowed
        assert!(limiter.check(&client_b));
        assert!(limiter.check(&client_b));
        assert!(!limiter.check(&client_b));
    }

    #[test]
    fn test_dns_rate_limiter_refill() {
        let mut limiter = DnsRateLimiter::new(20.0, 1.0);
        let client = Ipv4Addr::new(192, 168, 1, 100);

        assert!(limiter.check(&client));
        assert!(!limiter.check(&client));

        // Sleep 100ms (at 20/sec, refilling 1 token takes 50ms)
        sleep(Duration::from_millis(100));
        assert!(limiter.check(&client), "Token should have refilled");
    }

    #[test]
    fn test_dns_rate_limiter_retain_recent() {
        let mut limiter = DnsRateLimiter::default();
        let client = Ipv4Addr::new(192, 168, 1, 50);
        assert!(limiter.check(&client));
        assert_eq!(limiter.clients.len(), 1);
        limiter.retain_recent();
        assert_eq!(limiter.clients.len(), 1);
    }
}
