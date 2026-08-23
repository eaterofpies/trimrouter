use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Instant;

use pnet::util::MacAddr;

#[derive(Debug, Clone)]
pub struct ClientLease {
    pub ip: Ipv4Addr,
    pub expiry: Instant,
}

/// Encapsulates the lease map and IP allocation index as a single unit.
///
/// `by_mac` and `allocated_ips` are private to this module. An IP is
/// always in `allocated_ips` **if and only if** there is a live
/// corresponding entry in `by_mac`. Use the public methods to mutate.
pub struct LeaseTable {
    by_mac: HashMap<MacAddr, ClientLease>,
    /// O(1) index of currently allocated IPs. Always kept in sync with `by_mac`.
    allocated_ips: HashSet<Ipv4Addr>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self {
            by_mac: HashMap::new(),
            allocated_ips: HashSet::new(),
        }
    }

    /// Returns the active lease for this MAC address, if one exists.
    pub fn get(&self, mac: &MacAddr) -> Option<&ClientLease> {
        self.by_mac.get(mac)
    }

    /// Inserts or replaces the lease for `mac`, updating the IP index atomically.
    pub fn insert(&mut self, mac: MacAddr, lease: ClientLease) {
        // Release the old IP from the index if this MAC already had a lease.
        if let Some(old) = self.by_mac.get(&mac) {
            self.allocated_ips.remove(&old.ip);
        }
        self.allocated_ips.insert(lease.ip);
        self.by_mac.insert(mac, lease);
    }

    /// Removes the lease for `mac` and updates the IP index atomically.
    /// Returns the removed lease, or `None` if no lease existed.
    pub fn remove(&mut self, mac: &MacAddr) -> Option<ClientLease> {
        let lease = self.by_mac.remove(mac)?;
        self.allocated_ips.remove(&lease.ip);
        Some(lease)
    }

    /// Returns `true` if `ip` is not currently held by any client.
    pub fn is_ip_available(&self, ip: Ipv4Addr) -> bool {
        !self.allocated_ips.contains(&ip)
    }

    /// Returns `true` if `ip` is actively leased to a MAC *other* than `client_mac`.
    pub fn is_ip_taken_by_other(&self, ip: Ipv4Addr, client_mac: MacAddr) -> bool {
        self.by_mac
            .iter()
            .any(|(mac, l)| l.ip == ip && l.expiry > Instant::now() && *mac != client_mac)
    }

    /// Evicts all expired leases and returns their IPs to the available pool.
    ///
    /// The `allocated_ips` index is rebuilt from the remaining live leases
    /// after eviction, guaranteeing the two structures stay in sync.
    pub fn evict_expired(&mut self) {
        self.by_mac.retain(|_, l| l.expiry > Instant::now());
        self.allocated_ips = self.by_mac.values().map(|l| l.ip).collect();
    }

    /// Evicts expired leases, then finds the first available host IP in
    /// `net` that is not `server_ip`.
    pub fn next_available_ip(
        &mut self,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        self.evict_expired();
        net.hosts()
            .find(|&ip| ip != server_ip && self.is_ip_available(ip))
    }

    /// Finds the MAC address that currently holds the lease for `ip`.
    pub fn get_mac_by_ip(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.by_mac
            .iter()
            .find(|(_, lease)| lease.ip == ip && lease.expiry > Instant::now())
            .map(|(&mac, _)| mac)
    }

    /// Number of active (non-expired) leases. Used in tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_mac.len()
    }
}
