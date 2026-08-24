use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::util::MacAddr;
use tokio::sync::{mpsc, oneshot};

const LEASE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const CANDIDATE_HOLD_DURATION: Duration = Duration::from_secs(10);
const NEIGHBOR_HOLD_DURATION: Duration = Duration::from_secs(300);
const LEASE_CHANNEL_CAPACITY: usize = 64;

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
#[derive(Default)]
pub struct LeaseTable {
    by_mac: HashMap<MacAddr, ClientLease>,
    /// O(1) index of currently allocated IPs. Always kept in sync with `by_mac`.
    allocated_ips: HashSet<Ipv4Addr>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the active lease for this MAC address, if one exists.
    pub fn get(&self, mac: &MacAddr) -> Option<&ClientLease> {
        self.by_mac.get(mac)
    }

    /// Inserts or replaces the lease for `mac`, updating the IP index atomically.
    pub fn insert(&mut self, mac: MacAddr, lease: ClientLease) {
        if let Some(old) = self.by_mac.get(&mac) {
            self.allocated_ips.remove(&old.ip);
        }
        self.allocated_ips.insert(lease.ip);
        self.by_mac.insert(mac, lease);
    }

    /// Removes the lease for `mac` and updates the IP index atomically.
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

    /// Allocates the next available candidate IP with a temporary hold.
    pub fn allocate_candidate(
        &mut self,
        client_mac: MacAddr,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        let ip = self.next_available_ip(net, server_ip)?;
        self.insert(
            client_mac,
            ClientLease {
                ip,
                expiry: Instant::now() + CANDIDATE_HOLD_DURATION,
            },
        );
        Some(ip)
    }

    /// Validates a requested IP (or existing lease) and confirms the lease duration.
    pub fn validate_and_confirm(
        &mut self,
        client_mac: MacAddr,
        requested_ip: Option<Ipv4Addr>,
        server_ip: Ipv4Addr,
        net: ipnet::Ipv4Net,
        duration: Duration,
    ) -> Option<Ipv4Addr> {
        let target_ip = requested_ip.or_else(|| self.get(&client_mac).map(|l| l.ip))?;
        if target_ip == server_ip
            || !net.contains(&target_ip)
            || self.is_ip_taken_by_other(target_ip, client_mac)
        {
            return None;
        }
        self.insert(
            client_mac,
            ClientLease {
                ip: target_ip,
                expiry: Instant::now() + duration,
            },
        );
        Some(target_ip)
    }

    /// Records or updates an active neighbor mapping received from Netlink.
    pub fn update_from_neighbor(&mut self, mac: MacAddr, ip: Ipv4Addr) {
        if mac == MacAddr::zero() || mac == MacAddr::broadcast() {
            return;
        }
        if self.get(&mac).is_some_and(|existing| existing.ip == ip) {
            return;
        }
        self.insert(
            mac,
            ClientLease {
                ip,
                expiry: Instant::now() + NEIGHBOR_HOLD_DURATION,
            },
        );
    }

    /// Number of active leases. Used in tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_mac.len()
    }

    /// Whether the lease table has no active leases. Used in tests.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.by_mac.is_empty()
    }
}

pub enum LeaseCommand {
    GetExistingIp {
        client_mac: MacAddr,
        reply_tx: oneshot::Sender<Option<Ipv4Addr>>,
    },
    AllocateCandidate {
        client_mac: MacAddr,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
        reply_tx: oneshot::Sender<Option<Ipv4Addr>>,
    },
    ConfirmLease {
        client_mac: MacAddr,
        ip: Ipv4Addr,
        duration: Duration,
    },
    ValidateAndConfirmRequest {
        client_mac: MacAddr,
        requested_ip: Option<Ipv4Addr>,
        server_ip: Ipv4Addr,
        net: ipnet::Ipv4Net,
        duration: Duration,
        reply_tx: oneshot::Sender<Option<Ipv4Addr>>,
    },
    CheckConflict {
        target_ip: Ipv4Addr,
        client_mac: MacAddr,
        reply_tx: oneshot::Sender<bool>,
    },
    RecordConflict {
        ip: Ipv4Addr,
        duration: Duration,
    },
    Release {
        client_mac: MacAddr,
        reply_tx: oneshot::Sender<Option<Ipv4Addr>>,
    },
    AddNeighbor {
        mac: MacAddr,
        ip: Ipv4Addr,
    },
}

#[derive(Clone)]
pub struct LeaseHandle {
    sender: mpsc::Sender<LeaseCommand>,
}

impl LeaseHandle {
    pub async fn get_existing_ip(&self, client_mac: MacAddr) -> Option<Ipv4Addr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .send(LeaseCommand::GetExistingIp {
                client_mac,
                reply_tx,
            })
            .await
            .ok()?;
        reply_rx.await.ok()?
    }

    pub async fn allocate_candidate(
        &self,
        client_mac: MacAddr,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .send(LeaseCommand::AllocateCandidate {
                client_mac,
                net,
                server_ip,
                reply_tx,
            })
            .await
            .ok()?;
        reply_rx.await.ok()?
    }

    pub async fn confirm_lease(&self, client_mac: MacAddr, ip: Ipv4Addr, duration: Duration) {
        let _ = self
            .sender
            .send(LeaseCommand::ConfirmLease {
                client_mac,
                ip,
                duration,
            })
            .await;
    }

    pub async fn validate_and_confirm_request(
        &self,
        client_mac: MacAddr,
        requested_ip: Option<Ipv4Addr>,
        server_ip: Ipv4Addr,
        net: ipnet::Ipv4Net,
        duration: Duration,
    ) -> Option<Ipv4Addr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .send(LeaseCommand::ValidateAndConfirmRequest {
                client_mac,
                requested_ip,
                server_ip,
                net,
                duration,
                reply_tx,
            })
            .await
            .ok()?;
        reply_rx.await.ok()?
    }

    pub async fn check_conflict(&self, target_ip: Ipv4Addr, client_mac: MacAddr) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .sender
            .send(LeaseCommand::CheckConflict {
                target_ip,
                client_mac,
                reply_tx,
            })
            .await
            .is_err()
        {
            return false;
        }
        reply_rx.await.unwrap_or(false)
    }

    pub async fn record_conflict(&self, ip: Ipv4Addr, duration: Duration) {
        let _ = self
            .sender
            .send(LeaseCommand::RecordConflict { ip, duration })
            .await;
    }

    pub async fn release(&self, client_mac: MacAddr) -> Option<Ipv4Addr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .send(LeaseCommand::Release {
                client_mac,
                reply_tx,
            })
            .await
            .ok()?;
        reply_rx.await.ok()?
    }

    pub async fn add_neighbor(&self, mac: MacAddr, ip: Ipv4Addr) {
        let _ = self
            .sender
            .send(LeaseCommand::AddNeighbor { mac, ip })
            .await;
    }
}

pub fn spawn_lease_actor() -> LeaseHandle {
    let (tx, rx) = mpsc::channel(LEASE_CHANNEL_CAPACITY);
    tokio::spawn(run_lease_actor_loop(rx));
    LeaseHandle { sender: tx }
}

async fn run_lease_actor_loop(mut rx: mpsc::Receiver<LeaseCommand>) {
    let mut leases = LeaseTable::new();
    let mut cleanup_interval = tokio::time::interval(LEASE_CLEANUP_INTERVAL);
    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                leases.evict_expired();
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                handle_lease_command(cmd, &mut leases);
            }
        }
    }
}

fn handle_lease_command(cmd: LeaseCommand, leases: &mut LeaseTable) {
    match cmd {
        LeaseCommand::GetExistingIp {
            client_mac,
            reply_tx,
        } => {
            let _ = reply_tx.send(leases.get(&client_mac).map(|l| l.ip));
        }
        LeaseCommand::AllocateCandidate {
            client_mac,
            net,
            server_ip,
            reply_tx,
        } => {
            let ip = leases.allocate_candidate(client_mac, net, server_ip);
            let _ = reply_tx.send(ip);
        }
        LeaseCommand::ConfirmLease {
            client_mac,
            ip,
            duration,
        } => {
            leases.insert(
                client_mac,
                ClientLease {
                    ip,
                    expiry: Instant::now() + duration,
                },
            );
        }
        LeaseCommand::ValidateAndConfirmRequest {
            client_mac,
            requested_ip,
            server_ip,
            net,
            duration,
            reply_tx,
        } => {
            let ip =
                leases.validate_and_confirm(client_mac, requested_ip, server_ip, net, duration);
            let _ = reply_tx.send(ip);
        }
        LeaseCommand::CheckConflict {
            target_ip,
            client_mac,
            reply_tx,
        } => {
            let is_conflict = leases
                .get_mac_by_ip(target_ip)
                .is_some_and(|mac| mac != client_mac);
            let _ = reply_tx.send(is_conflict);
        }
        LeaseCommand::RecordConflict { ip, duration } => {
            leases.insert(
                MacAddr::zero(),
                ClientLease {
                    ip,
                    expiry: Instant::now() + duration,
                },
            );
        }
        LeaseCommand::Release {
            client_mac,
            reply_tx,
        } => {
            let removed = leases.remove(&client_mac).map(|l| l.ip);
            let _ = reply_tx.send(removed);
        }
        LeaseCommand::AddNeighbor { mac, ip } => {
            leases.update_from_neighbor(mac, ip);
        }
    }
}
