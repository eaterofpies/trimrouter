use crate::config::{ForwardProtocol, PortForwardRule};
use crate::error::RouterError;
use log::{debug, info};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Immediate, Nat, NatType, Register,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
};
use std::net::Ipv4Addr;

/// Netfilter prerouting hook priority for destination NAT rules (standard NF_IP_PRI_NAT_DST).
const NF_HOOK_PRIORITY_NAT_DST: i32 = -100;
/// Netfilter postrouting hook priority for NAT masquerade rules (standard NF_IP_PRI_NAT_SRC).
const NF_HOOK_PRIORITY_NAT: i32 = 100;
/// Netfilter input hook priority for local packet filtering (standard NF_IP_PRI_FILTER).
const NF_HOOK_PRIORITY_FILTER: i32 = 0;

pub const IFNAMSIZ: usize = 16;

pub trait RuleExt {
    fn ct_state(self, state: ConnTrackState) -> Result<Self, RouterError>
    where
        Self: Sized;
    fn ct_invalid(self) -> Result<Self, RouterError>
    where
        Self: Sized;
    fn ct_established_and_related(self) -> Result<Self, RouterError>
    where
        Self: Sized;
    fn dnat(self, int_ip: Ipv4Addr, int_port: u16) -> Self
    where
        Self: Sized;
}

impl RuleExt for Rule {
    fn ct_state(mut self, state: ConnTrackState) -> Result<Self, RouterError> {
        self.add_expr(Conntrack::new(ConntrackKey::State));
        self.add_expr(Bitwise::new(
            state.bits().to_le_bytes(),
            0u32.to_be_bytes(),
        )?);
        self.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes()));
        Ok(self)
    }

    fn ct_invalid(self) -> Result<Self, RouterError> {
        self.ct_state(ConnTrackState::INVALID)
    }

    fn ct_established_and_related(self) -> Result<Self, RouterError> {
        self.ct_state(ConnTrackState::ESTABLISHED | ConnTrackState::RELATED)
    }

    fn dnat(mut self, int_ip: Ipv4Addr, int_port: u16) -> Self {
        self.add_expr(Immediate::new_data(
            int_ip.octets().to_vec(),
            Register::Reg1,
        ));
        self.add_expr(Immediate::new_data(
            int_port.to_be_bytes().to_vec(),
            Register::Reg2,
        ));
        self.add_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(ProtocolFamily::Ipv4)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        );
        self
    }
}

fn validate_interface_name(name: &str) -> Result<(), RouterError> {
    if name.is_empty() || name.len() >= IFNAMSIZ || name.contains('\0') {
        return Err(RouterError::Generic(format!(
            "Invalid network interface name '{}': must be non-empty, < {} bytes, and contain no null bytes",
            name, IFNAMSIZ
        )));
    }
    Ok(())
}

fn flush_existing_table(table: &Table) -> Result<(), RouterError> {
    let mut del_batch = Batch::new();
    del_batch.add(table, MsgType::Del);
    if let Err(e) = del_batch.send() {
        let is_enoent = match e {
            rustables::error::QueryError::NetlinkError(ref err) => err.error.abs() == libc::ENOENT,
            _ => false,
        };
        if !is_enoent {
            return Err(e.into());
        }
    }
    Ok(())
}

fn build_single_dnat_rule(
    chain: &Chain,
    wan_iface: &str,
    proto: Protocol,
    ext_port: u16,
    int_ip: Ipv4Addr,
    int_port: u16,
) -> Result<Rule, RouterError> {
    Ok(Rule::new(chain)?
        .iiface(wan_iface)?
        .dport(ext_port, proto)
        .dnat(int_ip, int_port))
}

fn build_dnat_rules(
    prerouting_chain: &Chain,
    wan_iface: &str,
    rules: &[PortForwardRule],
) -> Result<Vec<Rule>, RouterError> {
    let mut nft_rules = Vec::new();
    for rule in rules {
        if rule.protocol == ForwardProtocol::Tcp || rule.protocol == ForwardProtocol::Both {
            nft_rules.push(build_single_dnat_rule(
                prerouting_chain,
                wan_iface,
                Protocol::TCP,
                rule.external_port,
                rule.internal_ip,
                rule.internal_port,
            )?);
        }
        if rule.protocol == ForwardProtocol::Udp || rule.protocol == ForwardProtocol::Both {
            nft_rules.push(build_single_dnat_rule(
                prerouting_chain,
                wan_iface,
                Protocol::UDP,
                rule.external_port,
                rule.internal_ip,
                rule.internal_port,
            )?);
        }
    }
    Ok(nft_rules)
}

fn build_nat_rule(nat_chain: &Chain, wan_iface: &str) -> Result<Rule, RouterError> {
    Ok(Rule::new(nat_chain)?.oiface(wan_iface)?.masquerade())
}

fn build_filter_rules(
    filter_chain: &Chain,
    wan_iface: &str,
    lan_iface: &str,
) -> Result<Vec<Rule>, RouterError> {
    Ok(vec![
        // 1. Drop invalid connection tracking states immediately
        Rule::new(filter_chain)?.ct_invalid()?.drop(),
        // 2. Accept loopback
        Rule::new(filter_chain)?.iiface("lo")?.accept(),
        // 3. Accept established / related connections
        Rule::new(filter_chain)?
            .ct_established_and_related()?
            .accept(),
        // 4. Accept LAN input traffic
        Rule::new(filter_chain)?.iiface(lan_iface)?.accept(),
        // 5. Accept DHCP client response traffic on WAN (UDP dport 68)
        Rule::new(filter_chain)?
            .iiface(wan_iface)?
            .dport(dhcproto::v4::CLIENT_PORT, Protocol::UDP)
            .accept(),
        // 6. Accept ICMP (ping / path MTU discovery)
        Rule::new(filter_chain)?.icmp().accept(),
    ])
}

pub fn configure_firewall(
    wan_iface: &str,
    lan_iface: &str,
    port_forwards: &[PortForwardRule],
) -> Result<(), RouterError> {
    validate_interface_name(wan_iface)?;
    validate_interface_name(lan_iface)?;
    if wan_iface == lan_iface {
        return Err(RouterError::Generic(format!(
            "WAN and LAN interfaces must be distinct (both given as '{}')",
            wan_iface
        )));
    }

    debug!("[netfilter] Configuring NAT and firewall rules...");

    let table = Table::new(ProtocolFamily::Ipv4).with_name("trimrouter");
    flush_existing_table(&table)?;

    let nat_prerouting = Chain::new(&table)
        .with_name("nat_prerouting")
        .with_hook(Hook::new(HookClass::PreRouting, NF_HOOK_PRIORITY_NAT_DST))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept);

    let nat_postrouting = Chain::new(&table)
        .with_name("nat_postrouting")
        .with_hook(Hook::new(HookClass::PostRouting, NF_HOOK_PRIORITY_NAT))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept);

    let filter_chain = Chain::new(&table)
        .with_name("filter_input")
        .with_hook(Hook::new(HookClass::In, NF_HOOK_PRIORITY_FILTER))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Drop);

    let dnat_rules = build_dnat_rules(&nat_prerouting, wan_iface, port_forwards)?;
    let masq_rule = build_nat_rule(&nat_postrouting, wan_iface)?;
    let filter_rules = build_filter_rules(&filter_chain, wan_iface, lan_iface)?;

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&nat_prerouting, MsgType::Add);
    batch.add(&nat_postrouting, MsgType::Add);
    batch.add(&filter_chain, MsgType::Add);
    for rule in &dnat_rules {
        batch.add(rule, MsgType::Add);
    }
    batch.add(&masq_rule, MsgType::Add);
    for rule in &filter_rules {
        batch.add(rule, MsgType::Add);
    }

    batch.send()?;
    info!(
        "[netfilter] NAT and firewall rules configured successfully ({} DNAT port forwards).",
        port_forwards.len()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_interface_name() {
        assert!(validate_interface_name("wan").is_ok());
        assert!(validate_interface_name("lan").is_ok());
        assert!(validate_interface_name("eth0").is_ok());

        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("name_is_way_too_long_for_ifnamsiz").is_err());
        assert!(validate_interface_name("eth0\0null").is_err());
    }

    #[test]
    fn test_configure_firewall_validation() {
        assert!(configure_firewall("", "lan", &[]).is_err());
        assert!(configure_firewall("wan", "", &[]).is_err());
        assert!(configure_firewall("wan", "wan", &[]).is_err());
    }

    #[test]
    fn test_build_filter_rules_count() {
        let table = Table::new(ProtocolFamily::Ipv4).with_name("test_table");
        let filter_chain = Chain::new(&table).with_name("test_chain");
        let rules = build_filter_rules(&filter_chain, "wan", "lan").unwrap();
        // 6 rules: 1. Invalid Drop, 2. Lo Accept, 3. CT Accept, 4. LAN Accept, 5. WAN DHCP Accept, 6. ICMP Accept
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn test_build_nat_rule_structure() {
        let table = Table::new(ProtocolFamily::Ipv4).with_name("nat_table");
        let nat_chain = Chain::new(&table).with_name("nat_chain");
        let rule = build_nat_rule(&nat_chain, "wan");
        assert!(rule.is_ok());
    }

    #[test]
    fn test_build_dnat_rules_tcp_and_udp() {
        let table = Table::new(ProtocolFamily::Ipv4).with_name("nat_table");
        let prerouting_chain = Chain::new(&table).with_name("nat_prerouting");

        let port_forwards = vec![
            PortForwardRule {
                protocol: ForwardProtocol::Tcp,
                external_port: 8080,
                internal_ip: Ipv4Addr::new(192, 168, 1, 50),
                internal_port: 80,
                description: Some("HTTP Forward".to_string()),
            },
            PortForwardRule {
                protocol: ForwardProtocol::Udp,
                external_port: 5353,
                internal_ip: Ipv4Addr::new(192, 168, 1, 60),
                internal_port: 5353,
                description: None,
            },
            PortForwardRule {
                protocol: ForwardProtocol::Both,
                external_port: 9999,
                internal_ip: Ipv4Addr::new(192, 168, 1, 70),
                internal_port: 9999,
                description: None,
            },
        ];

        let rules = build_dnat_rules(&prerouting_chain, "wan", &port_forwards).unwrap();
        // 1 TCP + 1 UDP + 2 for Both (1 TCP + 1 UDP) = 4 rules
        assert_eq!(rules.len(), 4);
    }
}
