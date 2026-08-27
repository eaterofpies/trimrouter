use crate::error::RouterError;
use log::{debug, info};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Immediate, Masquerade, Meta,
    MetaType, VerdictKind,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
};

/// Netfilter postrouting hook priority for NAT masquerade rules (standard NF_IP_PRI_NAT_SRC).
const NF_HOOK_PRIORITY_NAT: i32 = 100;
/// Netfilter input hook priority for local packet filtering (standard NF_IP_PRI_FILTER).
const NF_HOOK_PRIORITY_FILTER: i32 = 0;

pub const IFNAMSIZ: usize = 16;

fn validate_interface_name(name: &str) -> Result<(), RouterError> {
    if name.is_empty() || name.len() >= IFNAMSIZ || name.contains('\0') {
        return Err(RouterError::Generic(format!(
            "Invalid network interface name '{}': must be non-empty, < {} bytes, and contain no null bytes",
            name, IFNAMSIZ
        )));
    }
    Ok(())
}

fn pad_interface_name(name: &str) -> [u8; IFNAMSIZ] {
    let mut bytes = [0u8; IFNAMSIZ];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(IFNAMSIZ);
    bytes[..len].copy_from_slice(&name_bytes[..len]);
    bytes
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

fn build_nat_rule(nat_chain: &Chain, wan_iface: &str) -> Result<Rule, RouterError> {
    let mut masq_rule = Rule::new(nat_chain)?;
    masq_rule.add_expr(Meta::new(MetaType::OifName));
    masq_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(wan_iface)));
    masq_rule.add_expr(Masquerade::default());
    Ok(masq_rule)
}

fn build_filter_rules(
    filter_chain: &Chain,
    wan_iface: &str,
    lan_iface: &str,
) -> Result<Vec<Rule>, RouterError> {
    // 1. Drop invalid connection tracking states immediately
    let mut invalid_rule = Rule::new(filter_chain)?;
    invalid_rule.add_expr(Conntrack::new(ConntrackKey::State));
    let invalid_mask = ConnTrackState::INVALID.bits();
    invalid_rule.add_expr(Bitwise::new(
        invalid_mask.to_le_bytes(),
        0u32.to_be_bytes(),
    )?);
    invalid_rule.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes()));
    invalid_rule.add_expr(Immediate::new_verdict(VerdictKind::Drop));

    // 2. Accept loopback
    let mut lo_rule = Rule::new(filter_chain)?;
    lo_rule.add_expr(Meta::new(MetaType::IifName));
    lo_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name("lo")));
    lo_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 3. Accept established / related connections
    let mut ct_rule = Rule::new(filter_chain)?;
    ct_rule.add_expr(Conntrack::new(ConntrackKey::State));
    let state_mask = ConnTrackState::ESTABLISHED.bits() | ConnTrackState::RELATED.bits();
    ct_rule.add_expr(Bitwise::new(state_mask.to_le_bytes(), 0u32.to_be_bytes())?);
    ct_rule.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes()));
    ct_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 4. Accept LAN input traffic
    let mut lan_rule = Rule::new(filter_chain)?;
    lan_rule.add_expr(Meta::new(MetaType::IifName));
    lan_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(lan_iface)));
    lan_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 5. Accept DHCP client response traffic on WAN (UDP dport 68)
    let mut wan_dhcp_rule = Rule::new(filter_chain)?;
    wan_dhcp_rule.add_expr(Meta::new(MetaType::IifName));
    wan_dhcp_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(wan_iface)));
    wan_dhcp_rule.add_expr(
        rustables::expr::HighLevelPayload::Network(rustables::expr::NetworkHeaderField::IPv4(
            rustables::expr::IPv4HeaderField::Protocol,
        ))
        .build(),
    );
    wan_dhcp_rule.add_expr(Cmp::new(CmpOp::Eq, (libc::IPPROTO_UDP as u8).to_be_bytes()));
    wan_dhcp_rule.add_expr(
        rustables::expr::HighLevelPayload::Transport(rustables::expr::TransportHeaderField::Udp(
            rustables::expr::UDPHeaderField::Dport,
        ))
        .build(),
    );
    wan_dhcp_rule.add_expr(Cmp::new(CmpOp::Eq, dhcproto::v4::CLIENT_PORT.to_be_bytes()));
    wan_dhcp_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 6. Accept ICMP (ping / path MTU discovery)
    let icmp_rule = Rule::new(filter_chain)?.icmp().accept();

    Ok(vec![
        invalid_rule,
        lo_rule,
        ct_rule,
        lan_rule,
        wan_dhcp_rule,
        icmp_rule,
    ])
}

pub fn configure_firewall(wan_iface: &str, lan_iface: &str) -> Result<(), RouterError> {
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

    let nat_chain = Chain::new(&table)
        .with_name("nat_postrouting")
        .with_hook(Hook::new(HookClass::PostRouting, NF_HOOK_PRIORITY_NAT))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept);

    let filter_chain = Chain::new(&table)
        .with_name("filter_input")
        .with_hook(Hook::new(HookClass::In, NF_HOOK_PRIORITY_FILTER))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Drop);

    let masq_rule = build_nat_rule(&nat_chain, wan_iface)?;
    let filter_rules = build_filter_rules(&filter_chain, wan_iface, lan_iface)?;

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&nat_chain, MsgType::Add);
    batch.add(&filter_chain, MsgType::Add);
    batch.add(&masq_rule, MsgType::Add);
    for rule in &filter_rules {
        batch.add(rule, MsgType::Add);
    }

    batch.send()?;
    info!("[netfilter] NAT and firewall rules configured successfully.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_interface_name() {
        let padded = pad_interface_name("wan");
        assert_eq!(&padded[..4], b"wan\0");
        assert_eq!(padded.len(), 16);

        let long_name = "eth0_extremely_long_name";
        let padded_long = pad_interface_name(long_name);
        assert_eq!(&padded_long[..16], &long_name.as_bytes()[..16]);
    }

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
        assert!(configure_firewall("", "lan").is_err());
        assert!(configure_firewall("wan", "").is_err());
        assert!(configure_firewall("wan", "wan").is_err());
    }

    #[test]
    fn test_build_filter_rules_count() {
        let table = Table::new(ProtocolFamily::Ipv4).with_name("test_table");
        let filter_chain = Chain::new(&table).with_name("test_chain");
        let rules = build_filter_rules(&filter_chain, "wan", "lan").unwrap();
        // 6 rules: 1. Invalid Drop, 2. Lo Accept, 3. CT Accept, 4. LAN Accept, 5. WAN DHCP Accept, 6. ICMP Accept
        assert_eq!(rules.len(), 6);
    }
}
