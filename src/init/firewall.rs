use crate::error::RouterError;
use log::{debug, info};
use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Immediate, Masquerade, Meta,
    MetaType, VerdictKind,
};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
};

fn pad_interface_name(name: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(16);
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
    let mut lo_rule = Rule::new(filter_chain)?;
    lo_rule.add_expr(Meta::new(MetaType::IifName));
    lo_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name("lo")));
    lo_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    let mut ct_rule = Rule::new(filter_chain)?;
    ct_rule.add_expr(Conntrack::new(ConntrackKey::State));
    let state_mask = ConnTrackState::ESTABLISHED.bits() | ConnTrackState::RELATED.bits();
    ct_rule.add_expr(Bitwise::new(state_mask.to_le_bytes(), 0u32.to_be_bytes())?);
    ct_rule.add_expr(Cmp::new(CmpOp::Neq, 0u32.to_be_bytes()));
    ct_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    let mut lan_rule = Rule::new(filter_chain)?;
    lan_rule.add_expr(Meta::new(MetaType::IifName));
    lan_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(lan_iface)));
    lan_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

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

    let icmp_rule = Rule::new(filter_chain)?.icmp().accept();

    Ok(vec![lo_rule, ct_rule, lan_rule, wan_dhcp_rule, icmp_rule])
}

pub fn configure_firewall(wan_iface: &str, lan_iface: &str) -> Result<(), RouterError> {
    debug!("[netfilter] Configuring NAT and firewall rules...");

    let table = Table::new(ProtocolFamily::Ipv4).with_name("trimrouter");
    flush_existing_table(&table)?;

    let nat_chain = Chain::new(&table)
        .with_name("nat_postrouting")
        .with_hook(Hook::new(HookClass::PostRouting, 100))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept);

    let filter_chain = Chain::new(&table)
        .with_name("filter_input")
        .with_hook(Hook::new(HookClass::In, 0))
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
