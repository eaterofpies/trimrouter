use pnet::packet::MutablePacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

struct RawPacketEndpoints {
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
}

fn write_packet_headers(
    buf: &mut [u8],
    endpoints: &RawPacketEndpoints,
    payload: &[u8],
) -> Option<()> {
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let udp_header_len = MutableUdpPacket::minimum_packet_size();

    let mut eth = MutableEthernetPacket::new(buf)?;
    eth.set_destination(endpoints.dest_mac);
    eth.set_source(endpoints.src_mac);
    eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

    let mut ip = MutableIpv4Packet::new(eth.payload_mut())?;
    ip.set_version(4);
    ip.set_header_length((ip_header_len / 4) as u8);
    ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ip.set_source(endpoints.src_ip);
    ip.set_destination(endpoints.dest_ip);

    let mut udp = MutableUdpPacket::new(ip.payload_mut())?;
    udp.set_source(endpoints.src_port);
    udp.set_destination(endpoints.dest_port);
    udp.set_length((udp_header_len + payload.len()) as u16);
    udp.set_payload(payload);

    Some(())
}

fn set_ip_checksum(buf: &mut [u8]) -> Option<()> {
    let mut eth = MutableEthernetPacket::new(buf)?;
    let mut ip = MutableIpv4Packet::new(eth.payload_mut())?;
    let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(checksum);
    Some(())
}

/// Building raw packets is necessary for DHCP because during the initial IP discovery phase,
/// the client interface does not yet have an assigned IP address. Standard TCP/UDP sockets
/// require a bound IP to send/receive data through the kernel network stack.
/// To bypass this and communicate with the server before an IP is assigned, we must construct
/// raw Ethernet, IPv4, and UDP headers in-place and write them directly into a raw packet socket
/// targeting Layer 2 MAC addresses.
pub fn build_raw_packet(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let udp_header_len = MutableUdpPacket::minimum_packet_size();

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    let mut buf = vec![0u8; total_len];

    let endpoints = RawPacketEndpoints {
        src_mac,
        dest_mac,
        src_ip,
        dest_ip,
        src_port,
        dest_port,
    };
    write_packet_headers(&mut buf, &endpoints, payload);
    set_ip_checksum(&mut buf);

    buf
}
