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
use crate::error::RouterError;

pub const MAX_RAW_PACKET_PAYLOAD: usize = 65507; // 65535 - 20 (IP header) - 8 (UDP header)

pub fn build_raw_packet(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, RouterError> {
    if payload.len() > MAX_RAW_PACKET_PAYLOAD {
        return Err(RouterError::Generic(format!(
            "Payload length {} exceeds maximum raw packet payload capacity {}",
            payload.len(),
            MAX_RAW_PACKET_PAYLOAD
        )));
    }

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
    write_packet_headers(&mut buf, &endpoints, payload).ok_or_else(|| {
        RouterError::Generic("Failed to serialize raw packet headers".to_string())
    })?;
    set_ip_checksum(&mut buf).ok_or_else(|| {
        RouterError::Generic("Failed to compute IP checksum for raw packet".to_string())
    })?;

    Ok(buf)
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use pnet::packet::Packet;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;

    #[test]
    fn test_build_raw_packet_structure_and_checksum() {
        let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let dest_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        let src_ip = Ipv4Addr::new(0, 0, 0, 0);
        let dest_ip = Ipv4Addr::new(255, 255, 255, 255);
        let src_port = 68;
        let dest_port = 67;
        let payload = b"DHCPDISCOVER_TEST_PAYLOAD";

        let raw = build_raw_packet(
            src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port, payload,
        )
        .expect("valid raw packet");

        let eth = EthernetPacket::new(&raw).expect("valid ethernet frame");
        assert_eq!(eth.get_destination(), dest_mac);
        assert_eq!(eth.get_source(), src_mac);
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);

        let ip = Ipv4Packet::new(eth.payload()).expect("valid ipv4 packet");
        assert_eq!(ip.get_version(), 4);
        assert_eq!(ip.get_header_length(), 5);
        assert_eq!(ip.get_ttl(), 64);
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Udp);
        assert_eq!(ip.get_source(), src_ip);
        assert_eq!(ip.get_destination(), dest_ip);
        assert_eq!(
            ip.get_total_length() as usize,
            20 + 8 + payload.len() // IP header (20) + UDP header (8) + payload
        );
        // Verify IP checksum
        assert_ne!(ip.get_checksum(), 0);
        let mut verify_buf = eth.payload().to_vec();
        let mut verify_ip = pnet::packet::ipv4::MutableIpv4Packet::new(&mut verify_buf).unwrap();
        verify_ip.set_checksum(0);
        let expected_checksum = pnet::packet::ipv4::checksum(&verify_ip.to_immutable());
        assert_eq!(ip.get_checksum(), expected_checksum);

        let udp = UdpPacket::new(ip.payload()).expect("valid udp packet");
        assert_eq!(udp.get_source(), src_port);
        assert_eq!(udp.get_destination(), dest_port);
        assert_eq!(udp.get_length() as usize, 8 + payload.len());
        assert_eq!(udp.payload(), payload);
    }

    #[test]
    fn test_build_raw_packet_payload_overflow_returns_err() {
        let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let dest_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 2);
        let huge_payload = vec![0xAA; MAX_RAW_PACKET_PAYLOAD + 1];

        let res = build_raw_packet(src_mac, dest_mac, src_ip, dest_ip, 68, 67, &huge_payload);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_build_raw_packet_empty_payload() {
        let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let dest_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 2);
        let empty_payload = b"";

        let raw = build_raw_packet(src_mac, dest_mac, src_ip, dest_ip, 68, 67, empty_payload)
            .expect("valid empty payload packet");
        assert_eq!(raw.len(), 14 + 20 + 8);
    }
}
