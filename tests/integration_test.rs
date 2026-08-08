#![allow(dead_code, unused_macros)]

use dhcproto::Decodable;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::process::Command;

#[path = "../src/error.rs"]
mod error;

#[path = "../src/packet.rs"]
mod packet;

#[path = "../src/services/utils.rs"]
mod utils;

macro_rules! println {
    ($($arg:tt)*) => {{
        std::print!("{}", utils::get_timestamp_prefix());
        std::println!($($arg)*);
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        std::eprint!("{}", utils::get_timestamp_prefix());
        std::eprintln!($($arg)*);
    }};
}

const MOCK_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const MOCK_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const MOCK_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const MOCK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
const MOCK_SERVER_MAC: MacAddr = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

// Sample DNS query payload (google.com A record request)
const DNS_QUERY: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x01, 0x00, // Flags: Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // google.com
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
];

// Sample DNS response payload (google.com A record response: 8.8.8.8)
const DNS_RESPONSE: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x81, 0x80, // Flags: Standard query response, No error
    0x00, 0x01, // Questions: 1
    0x00, 0x01, // Answer RRs: 1
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
    0x01, // Type: A
    0x00, 0x01, // Class: IN
    0xc0, 0x0c, // Pointer to name
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
    0x00, 0x00, 0x00, 0x3c, // TTL: 60s
    0x00, 0x04, // Length: 4
    0x08, 0x08, 0x08, 0x08, // IP: 8.8.8.8
];

// RAII QEMU process cleaner to prevent leaks
struct QemuKillGuard(u32);
impl Drop for QemuKillGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg(self.0.to_string())
            .status();
    }
}

// Unified UNIX socket stream wrapper with 32-bit big-endian length prefix framing
struct UnixStreamMock {
    stream: tokio::net::UnixStream,
}

impl UnixStreamMock {
    fn new(stream: tokio::net::UnixStream) -> Self {
        Self { stream }
    }

    async fn send_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let len = frame.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(frame).await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

// Environment structure holding running QEMU and verified mocks
struct TestEnv {
    _qemu_guard: QemuKillGuard,
    _qemu_child: tokio::process::Child,
    _wan_isp_handle: tokio::task::JoinHandle<bool>,
    wan_verification_rx: tokio::sync::mpsc::Receiver<String>,
    wan_cmd_tx: tokio::sync::mpsc::Sender<String>,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file("target/wan.sock");
        let _ = std::fs::remove_file("target/lan.sock");
    }
}

#[tokio::main]
async fn main() {
    std::println!("\nrunning 7 integration test steps in QEMU VM");

    let test_timeout = std::time::Duration::from_secs(180);
    let start_time = std::time::Instant::now();

    // 1. Build test initramfs and start mocks/QEMU
    let mut env = startup_stage().await;

    // 2. Connect a dummy client to LAN unix socket to bring the guest LAN interface link UP
    println!("[test-env] Bringing guest LAN link UP...");
    let _lan_stream = tokio::spawn(async move {
        // Wait for target/lan.sock to exist (created by QEMU stream server backend)
        for _ in 0..100 {
            if std::path::Path::new("target/lan.sock").exists()
                && let Ok(_stream) = tokio::net::UnixStream::connect("target/lan.sock").await
            {
                println!("[test-env] Connected to guest LAN socket.");
                // Keep stream open to maintain the link state as UP
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("[test-env] ERROR: Failed to connect to guest LAN socket.");
    });

    // 3. Monitor QEMU output and verification signals in parallel
    use tokio::io::AsyncBufReadExt;
    let mut qemu_stdout = tokio::io::BufReader::new(env._qemu_child.stdout.take().unwrap()).lines();
    let mut qemu_stderr = tokio::io::BufReader::new(env._qemu_child.stderr.take().unwrap()).lines();

    // Spawn task to log guest stderr
    tokio::spawn(async move {
        while let Ok(Some(line)) = qemu_stderr.next_line().await {
            println!("[qemu-stderr] {}", line);
        }
    });

    let mut passed = 0;
    let mut failed = 0;
    let mut suite_status = None;

    let result = tokio::time::timeout(test_timeout, async {
        loop {
            tokio::select! {
                line_res = qemu_stdout.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            println!("[qemu-stdout] {}", line);

                            // Detect test case status from guest test runner output
                            if line.contains("[test-control] TEST_PASSED") {
                                passed += 1;
                            } else if line.contains("[test-control] TEST_FAILED") {
                                failed += 1;
                            } else if line.contains("[test-control] TRIGGER_UNSOLICITED_WAN_TRAFFIC") {
                                let _ = env.wan_cmd_tx.send("SEND_UNSOLICITED_WAN".to_string()).await;
                            } else if line.contains("[test-control] SUITE_PASSED") {
                                suite_status = Some(true);
                                break;
                            } else if line.contains("[test-control] SUITE_FAILED") {
                                suite_status = Some(false);
                                break;
                            }
                        }
                        _ => {
                            println!("[test-env] QEMU stdout closed.");
                            break;
                        }
                    }
                }
                Some(sig) = env.wan_verification_rx.recv() => {
                    println!("[test-env] Received network-level verification signal: {}", sig);
                }
            }
        }
    }).await;

    let elapsed = start_time.elapsed();

    println!("\n=== Cleaning up QEMU VM... ===");
    // RAII guard will clean up QEMU process automatically

    if result.is_err() {
        println!(
            "\ntest result: FAILED (TIMEOUT - Integration test exceeded {}s limit)\n",
            test_timeout.as_secs()
        );
        std::process::exit(102);
    }

    if let Some(true) = suite_status
        && failed == 0
    {
        println!(
            "\ntest result: ok. {} passed; {} failed; finished in {:.2?}\n",
            passed, failed, elapsed
        );
        std::process::exit(0);
    } else {
        println!(
            "\ntest result: FAILED. {} passed; {} failed; finished in {:.2?}\n",
            passed, failed, elapsed
        );
        std::process::exit(101);
    }
}

async fn startup_stage() -> TestEnv {
    // A. Build the test target initramfs
    let test_arch = std::env::var("TEST_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let target_path = format!("target/{test_arch}/initramfs-test.cpio.gz");
    let build_status = Command::new("make")
        .arg(target_path)
        .arg(format!("ARCH={test_arch}"))
        .status()
        .await
        .expect("Failed to run make");
    assert!(
        build_status.success(),
        "Failed to build test initramfs via make"
    );

    // Ensure target directory exists
    let _ = std::fs::create_dir_all("target");

    // Remove any existing socket files
    let _ = std::fs::remove_file("target/wan.sock");
    let _ = std::fs::remove_file("target/lan.sock");

    // B. Bind the WAN UNIX socket listener
    let wan_listener =
        UnixListener::bind("target/wan.sock").expect("Failed to bind WAN UNIX socket");

    // MPSC Channel to coordinate mock WAN ISP
    let (verification_tx, verification_rx) = tokio::sync::mpsc::channel::<String>(100);
    let (wan_cmd_tx, wan_cmd_rx) = tokio::sync::mpsc::channel::<String>(100);

    // C. Start our mock WAN ISP gateway in a background task
    let wan_isp_handle = tokio::spawn(async move {
        let (stream, _) = wan_listener
            .accept()
            .await
            .expect("Failed to accept WAN connection from QEMU");
        let mock = UnixStreamMock::new(stream);
        run_mock_wan_isp(mock, verification_tx, wan_cmd_rx).await
    });

    // D. Detect target architecture for simulation
    let test_arch = std::env::var("TEST_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    let (qemu_bin, extra_args) = if test_arch == "arm64" {
        (
            "qemu-system-aarch64",
            vec![
                "-M".to_string(),
                "virt".to_string(),
                "-cpu".to_string(),
                "cortex-a53".to_string(),
            ],
        )
    } else if test_arch == "armhf" {
        (
            "qemu-system-arm",
            vec![
                "-M".to_string(),
                "virt".to_string(),
                "-cpu".to_string(),
                "cortex-a7".to_string(),
            ],
        )
    } else {
        ("qemu-system-x86_64", vec![])
    };

    let console = if test_arch == "x86_64" {
        "ttyS0"
    } else {
        "ttyAMA0"
    };
    let append_arg = format!("console={} loglevel=3 panic=-1 net.ifnames=0", console);

    let kernel = format!("target/{test_arch}/test_boot/vmlinuz");
    let initrd = format!("target/{test_arch}/initramfs-test.cpio.gz");
    let image = format!("target/{test_arch}/trimrouter-test.img");
    let drive_arg = format!("file={},format=raw,media=disk,if=virtio", image);

    let dev_arg = if test_arch == "x86_64" {
        "virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56,romfile=".to_string()
    } else {
        "virtio-net-device,netdev=wan0,mac=52:54:00:12:34:56".to_string()
    };
    let dev_arg_lan = if test_arch == "x86_64" {
        "virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57,romfile=".to_string()
    } else {
        "virtio-net-device,netdev=lan0,mac=52:54:00:12:34:57".to_string()
    };

    let mut args = extra_args;
    args.extend(
        [
            "-m",
            "256",
            "-kernel",
            &kernel,
            "-initrd",
            &initrd,
            "-append",
            &append_arg,
            "-drive",
            &drive_arg,
            "-netdev",
            "stream,id=wan0,server=off,addr.type=unix,addr.path=target/wan.sock",
            "-device",
            &dev_arg,
            "-netdev",
            "stream,id=lan0,server=on,addr.type=unix,addr.path=target/lan.sock",
            "-device",
            &dev_arg_lan,
            "-nographic",
        ]
        .map(String::from),
    );

    // E. Launch QEMU pointing to UNIX domain sockets
    println!("[test-env] Launching QEMU VM ({test_arch})...");
    let qemu_child = Command::new(qemu_bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn QEMU");

    // Capture child process ID for RAII kill guard
    let qemu_kill_guard = qemu_child.id().map(QemuKillGuard);

    TestEnv {
        _qemu_guard: qemu_kill_guard.unwrap(),
        _qemu_child: qemu_child,
        _wan_isp_handle: wan_isp_handle,
        wan_verification_rx: verification_rx,
        wan_cmd_tx,
    }
}

async fn run_mock_wan_isp(
    mut mock: UnixStreamMock,
    verification_tx: tokio::sync::mpsc::Sender<String>,
    mut wan_cmd_rx: tokio::sync::mpsc::Receiver<String>,
) -> bool {
    let mut xid: u32 = 0;
    let mut client_mac = MacAddr::zero();

    // 1. Collect the first 3 DHCPDISCOVER retries and verify each carries
    //    0.0.0.0 as the IPv4 source address (RFC 2131 §4.1).
    const DISCOVERS_TO_VERIFY: usize = 3;
    println!("[isp-test] Waiting for {DISCOVERS_TO_VERIFY} DHCPDISCOVER packets...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(60);
    let mut discovers_seen = 0;

    loop {
        if start.elapsed() >= timeout_dur {
            if discovers_seen == 0 {
                println!("[isp-test] Timeout waiting for DHCPDISCOVER");
                return false;
            }
            break;
        }
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] Connection closed while waiting for DHCPDISCOVER");
                return false;
            }
            Err(_) => continue, // Timeout
        };

        if let Ok(dhcp_discover) = parse_dhcp_message(&frame) {
            use dhcproto::v4::MessageType;
            let msg_type = dhcp_discover
                .opts()
                .get(dhcproto::v4::OptionCode::MessageType);
            if let Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Discover)) = msg_type {
                if discovers_seen == 0 {
                    client_mac = MacAddr(
                        dhcp_discover.chaddr()[0],
                        dhcp_discover.chaddr()[1],
                        dhcp_discover.chaddr()[2],
                        dhcp_discover.chaddr()[3],
                        dhcp_discover.chaddr()[4],
                        dhcp_discover.chaddr()[5],
                    );
                    xid = dhcp_discover.xid();
                }
                discovers_seen += 1;

                let src_ip = parse_ipv4_source(&frame);
                println!(
                    "[isp-test] DHCPDISCOVER #{discovers_seen}/{DISCOVERS_TO_VERIFY} IPv4 source: {src_ip:?}"
                );
                if src_ip == Some(Ipv4Addr::UNSPECIFIED) {
                    let _ = verification_tx
                        .send("DISCOVER_SRC_IP_VERIFIED".to_string())
                        .await;
                } else {
                    println!(
                        "[isp-test] ERROR: DHCPDISCOVER #{discovers_seen} sent from {src_ip:?} — expected 0.0.0.0!"
                    );
                    let _ = verification_tx
                        .send("DISCOVER_SRC_IP_WRONG".to_string())
                        .await;
                }

                if discovers_seen >= DISCOVERS_TO_VERIFY {
                    println!("[isp-test] Collected {DISCOVERS_TO_VERIFY} DISCOVERs.");
                    break;
                }
            }
        }
    }

    println!("[isp-test] Discovered QEMU peer WAN Interface");

    // 2. Send DHCPOFFER
    println!("[isp-test] Sending DHCPOFFER...");
    let offer_payload = build_dhcp_offer(xid, client_mac);
    let offer_frame = packet::build_raw_packet(
        MOCK_SERVER_MAC,
        client_mac,
        MOCK_SERVER_IP,
        Ipv4Addr::BROADCAST,
        67,
        68,
        &offer_payload,
    );
    if mock.send_frame(&offer_frame).await.is_err() {
        return false;
    }

    // 3. Wait for DHCPREQUEST and verify its IPv4 source address is 0.0.0.0.
    println!("[isp-test] Waiting for DHCPREQUEST...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(5);
    loop {
        if start.elapsed() >= timeout_dur {
            println!("[isp-test] Timeout waiting for DHCPREQUEST");
            return false;
        }
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] Connection closed while waiting for DHCPREQUEST");
                return false;
            }
            Err(_) => continue, // Timeout
        };
        if let Ok(dhcp_request) = parse_dhcp_message(&frame) {
            use dhcproto::v4::MessageType;
            let msg_type = dhcp_request
                .opts()
                .get(dhcproto::v4::OptionCode::MessageType);
            if let Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Request)) = msg_type
                && dhcp_request.xid() == xid
            {
                let src_ip = parse_ipv4_source(&frame);
                println!("[isp-test] DHCPREQUEST IPv4 source: {:?}", src_ip);
                if src_ip == Some(Ipv4Addr::UNSPECIFIED) {
                    let _ = verification_tx
                        .send("REQUEST_SRC_IP_VERIFIED".to_string())
                        .await;
                } else {
                    println!(
                        "[isp-test] ERROR: DHCPREQUEST sent from {:?} — expected 0.0.0.0!",
                        src_ip
                    );
                    let _ = verification_tx
                        .send("REQUEST_SRC_IP_WRONG".to_string())
                        .await;
                }
                break;
            }
        }
    }
    println!("[isp-test] Received DHCPREQUEST.");

    // 4. Send DHCPACK
    println!("[isp-test] Sending DHCPACK...");
    let ack_payload = build_dhcp_ack(xid, client_mac);
    let ack_frame = packet::build_raw_packet(
        MOCK_SERVER_MAC,
        client_mac,
        MOCK_SERVER_IP,
        Ipv4Addr::BROADCAST,
        67,
        68,
        &ack_payload,
    );
    if mock.send_frame(&ack_frame).await.is_err() {
        return false;
    }

    // Notify coordinator that WAN DHCP setup is finished
    let _ = verification_tx.send("WAN_DHCP_DONE".to_string()).await;

    // 5. WAN Loop to handle ARP, ICMP transit, DNS queries, and unsolicited drop tests
    println!("[isp-test] Entering WAN verification event loop...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(60);

    loop {
        if start.elapsed() >= timeout_dur {
            break;
        }

        tokio::select! {
            cmd = wan_cmd_rx.recv() => {
                if let Some(cmd_str) = cmd && cmd_str == "SEND_UNSOLICITED_WAN" {
                    println!("[isp-test] Sending unsolicited DNS query to router's WAN IP: {}", MOCK_CLIENT_IP);
                    let unsolicited_pkt = build_udp_packet(
                        MOCK_SERVER_MAC,
                        client_mac,
                        MOCK_SERVER_IP, // send from gateway
                        MOCK_CLIENT_IP,
                        12345,
                        53,
                        DNS_QUERY,
                    );
                    let _ = mock.send_frame(&unsolicited_pkt).await;

                    // Start a 1-second monitoring window to check if any response comes back from the router
                    let monitor_start = std::time::Instant::now();
                    let mut packet_received = false;
                    while monitor_start.elapsed() < Duration::from_secs(1) {
                        if let Ok(Ok(f)) = tokio::time::timeout(Duration::from_millis(50), mock.recv_frame()).await
                            && let Some((src_ip, dest_ip, src_port, dest_port, _)) = parse_udp_packet(&f).ok().flatten()
                            && src_ip == MOCK_CLIENT_IP
                            && dest_ip == MOCK_SERVER_IP
                            && src_port == 53
                            && dest_port == 12345
                        {
                            packet_received = true;
                            break;
                        }
                    }

                    if packet_received {
                        println!("[isp-test] ERROR: Received DNS reply from router on WAN interface! Firewall did not drop the packet.");
                        let _ = verification_tx.send("FIREWALL_DROP_FAILED".to_string()).await;
                    } else {
                        println!("[isp-test] Verified: Firewall successfully dropped DNS query on WAN (no reply).");
                        let _ = verification_tx.send("FIREWALL_DROP_VERIFIED".to_string()).await;
                    }
                }
            }
            frame_res = tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()) => {
                let frame = match frame_res {
                    Ok(Ok(frame)) => frame,
                    Ok(Err(_)) => {
                        println!("[isp-test] WAN socket connection closed. Exiting verification loop.");
                        break;
                    }
                    Err(_) => continue, // Timeout
                };

                if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(&frame) {
                    println!(
                        "[isp-test] Received WAN frame: len={}, ethertype=0x{:04x}",
                        frame.len(),
                        eth.get_ethertype().0
                    );
                }

                // A. Handle ARP requests for WAN gateway / DNS server
                if let Some(arp_reply) = handle_arp_request(&frame).ok().flatten() {
                    let _ = mock.send_frame(&arp_reply).await;
                    continue;
                }

                // B. Handle ICMP request to 8.8.8.8 (checks NAT masquerading)
                if let Some((src_ip, dest_ip)) = parse_icmp_request(&frame).ok().flatten() {
                    if dest_ip == Ipv4Addr::new(8, 8, 8, 8) {
                        if src_ip == MOCK_CLIENT_IP {
                            println!("[isp-test] Verified NATed ICMP Request from WAN client!");
                            let _ = verification_tx.send("ICMP_VERIFIED".to_string()).await;
                        }
                        // Send ICMP Echo Reply back from 8.8.8.8 to the NATed client IP
                        let icmp_reply =
                            build_icmp_echo_reply(MOCK_SERVER_MAC, client_mac, dest_ip, src_ip, 0x4321, 1);
                        let _ = mock.send_frame(&icmp_reply).await;
                    }
                    continue;
                }

                // C. Handle DNS request to 10.0.2.3:53 (checks DNS forwarding)
                if let Some((src_ip, dest_ip, src_port, dest_port, payload)) = parse_udp_packet(&frame).ok().flatten() {
                    // F. Handle UDP NAT routing test to 8.8.8.8:23456
                    if dest_ip == Ipv4Addr::new(8, 8, 8, 8) && dest_port == 23456 {
                        if src_ip == MOCK_CLIENT_IP && payload == b"NAT_PING_TEST" {
                            println!("[isp-test] Verified NATed UDP Request from WAN client!");
                            let _ = verification_tx.send("ICMP_VERIFIED".to_string()).await;
                        }
                        println!(
                            "[isp-test] Sending NAT Pong Reply to {}:{} from {}:{}",
                            src_ip, src_port, dest_ip, dest_port
                        );
                        let udp_reply = build_udp_packet(
                            MOCK_SERVER_MAC,
                            client_mac,
                            dest_ip,
                            src_ip,
                            dest_port,
                            src_port,
                            b"NAT_PONG_TEST",
                        );
                        let _ = mock.send_frame(&udp_reply).await;
                        continue;
                    }

                    if dest_ip == MOCK_DNS_SERVER && dest_port == 53 {
                        if src_ip == MOCK_CLIENT_IP && payload.len() >= 2 && payload[2..] == DNS_QUERY[2..] {
                            println!("[isp-test] Verified DNS Forwarder query on WAN!");
                            let _ = verification_tx.send("DNS_VERIFIED".to_string()).await;
                        }

                        let mut response_payload = DNS_RESPONSE.to_vec();
                        if payload.len() >= 2 {
                            response_payload[0] = payload[0];
                            response_payload[1] = payload[1];
                        }

                        println!(
                            "[isp-test] Sending DNS Reply to {}:{} from {}:{} with client MAC: {}",
                            src_ip, src_port, dest_ip, dest_port, client_mac
                        );
                        let dns_reply = build_udp_packet(
                            MOCK_SERVER_MAC,
                            client_mac,
                            dest_ip,
                            src_ip,
                            dest_port,
                            src_port,
                            &response_payload,
                        );
                        let _ = mock.send_frame(&dns_reply).await;
                        continue;
                    }

                    // D. Handle NTP request to 8.8.8.8:123 (checks SNTP client synchronization)
                    if dest_port == 123 {
                        println!("[isp-test] Verified NTP request on WAN!");
                        let _ = verification_tx.send("NTP_VERIFIED".to_string()).await;

                        let mut ntp_resp = vec![0u8; 48];
                        ntp_resp[0] = 0x24; // LI=0, VN=4, Mode=4 (Server)
                        ntp_resp[1] = 0x01; // Stratum = 1 (primary reference)

                        if payload.len() >= 48 {
                            ntp_resp[24..32].copy_from_slice(&payload[40..48]);
                        }

                        // Set system time to year 2031 (seconds since 1900)
                        let ntp_secs = 4_144_934_400u64; // May 2031
                        let secs_bytes = (ntp_secs as u32).to_be_bytes();
                        ntp_resp[40] = secs_bytes[0];
                        ntp_resp[41] = secs_bytes[1];
                        ntp_resp[42] = secs_bytes[2];
                        ntp_resp[43] = secs_bytes[3];

                        println!(
                            "[isp-test] Sending NTP Reply to {}:{} from {}:{} with client MAC: {}",
                            src_ip, src_port, dest_ip, dest_port, client_mac
                        );

                        let ntp_reply = build_udp_packet(
                            MOCK_SERVER_MAC,
                            client_mac,
                            dest_ip,
                            src_ip,
                            dest_port,
                            src_port,
                            &ntp_resp,
                        );
                        let _ = mock.send_frame(&ntp_reply).await;
                        continue;
                    }
                }

                // E. Handle DHCPREQUEST (renewal)
                if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(&frame)
                    && eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4
                {
                        let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).unwrap();
                        if ip.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                            let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).unwrap();
                            if udp.get_destination() == 67
                                && let Ok(dhcp_req) = dhcproto::v4::Message::decode(&mut dhcproto::Decoder::new(udp.payload()))
                                && let Some(dhcproto::v4::DhcpOption::MessageType(dhcproto::v4::MessageType::Request)) = dhcp_req.opts().get(dhcproto::v4::OptionCode::MessageType)
                            {
                                println!("[isp-test] Verified DHCP renewal request from WAN client!");
                                let renew_ack = build_dhcp_ack(dhcp_req.xid(), client_mac);
                                let ack_frame = packet::build_raw_packet(
                                    MOCK_SERVER_MAC,
                                    client_mac,
                                    MOCK_SERVER_IP,
                                    Ipv4Addr::BROADCAST,
                                    67,
                                    68,
                                    &renew_ack,
                                );
                                let _ = mock.send_frame(&ack_frame).await;
                                let _ = verification_tx.send("DHCP_RENEWAL_VERIFIED".to_string()).await;
                                 continue;
                            }
                        }
                    }
                }
        }
    }

    true
}

fn parse_ipv4_source(frame: &[u8]) -> Option<Ipv4Addr> {
    let eth = pnet::packet::ethernet::EthernetPacket::new(frame)?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return None;
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload())?;
    Some(ip.get_source())
}

fn parse_dhcp_message(
    frame: &[u8],
) -> Result<dhcproto::v4::Message, Box<dyn std::error::Error + Send + Sync>> {
    if frame.len() < 42 {
        return Err("Packet too short".into());
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Err("Not an IPv4 packet".into());
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return Err("Not a UDP packet".into());
    }
    let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).ok_or("Malformed UDP packet")?;
    let dhcp = dhcproto::v4::Message::decode(&mut dhcproto::Decoder::new(udp.payload()))?;
    Ok(dhcp)
}

fn build_dhcp_offer(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut offer = Message::default();
    offer.set_opcode(Opcode::BootReply);
    offer.set_xid(xid);
    offer.set_yiaddr(MOCK_CLIENT_IP);
    offer.set_siaddr(MOCK_SERVER_IP);
    offer.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = offer.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Offer));
    opts.insert(DhcpOption::SubnetMask(MOCK_SUBNET_MASK));
    opts.insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
    opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![
        MOCK_DNS_SERVER,
    ]));
    opts.insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
    opts.insert(DhcpOption::AddressLeaseTime(6)); // Fast lease time (6 seconds) for testing renewal

    let mut payload = Vec::new();
    offer.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_dhcp_ack(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut ack = Message::default();
    ack.set_opcode(Opcode::BootReply);
    ack.set_xid(xid);
    ack.set_yiaddr(MOCK_CLIENT_IP);
    ack.set_siaddr(MOCK_SERVER_IP);
    ack.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = ack.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Ack));
    opts.insert(DhcpOption::SubnetMask(MOCK_SUBNET_MASK));
    opts.insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
    opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![
        MOCK_DNS_SERVER,
    ]));
    opts.insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
    opts.insert(DhcpOption::AddressLeaseTime(6)); // Fast lease time (6 seconds) for testing renewal

    let mut payload = Vec::new();
    ack.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_arp_reply(
    sender_mac: MacAddr,
    target_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::ethernet::EtherTypes;
    use pnet::packet::ethernet::MutableEthernetPacket;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let arp_header_len = MutableArpPacket::minimum_packet_size();
    let total_len = eth_header_len + arp_header_len;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(target_mac);
        eth.set_source(sender_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(pnet::packet::arp::ArpOperations::Reply);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);
    }

    buf
}

fn handle_arp_request(frame: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Arp {
        return Ok(None);
    }
    let arp = pnet::packet::arp::ArpPacket::new(eth.payload()).ok_or("Malformed ARP packet")?;
    if arp.get_operation() == pnet::packet::arp::ArpOperations::Request {
        let target_ip = arp.get_target_proto_addr();
        if target_ip == MOCK_SERVER_IP || target_ip == MOCK_DNS_SERVER {
            let arp_reply = build_arp_reply(
                MOCK_SERVER_MAC,
                arp.get_sender_hw_addr(),
                target_ip,
                arp.get_sender_proto_addr(),
            );
            return Ok(Some(arp_reply));
        }
    }
    Ok(None)
}

fn parse_icmp_request(
    frame: &[u8],
) -> Result<Option<(Ipv4Addr, Ipv4Addr)>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Ok(None);
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Icmp {
        return Ok(None);
    }
    let icmp = pnet::packet::icmp::IcmpPacket::new(ip.payload()).ok_or("Malformed ICMP packet")?;
    if icmp.get_icmp_type() == pnet::packet::icmp::IcmpTypes::EchoRequest {
        return Ok(Some((ip.get_source(), ip.get_destination())));
    }
    Ok(None)
}

type DnsRequestFields = (Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>);

fn parse_udp_packet(frame: &[u8]) -> Result<Option<DnsRequestFields>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Ok(None);
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return Ok(None);
    }
    let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).ok_or("Malformed UDP packet")?;
    Ok(Some((
        ip.get_source(),
        ip.get_destination(),
        udp.get_source(),
        udp.get_destination(),
        udp.payload().to_vec(),
    )))
}

fn build_udp_packet(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let udp_header_len = MutableUdpPacket::minimum_packet_size();

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dest_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length((ip_header_len / 4) as u8);
        ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);

        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dest_port);
        udp.set_length((udp_header_len + payload.len()) as u16);
        udp.set_payload(payload);
        udp.set_checksum(0);
    }

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    buf
}

fn build_icmp_echo_reply(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let icmp_header_len = 8;

    let total_len = eth_header_len + ip_header_len + icmp_header_len;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dest_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length((ip_header_len / 4) as u8);
        ip.set_total_length((ip_header_len + icmp_header_len) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);

        let mut icmp = MutableEchoReplyPacket::new(ip.payload_mut()).unwrap();
        icmp.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoReply);
        icmp.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
        icmp.set_identifier(identifier);
        icmp.set_sequence_number(sequence);

        let checksum = pnet::util::checksum(icmp.packet(), 1);
        icmp.set_checksum(checksum);
    }

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    buf
}
