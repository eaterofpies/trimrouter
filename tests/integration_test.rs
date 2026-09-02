#![allow(dead_code, unused_macros)]

use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable, Encoder};
use pnet::packet::arp::{ArpHardwareTypes, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::process::Command;

#[path = "../src/error.rs"]
mod error;

#[path = "../src/packet.rs"]
mod packet;

#[path = "../src/services/ipc.rs"]
mod ipc;

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
        let len = frame.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(frame).await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> std::io::Result<Vec<u8>> {
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
    _lan_client_handle: tokio::task::JoinHandle<()>,
    verification_rx: tokio::sync::mpsc::Receiver<String>,
    wan_cmd_tx: tokio::sync::mpsc::Sender<String>,
    lan_cmd_tx: tokio::sync::mpsc::Sender<String>,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file("target/wan.sock");
        let _ = std::fs::remove_file("target/lan.sock");
    }
}

#[tokio::main]
async fn main() {
    std::println!("\nrunning 9 integration test steps in QEMU VM");

    let test_timeout = std::time::Duration::from_secs(300);
    let start_time = std::time::Instant::now();

    // 1. Build test initramfs and start mocks/QEMU
    let mut env = startup_stage().await;

    // 3. Monitor QEMU output and verification signals in parallel
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
                            } else if line.contains("[test-control] TRIGGER_INVALID_CONNTRACK_TRAFFIC") {
                                let _ = env.wan_cmd_tx.send("SEND_INVALID_CONNTRACK_WAN".to_string()).await;
                            } else if line.contains("[test-control] TRIGGER_LAN_DHCP_HANDSHAKE") {
                                let _ = env.lan_cmd_tx.send("TRIGGER_LAN_DHCP_HANDSHAKE".to_string()).await;
                            } else if line.contains("[test-control] TRIGGER_FORWARDED_NAT_TEST") {
                                let _ = env.lan_cmd_tx.send("TRIGGER_FORWARDED_NAT_TEST".to_string()).await;
                            } else if line.contains("[test-control] TRIGGER_DNS_CLIENT_TEST") {
                                let _ = env.lan_cmd_tx.send("TRIGGER_DNS_CLIENT_TEST".to_string()).await;
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
                Some(sig) = env.verification_rx.recv() => {
                    println!("[test-env] Received network-level verification signal: {}", sig);
                    if sig == "SIMULATE_DNS_OUTAGE" {
                        let _ = env.wan_cmd_tx.send("SIMULATE_DNS_OUTAGE".to_string()).await;
                    } else if sig == "END_DNS_OUTAGE" {
                        let _ = env.wan_cmd_tx.send("END_DNS_OUTAGE".to_string()).await;
                    }
                }
            }
        }
    }).await;

    let elapsed = start_time.elapsed();

    println!("\n=== Cleaning up QEMU VM... ===");
    // Clean up QEMU process
    drop(env);
    tokio::time::sleep(Duration::from_millis(500)).await;

    if result.is_err() {
        println!(
            "\ntest result: FAILED (TIMEOUT - Integration test exceeded {}s limit)\n",
            test_timeout.as_secs()
        );
        std::process::exit(102);
    }

    // Verify system.log persists in FAT32 Partition 2 on the host disk image
    let image_path = PathBuf::from("target/x86_64/trimrouter-test.img");
    if let Err(e) = verify_host_image_log_partition(&image_path) {
        println!(
            "\n[test-host] FAILED to verify system.log on Partition 2: {}\n",
            e
        );
        std::process::exit(103);
    } else {
        println!(
            "[test-host] Successfully verified system.log persistence in Partition 2 of test image!"
        );
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

fn verify_host_image_log_partition(image_path: &std::path::Path) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .map_err(|e| e.to_string())?;
    let mbr = mbrman::MBR::read_from(&mut file, 512).map_err(|e| e.to_string())?;
    let p2 = &mbr[2];
    if p2.sectors == 0 || p2.starting_lba == 0 {
        return Err("Partition 2 not found in MBR of disk image".to_string());
    }
    let p2_start_bytes = (p2.starting_lba as u64) * 512;
    let p2_size_bytes = (p2.sectors as u64) * 512;

    let slice = PartitionSlice::new(file, p2_start_bytes, p2_size_bytes);
    let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
        .map_err(|e| format!("Failed to open FAT32 on partition 2: {}", e))?;
    let root = fs.root_dir();
    let mut found_system_log = false;
    for entry in root.iter() {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if name.eq_ignore_ascii_case("system.log") {
            found_system_log = true;
            if entry.len() == 0 {
                return Err("system.log on partition 2 is empty (0 bytes)".to_string());
            }
            let mut log_content = Vec::new();
            let mut log_file = entry.to_file();
            log_file
                .read_to_end(&mut log_content)
                .map_err(|e| e.to_string())?;
            let log_str = String::from_utf8_lossy(&log_content);
            if !log_str.contains("[INFO]") {
                return Err("system.log does not contain expected log formatting".to_string());
            }
            break;
        }
    }
    if !found_system_log {
        return Err("system.log was not found on partition 2 of the disk image".to_string());
    }
    Ok(())
}

struct PartitionSlice {
    file: std::fs::File,
    offset: u64,
    size: u64,
    pos: u64,
}

impl PartitionSlice {
    fn new(file: std::fs::File, offset: u64, size: u64) -> Self {
        Self {
            file,
            offset,
            size,
            pos: 0,
        }
    }
}

impl std::io::Read for PartitionSlice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = (self.size.saturating_sub(self.pos)) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(self.offset + self.pos))?;
        let bytes = self.file.read(&mut buf[..to_read])?;
        self.pos += bytes as u64;
        Ok(bytes)
    }
}

impl std::io::Write for PartitionSlice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.seek(SeekFrom::Start(self.offset + self.pos))?;
        let bytes = self.file.write(buf)?;
        self.pos += bytes as u64;
        Ok(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl std::io::Seek for PartitionSlice {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            std::io::SeekFrom::Start(offset) => offset as i64,
            std::io::SeekFrom::Current(offset) => (self.pos as i64).saturating_add(offset),
            std::io::SeekFrom::End(offset) => (self.size as i64).saturating_add(offset),
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "negative seek position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

fn find_ovmf_firmware() -> PathBuf {
    const CANDIDATES: [&str; 4] = [
        "/usr/share/OVMF/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/qemu/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    ];
    for candidate in &CANDIDATES {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!("OVMF UEFI firmware not found. Please install `ovmf` (e.g. `apt-get install -y ovmf`).");
}

async fn startup_stage() -> TestEnv {
    // A. Build the test target disk image
    let test_arch = std::env::var("TEST_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let target_path = format!("target/{test_arch}/trimrouter-test.img");
    let build_status = Command::new("make")
        .arg(target_path)
        .arg(format!("ARCH={test_arch}"))
        .status()
        .await
        .expect("Failed to run make");
    assert!(
        build_status.success(),
        "Failed to build test image via make"
    );

    // Ensure target directory exists
    let _ = std::fs::create_dir_all("target");

    // Remove any existing socket files
    let _ = std::fs::remove_file("target/wan.sock");
    let _ = std::fs::remove_file("target/lan.sock");

    // B. Bind the WAN UNIX socket listener
    let wan_listener =
        UnixListener::bind("target/wan.sock").expect("Failed to bind WAN UNIX socket");

    // MPSC Channel to coordinate mock WAN ISP and LAN client
    let (verification_tx, verification_rx) = tokio::sync::mpsc::channel::<String>(100);
    let (wan_cmd_tx, wan_cmd_rx) = tokio::sync::mpsc::channel::<String>(100);
    let (lan_cmd_tx, lan_cmd_rx) = tokio::sync::mpsc::channel::<String>(100);

    // C. Start our mock WAN ISP gateway in a background task
    let verification_tx_wan = verification_tx.clone();
    let wan_isp_handle = tokio::spawn(async move {
        let (stream, _) = wan_listener
            .accept()
            .await
            .expect("Failed to accept WAN connection from QEMU");
        let mock = UnixStreamMock::new(stream);
        run_mock_wan_isp(mock, verification_tx_wan, wan_cmd_rx).await
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
    args.extend(["-m".to_string(), "256".to_string()]);

    if test_arch == "x86_64" {
        let ovmf_path = find_ovmf_firmware();
        args.extend(["-bios".to_string(), ovmf_path.to_string_lossy().to_string()]);
    } else {
        let console = "ttyAMA0";
        let append_arg = format!("console={} loglevel=3 panic=1 net.ifnames=0", console);
        let kernel = format!("target/{test_arch}/test_boot/vmlinuz");
        let initrd = format!("target/{test_arch}/initramfs-test.cpio.gz");
        args.extend([
            "-kernel".to_string(),
            kernel,
            "-initrd".to_string(),
            initrd,
            "-append".to_string(),
            append_arg,
        ]);
    }

    if test_arch == "x86_64" {
        args.extend([
            "-device".to_string(),
            "i6300esb".to_string(),
            "-watchdog-action".to_string(),
            "none".to_string(),
        ]);
    }

    args.extend(
        [
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
            "-no-reboot",
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

    let verification_tx_clone = verification_tx.clone();
    let lan_client_handle = tokio::spawn(async move {
        // Wait for target/lan.sock to exist (created by QEMU stream server backend)
        let mut stream = None;
        for _ in 0..100 {
            if std::path::Path::new("target/lan.sock").exists()
                && let Ok(s) = tokio::net::UnixStream::connect("target/lan.sock").await
            {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stream = stream.expect("Failed to connect to guest LAN socket");
        println!("[test-env] Connected to guest LAN socket.");
        let mock = UnixStreamMock::new(stream);
        run_mock_lan_client(mock, lan_cmd_rx, verification_tx_clone).await;
    });

    TestEnv {
        _qemu_guard: qemu_kill_guard.unwrap(),
        _qemu_child: qemu_child,
        _wan_isp_handle: wan_isp_handle,
        _lan_client_handle: lan_client_handle,
        verification_rx,
        wan_cmd_tx,
        lan_cmd_tx,
    }
}

async fn collect_dhcp_discovers(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
) -> Option<(u32, MacAddr)> {
    const DISCOVERS_TO_VERIFY: usize = 3;
    println!("[isp-test] Waiting for {DISCOVERS_TO_VERIFY} DHCPDISCOVER packets...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(180);
    let mut discovers_seen = 0;
    let mut client_mac = MacAddr::zero();
    let mut xid = 0;

    loop {
        if start.elapsed() >= timeout_dur {
            if discovers_seen == 0 {
                println!("[isp-test] Timeout waiting for DHCPDISCOVER");
                return None;
            }
            break;
        }
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] Connection closed while waiting for DHCPDISCOVER");
                return None;
            }
            Err(_) => continue,
        };

        if let Ok(dhcp_discover) = parse_dhcp_message(&frame) {
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
    Some((xid, client_mac))
}

async fn await_dhcp_request(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    xid: u32,
) -> bool {
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
            Err(_) => continue,
        };
        if let Ok(dhcp_request) = parse_dhcp_message(&frame) {
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
                return true;
            }
        }
    }
}

async fn handle_unsolicited_wan_traffic(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    client_mac: MacAddr,
) {
    println!(
        "[isp-test] Sending unsolicited DNS query to router's WAN IP: {}",
        MOCK_CLIENT_IP
    );
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
            && let Some((src_ip, dest_ip, src_port, dest_port, _)) =
                parse_udp_packet(&f).ok().flatten()
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
        println!(
            "[isp-test] ERROR: Received DNS reply from router on WAN interface! Firewall did not drop the packet."
        );
        let _ = verification_tx
            .send("FIREWALL_DROP_FAILED".to_string())
            .await;
    } else {
        println!("[isp-test] Verified: Firewall successfully dropped DNS query on WAN (no reply).");
        let _ = verification_tx
            .send("FIREWALL_DROP_VERIFIED".to_string())
            .await;
    }
}

async fn handle_invalid_conntrack_traffic(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    client_mac: MacAddr,
) {
    println!(
        "[isp-test] Sending invalid conntrack packet (mangled TCP SYN+FIN) to router's WAN IP: {}",
        MOCK_CLIENT_IP
    );
    let eth_header_len = 14;
    let ip_header_len = 20;
    let tcp_header_len = 20;
    let mut frame = vec![0u8; eth_header_len + ip_header_len + tcp_header_len];

    // Ethernet
    frame[0..6].copy_from_slice(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);
    frame[6..12].copy_from_slice(&[
        MOCK_SERVER_MAC.0,
        MOCK_SERVER_MAC.1,
        MOCK_SERVER_MAC.2,
        MOCK_SERVER_MAC.3,
        MOCK_SERVER_MAC.4,
        MOCK_SERVER_MAC.5,
    ]);
    frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((ip_header_len + tcp_header_len) as u16).to_be_bytes());
    frame[22] = 64; // TTL
    frame[23] = libc::IPPROTO_TCP as u8;
    frame[26..30].copy_from_slice(&MOCK_SERVER_IP.octets());
    frame[30..34].copy_from_slice(&MOCK_CLIENT_IP.octets());

    // TCP with conflicting flags SYN (0x02) + FIN (0x01) = 0x03 invalid state
    let tcp_offset = eth_header_len + ip_header_len;
    frame[tcp_offset..tcp_offset + 2].copy_from_slice(&12345u16.to_be_bytes()); // src port
    frame[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&80u16.to_be_bytes()); // dst port
    frame[tcp_offset + 12] = 5 << 4; // Data offset
    frame[tcp_offset + 13] = 0x03; // SYN + FIN

    let _ = mock.send_frame(&frame).await;

    // Start a 1-second monitoring window to check if any response comes back
    let monitor_start = std::time::Instant::now();
    let mut packet_received = false;
    while monitor_start.elapsed() < Duration::from_secs(1) {
        if let Ok(Ok(f)) = tokio::time::timeout(Duration::from_millis(50), mock.recv_frame()).await
            && let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(&f)
            && eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4
            && let Some(ip) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload())
            && ip.get_source() == MOCK_CLIENT_IP
            && ip.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp
        {
            packet_received = true;
            break;
        }
    }

    if packet_received {
        println!("[isp-test] ERROR: Router responded to invalid conntrack packet!");
    } else {
        println!(
            "[isp-test] Verified: Firewall ct state invalid successfully dropped invalid TCP packet."
        );
        let _ = verification_tx
            .send("FIREWALL_INVALID_DROP_VERIFIED".to_string())
            .await;
    }
}

struct WanUdpPacket<'a> {
    client_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &'a [u8],
}

async fn process_wan_dns_query(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    pkt: &WanUdpPacket<'_>,
    dns_outage_active: bool,
) {
    if dns_outage_active {
        println!("[isp-test] Simulated upstream DNS outage: dropping query.");
        return;
    }
    if pkt.src_ip == MOCK_CLIENT_IP && pkt.payload.len() >= 2 && pkt.payload[2..] == DNS_QUERY[2..]
    {
        println!("[isp-test] Verified DNS Forwarder query on WAN!");
        let _ = verification_tx.send("DNS_VERIFIED".to_string()).await;
    }

    let mut response_payload = DNS_RESPONSE.to_vec();
    if pkt.payload.len() >= 2 {
        response_payload[0] = pkt.payload[0];
        response_payload[1] = pkt.payload[1];
    }

    println!(
        "[isp-test] Sending DNS Reply to {}:{} from {}:{} with client MAC: {}",
        pkt.src_ip, pkt.src_port, pkt.dest_ip, pkt.dest_port, pkt.client_mac
    );
    let dns_reply = build_udp_packet(
        MOCK_SERVER_MAC,
        pkt.client_mac,
        pkt.dest_ip,
        pkt.src_ip,
        pkt.dest_port,
        pkt.src_port,
        &response_payload,
    );
    let _ = mock.send_frame(&dns_reply).await;
}

async fn process_wan_ntp_request(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    pkt: &WanUdpPacket<'_>,
) {
    println!("[isp-test] Verified NTP request on WAN!");
    let _ = verification_tx.send("NTP_VERIFIED".to_string()).await;

    let mut ntp_resp = vec![0u8; 48];
    ntp_resp[0] = 0x24; // LI=0, VN=4, Mode=4 (Server)
    ntp_resp[1] = 0x01; // Stratum = 1 (primary reference)

    if pkt.payload.len() >= 48 {
        ntp_resp[24..32].copy_from_slice(&pkt.payload[40..48]);
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
        pkt.src_ip, pkt.src_port, pkt.dest_ip, pkt.dest_port, pkt.client_mac
    );

    let ntp_reply = build_udp_packet(
        MOCK_SERVER_MAC,
        pkt.client_mac,
        pkt.dest_ip,
        pkt.src_ip,
        pkt.dest_port,
        pkt.src_port,
        &ntp_resp,
    );
    let _ = mock.send_frame(&ntp_reply).await;
}

async fn process_wan_dhcp_renewal(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    client_mac: MacAddr,
    frame: &[u8],
) {
    if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame)
        && eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4
        && let Some(ip) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload())
        && ip.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp
        && let Some(udp) = pnet::packet::udp::UdpPacket::new(ip.payload())
        && udp.get_destination() == 67
        && let Ok(dhcp_req) =
            dhcproto::v4::Message::decode(&mut dhcproto::Decoder::new(udp.payload()))
        && let Some(dhcproto::v4::DhcpOption::MessageType(dhcproto::v4::MessageType::Request)) =
            dhcp_req.opts().get(dhcproto::v4::OptionCode::MessageType)
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
        )
        .expect("valid ack frame");
        let _ = mock.send_frame(&ack_frame).await;
        let _ = verification_tx
            .send("DHCP_RENEWAL_VERIFIED".to_string())
            .await;
    }
}

async fn run_mock_wan_isp(
    mut mock: UnixStreamMock,
    verification_tx: tokio::sync::mpsc::Sender<String>,
    mut wan_cmd_rx: tokio::sync::mpsc::Receiver<String>,
) -> bool {
    // 1. Collect DHCPDISCOVER
    let Some((xid, client_mac)) = collect_dhcp_discovers(&mut mock, &verification_tx).await else {
        return false;
    };

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
    )
    .expect("valid offer frame");
    if mock.send_frame(&offer_frame).await.is_err() {
        return false;
    }

    // 3. Wait for DHCPREQUEST
    if !await_dhcp_request(&mut mock, &verification_tx, xid).await {
        return false;
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
    )
    .expect("valid ack frame");
    if mock.send_frame(&ack_frame).await.is_err() {
        return false;
    }

    // Notify coordinator that WAN DHCP setup is finished
    let _ = verification_tx.send("WAN_DHCP_DONE".to_string()).await;

    // 5. WAN Loop to handle ARP, ICMP transit, DNS queries, and unsolicited drop tests
    println!("[isp-test] Entering WAN verification event loop...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(180);
    let mut dns_outage_active = false;

    loop {
        if start.elapsed() >= timeout_dur {
            break;
        }

        tokio::select! {
            cmd = wan_cmd_rx.recv() => {
                if let Some(cmd_str) = cmd {
                    if cmd_str == "SEND_UNSOLICITED_WAN" {
                        handle_unsolicited_wan_traffic(&mut mock, &verification_tx, client_mac).await;
                    } else if cmd_str == "SEND_INVALID_CONNTRACK_WAN" {
                        handle_invalid_conntrack_traffic(&mut mock, &verification_tx, client_mac).await;
                    } else if cmd_str == "SIMULATE_DNS_OUTAGE" {
                        println!("[isp-test] Simulating upstream DNS outage.");
                        dns_outage_active = true;
                    } else if cmd_str == "END_DNS_OUTAGE" {
                        println!("[isp-test] Ending simulated upstream DNS outage.");
                        dns_outage_active = false;
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
                    Err(_) => continue,
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
                        let icmp_reply =
                            build_icmp_echo_reply(MOCK_SERVER_MAC, client_mac, dest_ip, src_ip, 0x4321, 1);
                        let _ = mock.send_frame(&icmp_reply).await;
                    }
                    continue;
                }

                // C. Handle UDP packets
                if let Some((src_ip, dest_ip, src_port, dest_port, payload)) = parse_udp_packet(&frame).ok().flatten() {
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

                    let wan_pkt = WanUdpPacket {
                        client_mac,
                        src_ip,
                        dest_ip,
                        src_port,
                        dest_port,
                        payload: &payload,
                    };

                    if dest_ip == MOCK_DNS_SERVER && dest_port == 53 {
                        process_wan_dns_query(
                            &mut mock,
                            &verification_tx,
                            &wan_pkt,
                            dns_outage_active,
                        ).await;
                        continue;
                    }

                    if dest_port == 123 {
                        process_wan_ntp_request(
                            &mut mock,
                            &verification_tx,
                            &wan_pkt,
                        ).await;
                        continue;
                    }
                }

                // D. Handle DHCPREQUEST (renewal)
                process_wan_dhcp_renewal(&mut mock, &verification_tx, client_mac, &frame).await;
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

fn handle_arp_request_for_ip(
    frame: &[u8],
    _client_mac: MacAddr,
    client_ip: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let eth = pnet::packet::ethernet::EthernetPacket::new(frame)?;
    if eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Arp {
        let arp = pnet::packet::arp::ArpPacket::new(eth.payload())?;
        if arp.get_operation() == pnet::packet::arp::ArpOperations::Request {
            let target_ip = arp.get_target_proto_addr();
            if let Some(ip) = client_ip
                && target_ip == ip
            {
                return Some(ip);
            }
        }
    }
    None
}

fn build_dhcp_discover_lan(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    let mut disc = Message::default();
    disc.set_opcode(Opcode::BootRequest);
    disc.set_xid(xid);
    disc.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = disc.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Discover));
    opts.insert(DhcpOption::ParameterRequestList(vec![
        dhcproto::v4::OptionCode::SubnetMask,
        dhcproto::v4::OptionCode::Router,
        dhcproto::v4::OptionCode::DomainNameServer,
    ]));

    let mut payload = Vec::new();
    disc.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_dhcp_request_lan(
    xid: u32,
    client_mac: MacAddr,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut req = Message::default();
    req.set_opcode(Opcode::BootRequest);
    req.set_xid(xid);
    req.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = req.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Request));
    opts.insert(DhcpOption::RequestedIpAddress(requested_ip));
    opts.insert(DhcpOption::ServerIdentifier(server_ip));
    opts.insert(DhcpOption::Hostname("printer.local".to_string()));

    let mut payload = Vec::new();
    req.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

async fn handle_lan_command(
    mock: &mut UnixStreamMock,
    cmd: &str,
    client_mac: MacAddr,
    dns_test_phase: &mut i32,
) {
    if cmd == "TRIGGER_LAN_DHCP_HANDSHAKE" {
        println!("[lan-client] Starting DHCP Handshake...");
        let xid = rand::random::<u32>();
        let discover_payload = build_dhcp_discover_lan(xid, client_mac);
        let discover_pkt = packet::build_raw_packet(
            client_mac,
            MacAddr::broadcast(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            68,
            67,
            &discover_payload,
        )
        .expect("valid discover pkt");
        if let Err(e) = mock.send_frame(&discover_pkt).await {
            println!("[lan-client] ERROR sending DHCPDISCOVER: {}", e);
        } else {
            println!("[lan-client] Sent DHCPDISCOVER (xid: {})", xid);
        }
    } else if cmd == "TRIGGER_FORWARDED_NAT_TEST" {
        println!("[lan-client] Starting Forwarded NAT test...");
        let payload = b"NAT_PING_TEST";
        let pkt = packet::build_raw_packet(
            client_mac,
            MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x57), // router's LAN MAC
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            23456,
            23456,
            payload,
        )
        .expect("valid nat pkt");
        if let Err(e) = mock.send_frame(&pkt).await {
            println!("[lan-client] ERROR sending NAT Ping: {}", e);
        } else {
            println!("[lan-client] Sent NAT Ping to 8.8.8.8:23456");
        }
    } else if cmd == "TRIGGER_DNS_CLIENT_TEST" {
        println!("[lan-client] Starting DNS Client Cache Verification test...");
        *dns_test_phase = 1;
        let pkt = packet::build_raw_packet(
            client_mac,
            MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x57), // router's LAN MAC
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(192, 168, 1, 1),
            12345, // client port
            53,    // DNS port
            DNS_QUERY,
        )
        .expect("valid dns query pkt");
        if let Err(e) = mock.send_frame(&pkt).await {
            println!("[lan-client] ERROR sending DNS Query 1: {}", e);
        } else {
            println!("[lan-client] Sent DNS Query 1 to 192.168.1.1:53");
        }
    }
}

async fn process_lan_arp(
    mock: &mut UnixStreamMock,
    frame: &[u8],
    client_mac: MacAddr,
    assigned_ip: Option<Ipv4Addr>,
) {
    if let Some(target_ip) = handle_arp_request_for_ip(frame, client_mac, assigned_ip)
        && let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame)
        && let Some(arp) = pnet::packet::arp::ArpPacket::new(eth.payload())
    {
        println!(
            "[lan-client] Received ARP request for target IP: {}. Replying...",
            target_ip
        );
        let reply = build_arp_reply(
            client_mac,
            eth.get_source(),
            target_ip,
            arp.get_sender_proto_addr(),
        );
        let _ = mock.send_frame(&reply).await;
    }
}

async fn process_lan_icmp(
    mock: &mut UnixStreamMock,
    frame: &[u8],
    client_mac: MacAddr,
    assigned_ip: Option<Ipv4Addr>,
) {
    if let Some((src_ip, dest_ip)) = parse_icmp_request(frame).ok().flatten()
        && Some(dest_ip) == assigned_ip
        && let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(frame)
    {
        println!(
            "[lan-client] Received ICMP request from {} to {}. Replying...",
            src_ip, dest_ip
        );
        let mut icmp_id = 0x4321;
        let mut icmp_seq = 1;
        if let Some(ip) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload())
            && let Some(icmp) =
                pnet::packet::icmp::echo_request::EchoRequestPacket::new(ip.payload())
        {
            icmp_id = icmp.get_identifier();
            icmp_seq = icmp.get_sequence_number();
        }
        let reply = build_icmp_echo_reply(
            client_mac,
            eth.get_source(),
            dest_ip,
            src_ip,
            icmp_id,
            icmp_seq,
        );
        let _ = mock.send_frame(&reply).await;
    }
}

async fn process_lan_udp_nat(
    mock: &mut UnixStreamMock,
    client_mac: MacAddr,
    src_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) {
    if src_ip == Ipv4Addr::new(8, 8, 8, 8)
        && src_port == 23456
        && dest_port == 23456
        && payload == b"NAT_PONG_TEST"
    {
        println!("[lan-client] Received NAT_PONG_TEST from 8.8.8.8! NAT verified.");
        let confirm_pkt = packet::build_raw_packet(
            client_mac,
            MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x57), // router's LAN MAC
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(192, 168, 1, 1),
            23456,
            23457,
            b"FORWARDED_NAT_OK",
        )
        .expect("valid confirm pkt");
        let _ = mock.send_frame(&confirm_pkt).await;
    }
}

struct LanUdpPacket<'a> {
    client_mac: MacAddr,
    src_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &'a [u8],
}

async fn process_lan_udp_dns(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    pkt: &LanUdpPacket<'_>,
    dns_test_phase: &mut i32,
) {
    if pkt.src_ip == Ipv4Addr::new(192, 168, 1, 1)
        && pkt.src_port == 53
        && pkt.dest_port == 12345
        && pkt.payload.len() >= 2
        && pkt.payload[2..] == DNS_RESPONSE[2..]
    {
        if *dns_test_phase == 1 {
            println!(
                "[lan-client] DNS Query 1 resolved successfully! Requesting SIMULATE_DNS_OUTAGE..."
            );
            *dns_test_phase = 2;
            let _ = verification_tx
                .send("SIMULATE_DNS_OUTAGE".to_string())
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let req_pkt = packet::build_raw_packet(
                pkt.client_mac,
                MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x57), // router's LAN MAC
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 1),
                12345, // client port
                53,    // DNS port
                DNS_QUERY,
            )
            .expect("valid dns req pkt");
            let _ = mock.send_frame(&req_pkt).await;
            println!(
                "[lan-client] Sent DNS Query 2 (which must be served from cache) to 192.168.1.1:53"
            );
        } else if *dns_test_phase == 2 {
            println!("[lan-client] DNS Query 2 resolved successfully! DNS Caching verified.");
            *dns_test_phase = 0;
            let _ = verification_tx.send("END_DNS_OUTAGE".to_string()).await;
            let confirm_pkt = packet::build_raw_packet(
                pkt.client_mac,
                MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x57), // router's LAN MAC
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 1),
                23456,
                23457,
                b"DNS_CACHE_OK",
            )
            .expect("valid confirm pkt");
            let _ = mock.send_frame(&confirm_pkt).await;
        }
    }
}

async fn process_lan_dhcp(
    mock: &mut UnixStreamMock,
    verification_tx: &tokio::sync::mpsc::Sender<String>,
    client_mac: MacAddr,
    frame: &[u8],
    assigned_ip: &mut Option<Ipv4Addr>,
) {
    if let Ok(dhcp_msg) = parse_dhcp_message(frame) {
        let xid = dhcp_msg.xid();
        let msg_type = dhcp_msg.opts().get(dhcproto::v4::OptionCode::MessageType);

        match msg_type {
            Some(dhcproto::v4::DhcpOption::MessageType(dhcproto::v4::MessageType::Offer)) => {
                let offered_ip = dhcp_msg.yiaddr();
                println!("[lan-client] Received DHCPOFFER for IP: {}", offered_ip);
                let request_payload = build_dhcp_request_lan(
                    xid,
                    client_mac,
                    offered_ip,
                    Ipv4Addr::new(192, 168, 1, 1),
                );
                let request_pkt = packet::build_raw_packet(
                    client_mac,
                    MacAddr::broadcast(),
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                    68,
                    67,
                    &request_payload,
                )
                .expect("valid req pkt");
                let _ = mock.send_frame(&request_pkt).await;
                println!("[lan-client] Sent DHCPREQUEST for IP: {}", offered_ip);
            }
            Some(dhcproto::v4::DhcpOption::MessageType(dhcproto::v4::MessageType::Ack)) => {
                let acked_ip = dhcp_msg.yiaddr();
                println!("[lan-client] Received DHCPACK! IP: {} assigned.", acked_ip);
                *assigned_ip = Some(acked_ip);
                let _ = verification_tx.send("LAN_DHCP_VERIFIED".to_string()).await;
            }
            _ => {}
        }
    }
}

async fn run_mock_lan_client(
    mut mock: UnixStreamMock,
    mut cmd_rx: tokio::sync::mpsc::Receiver<String>,
    verification_tx: tokio::sync::mpsc::Sender<String>,
) {
    let client_mac = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
    let mut assigned_ip = None;
    let mut dns_test_phase = 0;

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                handle_lan_command(&mut mock, &cmd, client_mac, &mut dns_test_phase).await;
            }
            frame_res = mock.recv_frame() => {
                let frame = match frame_res {
                    Ok(f) => f,
                    Err(_) => break, // Socket closed
                };

                process_lan_arp(&mut mock, &frame, client_mac, assigned_ip).await;
                process_lan_icmp(&mut mock, &frame, client_mac, assigned_ip).await;

                if let Some((src_ip, src_port, dest_port, payload)) = parse_udp_payload(&frame) {
                    process_lan_udp_nat(&mut mock, client_mac, src_ip, src_port, dest_port, &payload).await;
                    let lan_pkt = LanUdpPacket {
                        client_mac,
                        src_ip,
                        src_port,
                        dest_port,
                        payload: &payload,
                    };
                    process_lan_udp_dns(&mut mock, &verification_tx, &lan_pkt, &mut dns_test_phase).await;
                }

                process_lan_dhcp(&mut mock, &verification_tx, client_mac, &frame, &mut assigned_ip).await;
            }
        }
    }
}

fn parse_udp_payload(frame: &[u8]) -> Option<(Ipv4Addr, u16, u16, Vec<u8>)> {
    let eth = pnet::packet::ethernet::EthernetPacket::new(frame)?;
    if eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
        let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload())?;
        if ip.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
            let udp = pnet::packet::udp::UdpPacket::new(ip.payload())?;
            return Some((
                ip.get_source(),
                udp.get_source(),
                udp.get_destination(),
                udp.payload().to_vec(),
            ));
        }
    }
    None
}
