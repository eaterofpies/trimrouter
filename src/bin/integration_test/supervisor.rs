use std::time::Duration;
use trimrouter::services::DnsForwarder;

pub async fn test_dns_supervisor_recovery(
    dns_forwarder: DnsForwarder,
) -> Result<DnsForwarder, String> {
    std::println!("[test] Starting DNS Supervisor Recovery test...");

    // 1. Get original worker PID
    let pid1 = dns_forwarder.get_worker_pid();
    if pid1 == 0 {
        return Err("DNS forwarder has no active worker PID".to_string());
    }
    std::println!("[test] Initial DNS forwarder worker PID: {}", pid1);

    // 2. Kill the worker process (simulating a crash)
    let pid_nix = nix::unistd::Pid::from_raw(pid1 as i32);
    nix::sys::signal::kill(pid_nix, nix::sys::signal::Signal::SIGKILL)
        .map_err(|e| format!("Failed to kill worker process: {}", e))?;
    std::println!("[test] Sent SIGKILL to DNS forwarder worker PID {}", pid1);

    // 3. Wait for supervisor to restart it (first restart delay is 2 seconds, let's wait 3.5 seconds)
    std::println!("[test] Waiting for supervisor to restart the crashed worker...");
    tokio::time::sleep(Duration::from_millis(3500)).await;

    // 4. Verify that the new worker PID is active and different
    let pid2 = dns_forwarder.get_worker_pid();
    if pid2 == 0 {
        return Err("DNS forwarder supervisor failed to restart worker (PID is 0)".to_string());
    }
    if pid2 == pid1 {
        return Err(format!(
            "DNS forwarder PID did not change after crash: {}",
            pid2
        ));
    }
    std::println!(
        "[test] DNS forwarder supervisor successfully restarted worker. New PID: {}",
        pid2
    );

    // 5. Verify the restarted DNS forwarder is still operational over TCP and UDP
    crate::dns_forwarder::verify_tcp_dns_resolution().await?;

    // We bind to UDP port 23457 to receive the confirmation
    let socket = std::net::UdpSocket::bind("192.168.1.1:23457").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    std::println!("[test-control] TRIGGER_DNS_CLIENT_TEST");

    let mut buf = [0u8; 512];
    let (amt, _src) = socket.recv_from(&mut buf).map_err(|e| {
        format!(
            "Timed out waiting for DNS caching verification after supervisor restart: {}",
            e
        )
    })?;

    if &buf[..amt] == b"DNS_CACHE_OK" {
        std::println!("[test] DNS Forwarder successfully recovered and served queries.");
        Ok(dns_forwarder)
    } else {
        Err(format!(
            "Received invalid DNS verification payload after restart: {:?}",
            String::from_utf8_lossy(&buf[..amt])
        ))
    }
}

pub fn test_seccomp_sandbox_enforcement() -> Result<(), String> {
    std::println!("[test] Starting Seccomp Sandbox BPF Enforcement test...");

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => {
            if let Err(e) = trimrouter::services::utils::apply_seccomp() {
                std::eprintln!("[test-seccomp] Failed to apply seccomp in child: {}", e);
                std::process::exit(1);
            }

            // 1. Verify unauthorized syscall (SYS_ptrace) is blocked with EPERM
            let res = unsafe { libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0) };
            let err = std::io::Error::last_os_error();
            if res != -1 || err.raw_os_error() != Some(libc::EPERM) {
                std::eprintln!(
                    "[test-seccomp] SYS_ptrace did not return EPERM: res={}, err={}",
                    res,
                    err
                );
                std::process::exit(2);
            }

            // 2. Verify unauthorized socket syscall (SYS_socket) is blocked with EPERM
            let sock_res =
                unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_DGRAM, 0) };
            let sock_err = std::io::Error::last_os_error();
            if sock_res != -1 || sock_err.raw_os_error() != Some(libc::EPERM) {
                std::eprintln!(
                    "[test-seccomp] SYS_socket did not return EPERM: res={}, err={}",
                    sock_res,
                    sock_err
                );
                std::process::exit(3);
            }

            // 3. Verify std::net::UdpSocket::bind fails with PermissionDenied (EPERM)
            match std::net::UdpSocket::bind("127.0.0.1:0") {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    std::process::exit(0);
                }
                other => {
                    std::eprintln!(
                        "[test-seccomp] UdpSocket::bind did not fail with PermissionDenied: {:?}",
                        other
                    );
                    std::process::exit(4);
                }
            }
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            let status = nix::sys::wait::waitpid(child, None)
                .map_err(|e| format!("Failed to wait for child: {}", e))?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, 0) => {
                    std::println!(
                        "[test] Child unauthorized syscalls (SYS_ptrace, SYS_socket, UdpSocket::bind) were successfully blocked with EPERM by kernel seccomp BPF filter."
                    );
                    Ok(())
                }
                _ => Err(format!(
                    "Child did not exit cleanly after EPERM enforcement: {:?}",
                    status
                )),
            }
        }
        Err(e) => Err(format!("Fork failed: {}", e)),
    }
}
