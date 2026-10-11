# Specification: WAN DHCP Client

The DHCP Client is an embedded service in `trimrouter` responsible for negotiating IPv4 network configuration dynamically with an upstream DHCP server on the WAN interface.

> [!NOTE]
> **Status: Implemented.**

---

## 1. Socket and Packet Mechanics

Because the WAN interface does not have an IP address assigned during initial configuration, the DHCP client cannot use standard UDP socket abstractions (`std::net::UdpSocket`). Instead, it communicates with the network hardware link layer via the privileged parent process:

*   **Parent Raw Socket & Kernel Filtering**: A raw packet socket (`AF_PACKET` / `SOCK_RAW`) bound directly to the WAN interface is owned, polled, and managed exclusively by the privileged parent process. The socket is opened with protocol `ETH_P_IP` and configured with a Classic BPF filter (compiled via `pktbaffle` and attached via `SO_ATTACH_FILTER`) targeting destination UDP port 68, discarding non-DHCP transit traffic in the kernel before userspace copy.
*   **Inbound Routing & Full Userspace Decode**: The parent routes incoming raw Layer-2 frames to the unprivileged DHCP client worker over a private Unix SEQPACKET IPC channel (`RawPacket`). The worker performs the full packet decode in userspace:
    *   **Ethernet Header**: Extracts source and destination MACs; validates frame types.
    *   **IPv4 & UDP Headers**: Extracts source and destination IPs and ports; validates UDP ports 67/68.
    *   **DHCP Payload & Response Filtering**: Decodes the DHCP message and options, matching against the client MAC address and active transaction ID (`xid`) to filter out unrelated WAN traffic.
*   **Constrained Outbound Requests & Parent Encoding**: The unprivileged worker does not construct or emit raw packet bytes. Instead, it sends strongly typed semantic domain requests over IPC (`SendDiscover`, `SendRequest`). The privileged parent performs the full packet encoding and transmission:
    *   **DHCP Message Construction**: Builds the DHCP payload including required options (Parameter Request List, Requested IP, Server Identifier).
    *   **UDP Header**: Encapsulates source port 68 (DHCP client) and destination port 67 (DHCP server).
    *   **IPv4 Header**: Sets source IP to `0.0.0.0` (or currently leased IP during unicast renewal) and destination IP to `255.255.255.255` (or unicast server IP during renewal).
    *   **Ethernet Header**: Sets source MAC to the WAN interface hardware address and destination MAC to broadcast (`FF:FF:FF:FF:FF:FF`) or server unicast MAC.
    *   **Checksum & Transmit**: Computes IP and UDP checksums and writes the frame directly to the WAN raw packet socket.

---

## 2. State & Phase Transitions

The DHCP client transitions through a standard RFC 2131 state machine:

```mermaid
stateDiagram-v2
    [*] --> DISCOVER : Start / Socket Bind
    DISCOVER --> REQUEST : DHCPOFFER received
    REQUEST --> BOUND : DHCPACK received
    REQUEST --> DISCOVER : DHCPNAK / Timeout
    BOUND --> RENEWING : T1 Timer Expiry (50% Lease)
    RENEWING --> BOUND : DHCPACK received (Unicast)
    RENEWING --> REBINDING : T2 Timer Expiry (87.5% Lease)
    REBINDING --> BOUND : DHCPACK received (Broadcast)
    REBINDING --> DISCOVER : Lease Expiry / DHCPNAK
```

### 2.1 DISCOVER Phase
*   Generates a random 32-bit transaction ID (`xid`).
*   Broadcasts a `DHCPDISCOVER` packet on the WAN interface.
*   Listens for a matching `DHCPOFFER` response.
*   If no offer is received within the timeout, retries with exponential backoff starting at 4 seconds up to a maximum of 64 seconds.

### 2.2 REQUEST Phase
*   Broadcasts a `DHCPREQUEST` packet containing:
    *   The requested IP address (from the selected `DHCPOFFER`).
    *   The Server Identifier (Option 54) pointing to the offering DHCP server.
*   Listens for a matching `DHCPACK` or `DHCPNAK`.
*   If `DHCPACK` is received, extracts network parameters and transitions to **BOUND**.
*   If `DHCPNAK` is received or the phase times out, restarts to **DISCOVER**.

### 2.3 BOUND Phase
*   Applies the configuration parameters to the WAN interface using `NETLINK_ROUTE`:
    *   Assigns the leased IP address and subnet mask.
    *   Sets up the default gateway route.
*   Writes the lease details (IP, gateway, DNS servers) to the thread-safe `WanLease` shared state.
*   Triggers the lease renewal timer based on the lease duration:
    *   **T1 (Renewal)**: `lease_secs / 2`
    *   **T2 (Rebinding)**: `lease_secs * 0.875`
*   If the lease expires without renewal, calls `deconfigure()` to clear the IP and routes, resets the shared `WanLease`, and returns to **DISCOVER**.

### 2.4 RENEWING State
*   Upon T1 expiry, sends a unicast `DHCPREQUEST` directly to the DHCP server's IP address.
*   If a `DHCPACK` is received, updates the lease timers, reapplies config if changed, and returns to **BOUND**.
*   If no response is received, continues unicast retries until T2 is reached.

### 2.5 REBINDING State
*   Upon T2 expiry, broadcasts a `DHCPREQUEST` to `255.255.255.255`.
*   If a `DHCPACK` is received, updates lease timers, reapplies config, and returns to **BOUND**.
*   If the lease fully expires without an ACK, or if a `DHCPNAK` is received, immediately tears down the interface IP and routes via `deconfigure()` and restarts at **DISCOVER**.

---

## 3. Configuration Parameters & Options

The client requests and parses the following standard DHCP options:
*   **Subnet Mask** (Option 1): Used to compute the local subnet boundary.
*   **Router / Default Gateway** (Option 3): The gateway IP to route all external traffic.
*   **DNS Servers** (Option 6): List of upstream DNS resolver IPs.
*   **IP Address Lease Time** (Option 51): Duration of the lease in seconds.
*   **DHCP Message Type** (Option 53): Identifies the packet type (Discover, Offer, Request, Ack, Nak).
*   **Server Identifier** (Option 54): Server IP address to target for renewals and requests.

---

## 4. Failure Recovery & Robustness

*   **Socket Reinitialization**: If the raw socket encounters persistent read/write errors, the parent supervisor tears down the socket, waits 5 seconds (`SOCKET_RESTART_DELAY_SECS`), and rebinds a new socket on the WAN interface.
*   **Off-Subnet Gateway Protection**: Validates that any offered gateway IP is non-zero, non-broadcast, and contained within the leased subnet before configuring netlink default routes.
*   **RFC 2131 Renewal Scaling**: Retransmission intervals during renewal and rebinding wait half the remaining time down to 60s for standard leases (`(remaining / 2).max(60)`), and scale dynamically for sub-minute leases (`(remaining / 2).max(1)`).
*   **Unrecoverable Lease Expiry**: To prevent routing blackholes, if the lease expires during rebinding, the client immediately deletes the IP address and the default gateway route from the WAN interface before restarting discovery.
*   **LAN/WAN Subnet Overlap Handling**: Subnet conflicts and overlaps between WAN and LAN subnets are managed reactively by the dedicated LAN Manager service.


