# Specification: LAN DHCP Server

The DHCP Server is an embedded service in `trimrouter` responsible for dynamically allocating and managing IPv4 addresses for local clients on the LAN interface.

> [!NOTE]
> **Status: Implemented.**

---

## 1. Socket and Routing Mechanics

During the initial phase of connection, a client does not possess an IP address and therefore cannot resolve ARP queries. Consequently, standard UDP sockets cannot be used to respond to the client.

*   **Socket Type**: A raw packet socket (`AF_PACKET`) bound directly to the LAN interface.
*   **Userspace Broadcast/Unicast**: The server reads raw packets and parses them in userspace. It unicasts replies directly to the client's destination hardware MAC address at the Ethernet layer, bypassing the kernel ARP table.
*   **Ports**: Listens for client messages on UDP port `67` and responds to client port `68`.

---

## 2. Atomicity & Lease Table Management

To ensure reliability, the DHCP server maintains an in-memory database of active leases (`LeaseTable`) using a strict encapsulation pattern to guarantee the lease mapping and the active allocation index never diverge:

*   **Data Structures**:
    *   `by_mac`: A hash map mapping client `MacAddr` to `ClientLease` (containing the assigned `Ipv4Addr` and expiration `Instant`).
    *   `allocated_ips`: A hash set containing currently leased IP addresses for O(1) lookup.
*   **Atomicity Guarantees**:
    *   An IP is in `allocated_ips` if and only if there is a corresponding active lease in `by_mac`.
    *   Every insertion, replacement, or removal operation modifies both the mapping and the set index inside a single atomic operation within the `LeaseTable` module boundaries.
*   **Eviction**:
    *   Expired leases are automatically evicted from the database during new lease allocation queries to reclaim expired addresses.

---

## 3. DHCP Request Handling & Validation

When the server receives a message from a client, it processes it according to the DHCP state transitions:

### 3.1 DISCOVER Processing
1.  Filters and checks if the client MAC already has an active lease. If yes, offers that IP address.
2.  If no lease exists, calls `next_available_ip()` to find a candidate host IP in the LAN subnet (excluding the server's own gateway IP).
3.  **Active Verification**: Performs active verification using kernel-assisted ARP probing by sending a dummy UDP packet to target the IP and sleeping for 100ms.
    *   **Dynamic Netlink Watcher**: A long-running background task subscribes to the kernel's `MulticastGroup::Neigh` Netlink group. It reactively parses neighbor (`NewNeighbour`) events to register IP/MAC mappings directly into the shared lease table.
    *   If a conflict is detected (the IP is resolved under a different MAC in the lease table), the candidate IP is marked as temporarily reserved (5-minute hold), and the search continues for the next available IP.
    *   If no conflict is detected, the IP is offered.
4.  Returns a `DHCPOFFER` to the client.

### 3.2 REQUEST Processing
1.  **Request Type Validation**: Inspects the requested IP address and the Server Identifier (Option 54).
2.  **Conflict Validation**:
    *   Verifies the requested IP is within the LAN subnet scope.
    *   Verifies the requested IP does not conflict with the server's own gateway IP address.
    *   Verifies the requested IP is not already leased to another client MAC.
    *   **Active Verification**: Triggers an active kernel-assisted ARP probe (sending a dummy UDP packet and sleeping for 100ms). If the background Netlink watcher resolves a different MAC address for this IP, a conflict is registered.
3.  **Conflict Response**: If any validation check or active Netlink/ARP verification fails, the server responds with a `DHCPNAK` to force the client to restart the negotiation.
4.  **Successful Lease**: If valid, the server inserts/updates the lease in the `LeaseTable` (applying a default duration of 3600 seconds), and returns a `DHCPACK`.

---

## 4. Advertising Configuration Options

Every successful `DHCPOFFER` and `DHCPACK` includes the following configuration options configured for the LAN:
*   **Subnet Mask** (Option 1): The subnet mask of the LAN interface.
*   **Router / Default Gateway** (Option 3): The gateway IP (set to the LAN interface's IP, e.g., `192.168.1.1`).
*   **DNS Server** (Option 6): Advertises the server's own LAN IP, since `trimrouter` runs an embedded DNS forwarder on port 53.
*   **IP Address Lease Time** (Option 51): Configured to 3600 seconds (`LAN_LEASE_SECS`).
*   **Server Identifier** (Option 54): Set to the LAN interface's IP.

---

## 5. LAN Manager Service & Dynamic Subnet Reconfiguration

The `LanManager` service manages the LAN interface configuration and encapsulates self-healing conflict resolution. It runs the DHCP Server as a child service and reacts to Netlink address and link events:
1.  **Conflict Detection**: If a conflict/overlap between the WAN subnet and the active LAN subnet is detected, the `LanManager` initiates a dynamic subnet shift.
2.  **Child DHCP Server Teardown**: The child DHCP Server service is stopped and its active tasks are terminated.
3.  **Address Cleanup**: The active IPv4 address configurations on the LAN interface are deleted/flushed to ensure clean reinitialization. The interface state (UP/DOWN link state) is left untouched.
4.  **Reconfiguration**: The LAN interface is configured with the backup IP address specified by the `backup_lan_ip` (e.g. `10.0.0.1/24`).
5.  **Child DHCP Server Restart**: The child DHCP Server is re-instantiated with the new LAN IP/subnet range and restarted. The active lease table is cleared, forcing existing clients to re-negotiate leases within the updated range (e.g. `10.0.0.2` to `10.0.0.254`).

