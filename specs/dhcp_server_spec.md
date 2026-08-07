# Specification: LAN DHCP Server

The DHCP Server is an embedded service in `trimrouter` responsible for dynamically allocating and managing IPv4 addresses for local clients on the LAN interface.

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
2.  If no lease exists, calls `next_available_ip()` to find the first unused host IP in the LAN subnet (excluding the server's own gateway IP).
3.  Returns a `DHCPOFFER` to the client.

### 3.2 REQUEST Processing
1.  **Request Type Validation**: Inspects the requested IP address and the Server Identifier (Option 54).
2.  **Conflict Validation**:
    *   Verifies the requested IP is within the LAN subnet scope.
    *   Verifies the requested IP does not conflict with the server's own gateway IP address.
    *   Verifies the requested IP is not already leased to another client MAC.
3.  **Conflict Response**: If any validation check fails, the server responds with a `DHCPNAK` to force the client to restart the negotiation.
4.  **Successful Lease**: If valid, the server inserts/updates the lease in the `LeaseTable` (applying a default duration of 3600 seconds), and returns a `DHCPACK`.

---

## 4. Advertising Configuration Options

Every successful `DHCPOFFER` and `DHCPACK` includes the following configuration options configured for the LAN:
*   **Subnet Mask** (Option 1): The subnet mask of the LAN interface.
*   **Router / Default Gateway** (Option 3): The gateway IP (set to the LAN interface's IP, e.g., `192.168.1.1`).
*   **DNS Server** (Option 6): Advertises the server's own LAN IP, since `trimrouter` runs an embedded DNS forwarder on port 53.
*   **IP Address Lease Time** (Option 51): Configured to 3600 seconds (`LAN_LEASE_SECS`).
*   **Server Identifier** (Option 54): Set to the LAN interface's IP.
