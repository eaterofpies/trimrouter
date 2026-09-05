# TODO List

- DNS query rate limiting and flood defense (per-client token-bucket rate limiting)
- Inbound TCP listener on port 53 for LAN DNS queries (RFC 7766)
- EDNS0 buffer sizing and truncation (TC=1 flag) handling in DNS forwarder
- Upstream DNS query deduplication and in-flight request joining
- Upstream TCP fallback and secondary resolver failover in DNS forwarder
- DNS-over-TLS (DoT) upstream resolution (port 853 with embedded CA trust roots)
- DNS-over-HTTPS (DoH) upstream resolution (RFC 8484 over HTTP/2)
- Inbound port forwarding (DNAT rules in trimrouter.toml)
- Add basic observability and system metrics reporting
- IPv6 SLAAC & Router Advertisements (RAs)