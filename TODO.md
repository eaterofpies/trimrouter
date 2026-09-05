# TODO List

- Inbound TCP listener on port 53 for LAN DNS queries (RFC 7766)
- Upstream DNS query deduplication and in-flight request joining
- Upstream TCP fallback and secondary resolver failover in DNS forwarder
- DNS-over-TLS (DoT) upstream resolution (port 853 with embedded CA trust roots)
- DNS-over-HTTPS (DoH) upstream resolution (RFC 8484 over HTTP/2)
- Inbound port forwarding (DNAT rules in trimrouter.toml)
- Add basic observability and system metrics reporting
- IPv6 SLAAC & Router Advertisements (RAs)