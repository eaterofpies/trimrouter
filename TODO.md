# TODO List

- Maybe switch upstream DNS queries to use a proper DNS client library instead of manual UDP packet forwarding
- Support TCP, DNSSEC, etc. in the DNS forwarder
- Add some basic observability and metrics
- Panic doesn't stop routing / other services. Should it?
- Static DHCP lease reservations via trimrouter.toml
- Inbound port forwarding (DNAT rules in trimrouter.toml)
- IPv6 SLAAC & Router Advertisements (RAs)
- DNS query rate limiting / flooding protection
- DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH) upstream resolution