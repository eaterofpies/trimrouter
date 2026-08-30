# TODO List

- Maybe switch upstream DNS queries to use a proper DNS client library instead of manual UDP packet forwarding
- Support TCP, DNSSEC, etc. in the DNS forwarder
- Add some basic observability and metrics
- Deduplicate dependencies
- Add service stopping notifications
- Panic doesn't stop routing / other services. Should it?