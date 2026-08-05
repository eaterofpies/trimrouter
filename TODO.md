# TODO List

- Move tests inside the guest image to run them directly instead of observing from the outside
- Set up `/etc/resolv.conf` in the guest so we can make standard DNS library calls for local requests
- Maybe switch upstream DNS queries to use a proper DNS client library instead of manual UDP packet forwarding
- Support TCP, DNSSEC, etc. in the DNS forwarder
- Add some basic observability and metrics
- Clean up logging (maybe add a structured logging library like `tracing`)
- Show ethernet link speed changes in the logs
- Clean up option logs so they print clean values instead of `Some(...)`
- Add logging to file + file rotation
- Deduplicate dependencies
- LAN/WAN IP conflict resolution
- Add service stopping notifications
- Panic doesn't stop routing / other services. Should it?
- Service privilege separation