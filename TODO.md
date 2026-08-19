# TODO List

- Move tests inside the guest image to run them directly instead of observing from the outside
- Set up `/etc/resolv.conf` in the guest so we can make standard DNS library calls for local requests
- Maybe switch upstream DNS queries to use a proper DNS client library instead of manual UDP packet forwarding
- Support TCP, DNSSEC, etc. in the DNS forwarder
- Add some basic observability and metrics
- Clean up logging (maybe add a structured logging library like `tracing`)
- Add logging to file + file rotation
- Deduplicate dependencies
- Add service stopping notifications
- Panic doesn't stop routing / other services. Should it?
- Remove compressed module loading support if the kernel can do it
- Revisit Seccomp-BPF filters to establish per-service fine-grained allowed syscall lists, and pass pre-bound SNTP sockets from the parent to completely remove socket/bind/connect calls from workers