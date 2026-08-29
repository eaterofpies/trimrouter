# TODO List

- Maybe switch upstream DNS queries to use a proper DNS client library instead of manual UDP packet forwarding
- Support TCP, DNSSEC, etc. in the DNS forwarder
- Add some basic observability and metrics
- Deduplicate dependencies
- Add service stopping notifications
- Panic doesn't stop routing / other services. Should it?
- Remove compressed module loading support if the kernel can do it
- Revisit Seccomp-BPF filters to establish per-service fine-grained allowed syscall lists, and pass pre-bound SNTP sockets from the parent to completely remove socket/bind/connect calls from workers