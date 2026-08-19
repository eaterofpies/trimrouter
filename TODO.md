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
- Switch to a UEFI boot process on x86 and x86 tests
- Include all storage kernel modules in the initrd as it doesn't work on real hardware
- Copy all kernel modules to an EROFS image and copy that to the boot partition. Mount the EROFS image as soon as /boot has been mounted.