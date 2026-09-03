# Changelog

## [0.2.0](https://github.com/eaterofpies/trimrouter/compare/v0.1.0...v0.2.0) (2026-09-03)


### Features

* **dns:** implement RFC 2308 negative DNS caching with security guards ([5ba1f0d](https://github.com/eaterofpies/trimrouter/commit/5ba1f0d0dc0fd8708a5969f33a59c74f2bf604e1))
* implement local lan dns and dhcp option 12 hostname resolution ([e31e200](https://github.com/eaterofpies/trimrouter/commit/e31e200a154e71134878a554beeab18c2b6d766b))
* implement static DHCP lease reservations with startup synchronization ([861f7a0](https://github.com/eaterofpies/trimrouter/commit/861f7a0b8616137dca2b3d69a028d8ad81fc8c64))
* **init:** configure bounded tmpfs quotas and security flags for /run and /tmp ([39aad07](https://github.com/eaterofpies/trimrouter/commit/39aad07b3b5405d04bcb65939123554a61c2c86c))
* **init:** graceful filesystem sync on poweroff and panic teardown ([d81d2ed](https://github.com/eaterofpies/trimrouter/commit/d81d2ed64e5d32d8cd6ad8c2de2a88f4b712758e))
* **interface:** add periodic carrier polling and synchronize interface spec ([7cece2d](https://github.com/eaterofpies/trimrouter/commit/7cece2dbdf905d7c4100c4b5c3945751f5155e84))
* support custom upstream dns resolvers via trimrouter.toml ([e1fb713](https://github.com/eaterofpies/trimrouter/commit/e1fb713c948d8758c5edeebf12d18c4ab128ce5c))
* **watchdog:** implement hardware watchdog supervision and service heartbeats ([c8ebe19](https://github.com/eaterofpies/trimrouter/commit/c8ebe19e1c3dcbdfa7813c483d784d9fc0aa3dd3))

## 0.1.0 (2026-08-29)


### Features

* add commit-helper and rust-guidelines agent skills ([3a5cb1e](https://github.com/eaterofpies/trimrouter/commit/3a5cb1e5704fcf51313f9f9cea76c1d786250f13))
* add LAN manager service for reactive LAN/WAN subnet conflict resolution ([d4dd315](https://github.com/eaterofpies/trimrouter/commit/d4dd315b90280a60e7e174bee665e79ee431ac04))
* add TRIMROUTER_CONFIG override variable and test isolation ([c018609](https://github.com/eaterofpies/trimrouter/commit/c0186098dc2a4eb3251d2f845ccb79ede5b24e4b))
* boot QEMU from VM disk images for all architectures and unify Makefile targets ([bbdd460](https://github.com/eaterofpies/trimrouter/commit/bbdd46044593d1d6114329e46e63143ea60c898e))
* configure display console for hardware and serial console for test harness ([9a6548c](https://github.com/eaterofpies/trimrouter/commit/9a6548c224b932a245a10ab0d9dcbd554ef54ce6))
* **dhcp-server:** add background periodic lease eviction timer ([ff846f6](https://github.com/eaterofpies/trimrouter/commit/ff846f66c77232b3bbd0757e16ea499f5336c28f))
* **dns-forwarder:** add bounded cache eviction and sequential multi-upstream fallback ([e6cb05c](https://github.com/eaterofpies/trimrouter/commit/e6cb05c4ccddf0ba7df2dd1ba601a3b3e82243d1))
* implement caching DNS forwarder service using dns-parser library and background TTL cleanup ([717670c](https://github.com/eaterofpies/trimrouter/commit/717670c1a37f1e34087ca4079ae14fede228f537))
* implement dynamic interface lifecycle controller and dependency injection ([57bff64](https://github.com/eaterofpies/trimrouter/commit/57bff64f016c2deef1ded7d7225e81bd55842569))
* implement generic LAN DHCP server lease management, anti-spoofing checks, and decline/release handling ([4bd1dc6](https://github.com/eaterofpies/trimrouter/commit/4bd1dc6f11f1363a881a870050bfd26adec3230d))
* implement kernel-initiated lazy module loading and extract kmod module ([cd417f0](https://github.com/eaterofpies/trimrouter/commit/cd417f0bcd02a27695d14c856b564b10f6ecba5e))
* implement loopback, lan, and wan network configuration ([a78ebba](https://github.com/eaterofpies/trimrouter/commit/a78ebbae7425103a3f96f3e34111c3649ec1e962))
* implement netfilter module loading and masquerade rules with secure failover reboot ([6976859](https://github.com/eaterofpies/trimrouter/commit/6976859b0c584339ab87e2d715ed105d0a8c4b2a))
* implement parameterized architecture builds, dynamic test emulation sandboxing, and deprecation fixes ([0b97f1a](https://github.com/eaterofpies/trimrouter/commit/0b97f1a474a5ced9bcc4178c15bb0c3ed4a42100))
* implement partition layout spec with fatfs formatting and label scanning ([fc9c425](https://github.com/eaterofpies/trimrouter/commit/fc9c425f4020054481ac4845d1f7826c85ad4517))
* implement privilege separation for DNS Forwarder ([ef593b0](https://github.com/eaterofpies/trimrouter/commit/ef593b077435919813ed3de8b8e759c7c154d73f))
* implement privilege separation for LAN DHCP Server and deduplicate code ([a49347f](https://github.com/eaterofpies/trimrouter/commit/a49347fea89a517c9eee1979e239d48ba3be9066))
* implement privilege separation for SNTP Client and split parent-to-worker IPC messages ([b5a078f](https://github.com/eaterofpies/trimrouter/commit/b5a078f17dceb67b7d9bea8da93c1694f7b61500))
* implement privilege separation proof-of-concept for DHCP Client ([6bf2e72](https://github.com/eaterofpies/trimrouter/commit/6bf2e726af50efed2d1d9a92bb878e2f78fe362d))
* implement raw packet builder using pnet size constants with borrow checker comments ([6a5ee0e](https://github.com/eaterofpies/trimrouter/commit/6a5ee0e772920255f1274e44b22696fee8864594))
* implement safe uevent hardware discovery and hotplug watchdogs for WAN and LAN ([789e611](https://github.com/eaterofpies/trimrouter/commit/789e611e27aa10712c19778655ab0b01959c8cfa))
* implement UEFI boot and delayed coldplug module discovery with alias caching ([98babf0](https://github.com/eaterofpies/trimrouter/commit/98babf0d6018fc5e070cd1044b644a79732482a7))
* implement unique isolated user IDs for each sandboxed service worker ([879e797](https://github.com/eaterofpies/trimrouter/commit/879e797bf70138e847044aeba4ffb5d591e68fc0))
* implement WAN DHCP client using standard port constants ([983a1a6](https://github.com/eaterofpies/trimrouter/commit/983a1a655d5f02573cf6ff8c5cd20923d4523915))
* **init:** log git commit sha and build timestamp on startup ([78785e9](https://github.com/eaterofpies/trimrouter/commit/78785e9112c45730802723dbefa7f5f40b069147))
* **kmod:** Add usb NIC drivers kmod dependency resolution, ([4e95a5e](https://github.com/eaterofpies/trimrouter/commit/4e95a5e89f9afdd05ec0028f54e9e3e711e38df1))
* log link speed and state changes in interface monitor ([cd5e25d](https://github.com/eaterofpies/trimrouter/commit/cd5e25da19603218b880114b0a1e415053f2c2be))
* **logging:** add ISO 8601 timestamps to all logs and factor out get_timestamp_prefix ([3575fb1](https://github.com/eaterofpies/trimrouter/commit/3575fb126f2c348a256f1ab61f54b2f5fe8ff18e))
* **logging:** implement logging subsystem with rotation, VM writeback tuning, and QEMU test verification ([2dd55ff](https://github.com/eaterofpies/trimrouter/commit/2dd55ff42482c40ef3b6825b17bcec1bae6e68cc))
* **logging:** integrate log crate with contextual severity levels and level filtering ([482da19](https://github.com/eaterofpies/trimrouter/commit/482da1958bf3ca270e7b1fc327be9dce287ed821))
* migrate configuration to toml format read from boot partition ([10bee9b](https://github.com/eaterofpies/trimrouter/commit/10bee9b9a4fba1e1ff4d871d465482cdeace1c56))
* mount boot partition read-only on startup ([e28482d](https://github.com/eaterofpies/trimrouter/commit/e28482d6de4f4116621fcca0fbbab2471bc92038))
* **sntp:** implement SNTP client with 60s initial retry, loopback routing, and rsntp integration ([97b9b14](https://github.com/eaterofpies/trimrouter/commit/97b9b146a882813572a79cddec6a257af5ee41fd))
* support unified 32/64-bit rpi image and dynamic module resolution ([c71c772](https://github.com/eaterofpies/trimrouter/commit/c71c7722517ba6b50dcc9cd60261aa588d36aa05))
* switch to generic kernel and implement dynamic hardware module discovery ([c687c77](https://github.com/eaterofpies/trimrouter/commit/c687c77febf04bb713661a455dd2956346a87c70))
* **system:** support compressed kernel modules (.xz, .gz, .zst) loaded via memory buffer ([2edbc53](https://github.com/eaterofpies/trimrouter/commit/2edbc536d5a5c480754b59e46226b30883ee9350))
* upgrade to Debian 13 Trixie kernel and support dynamic module discovery ([febc605](https://github.com/eaterofpies/trimrouter/commit/febc6054c2808707969d75a6fa1a8cd70a0021f2))


### Bug Fixes

* **build:** set boot flag instead of esp flag on x86_64 boot partition ([0f52fce](https://github.com/eaterofpies/trimrouter/commit/0f52fcee14bf9a101ba51aa1faa9dad7a50d0313))
* **config:** add MAC & CIDR validation, early logging registration, and panic sync ([0035217](https://github.com/eaterofpies/trimrouter/commit/0035217065c796b586e2170a21a0b24c08f32a50))
* **dhcp-client:** add CVE test suite, off-subnet gateway validation, and RFC 2131 renewal intervals ([ad7e4b0](https://github.com/eaterofpies/trimrouter/commit/ad7e4b0606928cf0b6e72785c6f9a7a15937c7c8))
* **dhcp-server:** add CVE test suite, independent conflict holds, and Option 54 filtering ([9aece68](https://github.com/eaterofpies/trimrouter/commit/9aece68a0875fd40c08354cc4be6e36293276d83))
* **dhcp-server:** log socket read error before recreating socket ([371401f](https://github.com/eaterofpies/trimrouter/commit/371401f80097693c25da1c9fe596b5dee36ecc19))
* **dhcp-server:** safely parse netlink MAC address bytes and propagate IPC errors ([1943055](https://github.com/eaterofpies/trimrouter/commit/1943055cff391059fc71a5a2bb7f201d9d2bede6))
* **dhcp-server:** true LeaseTable privacy, typed ServerError, expired lease eviction, deduplicate test helper ([f5d6d85](https://github.com/eaterofpies/trimrouter/commit/f5d6d85378bf40de0dc6d2f10cb6cc487d136096))
* **dhcp-server:** use host iterator to safely log dynamic lease pool without overflow risk ([d30dbe8](https://github.com/eaterofpies/trimrouter/commit/d30dbe84d1b4638ca988a976d840a2b52b9079be))
* **dhcp-server:** use safe mac_from_slice instead of unwrap in neighbor parsing ([3c48948](https://github.com/eaterofpies/trimrouter/commit/3c4894819637c0b824892426ef420d724eeb7b9d))
* **dns-forwarder:** add CVE test suite, port verification, and RFC 2181 TTL semantics ([45ce8ca](https://github.com/eaterofpies/trimrouter/commit/45ce8ca80b5c0a98736e88aedfdb591bbdddee71))
* **dns-forwarder:** reuse single upstream socket for queries and cap maximum pending requests to avoid infinite loops ([b5aa3ca](https://github.com/eaterofpies/trimrouter/commit/b5aa3ca4e4d2a0b57bf7fe1183acf197cc56d1b4))
* **error-handling:** add logging to unhandled I/O operations and avoid silent error discard ([75beb9a](https://github.com/eaterofpies/trimrouter/commit/75beb9aea25cccd4662f43591a45f44cd930ee32))
* **firewall:** add invalid conntrack drop rule and interface name validation ([4d1749b](https://github.com/eaterofpies/trimrouter/commit/4d1749bb11e5b7b99a63ab45cc57635a23bb2406))
* force 0.0.0.0 source IP for WAN DHCP client using raw packet socket ([da62beb](https://github.com/eaterofpies/trimrouter/commit/da62bebed810bc37593b7afe0b29c9be8dcbac8c))
* format log Option values cleanly and update TODO / rust-guidelines ([a53c61c](https://github.com/eaterofpies/trimrouter/commit/a53c61c7572e59ed479f5e4cad6cea9ca881766c))
* **init:** dynamically discover input event devices for ACPI power button ([c8a9889](https://github.com/eaterofpies/trimrouter/commit/c8a9889df87c080d5f52973b99b45cb1728e7f11))
* **init:** handle signal binding and chroot jail errors gracefully without expect ([1f700a9](https://github.com/eaterofpies/trimrouter/commit/1f700a938e7449ed8960334e8c1a2d7e7f628c62))
* **ipc:** add message length limits and overflow-safe supervisor restart backoff ([4d4a456](https://github.com/eaterofpies/trimrouter/commit/4d4a456b5bb8ef13e3afec70bba0644f12fb4e94))
* **kmod:** add non-recursive wildcard matching, recursion depth bounds, and path sanitization ([95c57ae](https://github.com/eaterofpies/trimrouter/commit/95c57ae0f7d0d8c7505cfce6b8957807b42b473a))
* **kmod:** replace CString new unwrap with safe default ([5c28b15](https://github.com/eaterofpies/trimrouter/commit/5c28b155f2ee2b58371aa28232b7556dedf78cfe))
* **lan-manager:** add prefix length bounds and backup collision safety checks ([9da12f7](https://github.com/eaterofpies/trimrouter/commit/9da12f7644fafd3d64d010135698c12cfad26743))
* **lint:** suppress unused_imports warnings in unit test modules under integration test context ([225efb3](https://github.com/eaterofpies/trimrouter/commit/225efb3c2465758426a2f53fb4c029eadd411c6e))
* **logging:** add symlink unlinking on open, rotation, and space reclamation ([9f5bbc1](https://github.com/eaterofpies/trimrouter/commit/9f5bbc1bc1f672fb05add1115fbb58fceb667857))
* **netfilter:** correct conntrack endianness and rewrite integration test using UNIX stream sockets ([e7cd959](https://github.com/eaterofpies/trimrouter/commit/e7cd9595f1a2f5a43e3a5734309223783500402c))
* **packet:** add MAX_RAW_PACKET_PAYLOAD bound and return Result on build error ([a5c1018](https://github.com/eaterofpies/trimrouter/commit/a5c1018e9c047be416d3ac03561255c3e6d63af4))
* **power:** consolidate ACPI power monitor, ensure log sync on shutdown, and add power key event tests ([6d50828](https://github.com/eaterofpies/trimrouter/commit/6d5082811fa01b0daffcfc3ae6c99447014b54f5))
* **sntp:** add CVE test suite, epoch bounds validation, and server IP filtering ([6dcaf0f](https://github.com/eaterofpies/trimrouter/commit/6dcaf0f0bcaa7de717ceafe8fa0e800495fc21df))
* **storage:** add MBR sector overflow protection and consolidate partition 2 device name derivation ([9bdd698](https://github.com/eaterofpies/trimrouter/commit/9bdd69810a5cf85b2450697b4c57c2bbe1656086))
* **supervisor:** add cooperative sleep and suppress benign ESRCH in terminate_worker ([ceca877](https://github.com/eaterofpies/trimrouter/commit/ceca877151508fad2ea85d2fa36f141abaf44434))
* **supervisor:** reset restart backoff attempt counter after sustained uptime ([de90f05](https://github.com/eaterofpies/trimrouter/commit/de90f05df5680b7688ec7c6d5135cc991376cca0))


### Performance Improvements

* **build:** add test-fast profile with parallel codegen and skip lto for fast test builds ([266a75c](https://github.com/eaterofpies/trimrouter/commit/266a75c2d8694830fd31c266c50137d6c4786255))
