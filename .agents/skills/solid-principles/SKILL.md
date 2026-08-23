---
name: solid-principles
description: Guidelines, design patterns, anti-patterns, and review standards for applying SOLID software design principles in Rust codebases.
---

# SOLID Principles in Rust

This skill provides design standards, patterns, and checklists for designing and refactoring Rust code to adhere to the **SOLID** software design principles in this project.

---

## 1. Single Responsibility Principle (SRP)
> *"A module, struct, or function should have one, and only one, reason to change."*

### Guidelines
* **Separate Domain Logic from I/O & Transport**: Isolate protocol encoding/decoding, business rules, and state transitions from raw network sockets (`UdpSocket`, raw sockets) or file system operations.
* **Avoid "God" Orchestrators**: Break large initialization procedures or event loops (e.g., `run_init`) into dedicated stage coordinators (e.g., storage manager, firewall configurer, service supervisor).
* **Decompose Data Structures**: Ensure structs represent a cohesive domain entity. If a struct contains configuration state, socket handles, task handles, and metrics, break it into composable sub-structures.

### Rust Pattern
```rust
// ❌ Violates SRP: Mixes lease management with raw socket I/O and packet encoding
struct DhcpServer {
    raw_socket: RawFd,
    leases: HashMap<MacAddr, Ipv4Addr>,
}

// ✅ Adheres to SRP: Clear separation of responsibilities
struct LeaseTable {
    leases: HashMap<MacAddr, ClientLease>,
}

struct DhcpPacketCodec;

struct DhcpServerWorker {
    leases: LeaseTable,
    socket: RawSocketHandler,
}
```

---

## 2. Open / Closed Principle (OCP) & Closed-Ecosystem Type Safety
> *"Software entities should be open for extension, but closed for modification."*

### Closed-Ecosystem Standard: Type Safety via Closed Enums
In this embedded router / appliance codebase, **type safety, compile-time exhaustiveness, and zero-cost static dispatch are explicitly prioritized over open dynamic extension**.

* **Explicitly Allowed & Preferred: Service Enums**: Closed enum wrappers (such as `RouterService` and `WorkerService`) are the preferred architectural pattern.
* **Benefits of Closed Enums in Rust**:
  1. **Compile-Time Exhaustiveness**: The Rust compiler guarantees every match site handles all possible services; missing a service variant is caught at compile time rather than failing at runtime.
  2. **Zero-Cost Static Dispatch**: Avoids `Box<dyn Service>` heap allocations, pointer indirection, and runtime vtables.
  3. **Strong Serialization & CLI Typing**: Enums integrate seamlessly with `clap`, `serde`, and IPC serialization without requiring runtime type erasure or `Any` downcasting.
* **Adhering to SOLID with Enums**: Implement shared traits (such as `Service`) directly on the wrapper enum. Calling code (like `ManagedInterface`) interacts with the services uniformly through the trait interface, maintaining behavioral consistency while preserving closed-system type safety.

### Rust Pattern
```rust
// ✅ Preferred & Standard in this codebase: Closed Enum with Trait Implementation
pub enum RouterService {
    DhcpClient(DhcpClient),
    SntpClient(SntpClient),
    LanManager(LanManager),
}

// Uniform trait implementation over closed enum variants
impl Service for RouterService {
    async fn start(&mut self) -> Result<(), ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.start().await,
            RouterService::SntpClient(s) => s.start().await,
            RouterService::LanManager(s) => s.start().await,
        }
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.stop().await,
            RouterService::SntpClient(s) => s.stop().await,
            RouterService::LanManager(s) => s.stop().await,
        }
    }
}

pub struct ManagedInterface {
    pub name: String,
    pub active_services: Vec<RouterService>,
}
```

---

## 3. Liskov Substitution Principle (LSP)
> *"Functions that use pointers or references to base types (traits) must be able to use objects of derived types without knowing it."*

### Guidelines
* **Preserve Semantic Contracts**: Trait implementations must fulfill all contract invariants (e.g. `start()` must not return `Ok(())` if the service failed to initialize; `stop()` must be idempotent).
* **Avoid Unimplemented / Panicking Stubs**: Never implement a trait by using `todo!()`, `unimplemented!()`, or returning dummy errors for methods that do not apply to that subtype. If a method does not apply, the trait is violating ISP.
* **Symmetrical Mocking**: Ensure mock implementations (`MockSystem`, `MockSocket`) behave consistently with production implementations regarding error codes, EOF states, and lifecycle transitions.

---

## 4. Interface Segregation Principle (ISP)
> *"Clients should not be forced to depend upon interfaces/traits they do not use."*

### Guidelines
* **Role Traits over Header Traits**: Prefer small, focused traits (1–3 methods) representing specific capabilities rather than broad monolithic traits.
* **Compose Traits with Supertraits**: Compose fine-grained traits together when a combined capability is needed instead of bundling everything into one giant interface.

### Rust Pattern
```rust
// ❌ Violates ISP: A process reaper is forced to depend on disk mounting & power management
pub trait System {
    fn mount(&self, src: &str, target: &str) -> Result<()>;
    fn reap_children(&self) -> Result<Vec<Pid>>;
    fn reboot(&self) -> Result<()>;
}

// ✅ Adheres to ISP: Segregated into single-purpose role traits
pub trait MountOps {
    fn mount(&self, src: &str, target: &str) -> Result<()>;
    fn umount(&self, target: &str) -> Result<()>;
}

pub trait ProcessOps {
    fn reap_children(&self) -> Result<Vec<Pid>>;
    fn send_signal(&self, pid: Pid, sig: Signal) -> Result<()>;
}

pub trait PowerOps {
    fn reboot(&self) -> Result<()>;
    fn poweroff(&self) -> Result<()>;
}
```

---

## 5. Dependency Inversion Principle (DIP)
> *"High-level modules should not depend on low-level details. Both should depend on abstractions."*

### Guidelines
* **Inject Dependencies**: Pass dependencies (network clients, file accessors, timers, clocks) into constructors (`new(...)`) as trait objects or generic parameters (`impl Trait`) rather than instantiating concrete types internally.
* **Abstract System and I/O Boundaries**: Decouple business logic from kernel APIs (Netlink, libc, sysfs) by introducing abstraction traits so domain logic can be tested hermetically without elevated root privileges or hardware.

### Rust Pattern
```rust
// ❌ Violates DIP: Directly constructs concrete dependency and calls Netlink/system directly
pub struct LanManager {
    dhcp_server: DhcpServer, // Concrete instantiation inside LanManager
}

// ✅ Adheres to DIP: Injects abstract service dependency
pub struct LanManager<S: Service, N: NetworkConfigurator> {
    dhcp_service: S,
    network: N,
}
```

---

## SOLID Review Checklist

When authoring or reviewing code in this codebase, check:
1. [ ] **SRP**: Does each struct and module have only one clear responsibility?
2. [ ] **OCP / Type Safety**: Are closed ecosystems modeled with exhaustive enums (`RouterService`, `WorkerService`) that implement common traits (`Service`) for uniform handling?
3. [ ] **LSP**: Do all trait implementations fulfill the complete contract without panics, stubs, or unexpected side-effects?
4. [ ] **ISP**: Are traits focused and small? Can a caller depend only on the specific subset of functionality it needs?
5. [ ] **DIP**: Are external I/O, system calls, and child services injected as traits/abstractions rather than hardcoded concrete types?
