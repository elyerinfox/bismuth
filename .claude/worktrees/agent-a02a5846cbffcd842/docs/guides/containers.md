# Running workloads as containers

This guide packages a sensor workload as a sandboxed container, validates it at compile
time, and installs, starts, monitors and restarts it. The code below was compiled and
run against the current kernel. For the concepts and the full list of limitations, read
the [containers design page](../design/containers.md).

Requirements:

- the `containers` feature (on by default);
- the `crypto` feature, if the workload needs `user::random` or keys;
- for sandboxed containers on hardware, a Cortex-M core with an MPU. Without one,
  `start` fails with `Unsupported`.

## 1. Write the workload

A sandboxed workload runs unprivileged and may use **only** `bismuth::user` and `core`.
It needs an MPU-mappable stack (`UserStack1K`/`2K`/`4K`).

```rust
use bismuth::{Timeout, UserStack1K, user};

static TELEMETRY_STACK: UserStack1K = UserStack1K::new();

/// The workload: runs unprivileged, talks to the kernel only through `bismuth::user`.
extern "C-unwind" fn telemetry(_: usize) {
    let Ok(sensor) = user::open("sensor") else { user::exit(1) };
    let mut raw = [0u8; 4];
    for _ in 0..10 {
        if user::read(sensor, &mut raw, Timeout::Forever).is_ok() {
            user::log(b"[telemetry] sample\n");
        }
        user::sleep_ticks(100);
    }
    user::exit(0)
}
```

For a workload that must run privileged (an isolated but not sandboxed domain), use a
plain `fn(usize)`, any `Stack<N>`, and `ContainerEntry::privileged`. Such a workload is
only checked by software: see the [threat model](../design/security.md#threat-model).

## 2. Declare the container and validate it at compile time

```rust
use bismuth::security::container::{ContainerDecl, ContainerEntry, ContainerManifest, CpuBudget, OnFault, validate_containers};
use bismuth::security::manifest::{self, DomainDecl, GrantDecl};
use bismuth::security::{DomainSpec, Rights};

const TELEMETRY_DOMAIN: DomainDecl = DomainDecl {
    spec: DomainSpec::sandboxed("telemetry", 8, 2),          // ceiling 8, at most 2 tasks
    grants: &[GrantDecl { device: "temp0", name: "sensor", rights: Rights(Rights::READ.0 | Rights::CONTROL.0) }],
};

static CONTAINERS: ContainerManifest = ContainerManifest {
    containers: &[ContainerDecl {
        domain: TELEMETRY_DOMAIN,
        entry: ContainerEntry::user(telemetry, 5, &TELEMETRY_STACK),
        version: 1,
        cpu: Some(CpuBudget { period_ms: 100, micros: 20_000, partitioned: false }), // 20 %, not enforced yet
        ram_bytes: 1024,
        on_fault: OnFault::Restart { max: 3, window_ms: 1000 },                     // recorded, not acted on yet
        image_hash: [0; 32],
    }],
    supervisor: None,
};

// Both checks run at compile time: a policy mistake fails the build.
const _: () = manifest::validate(&manifest::Manifest { domains: &[TELEMETRY_DOMAIN] });
const _: () = validate_containers(&CONTAINERS);
```

Notes on the declaration:

- `GrantDecl::device` is the registered device name. `name` is what the container sees
  (`user::open("sensor")`). The real name `temp0` is invisible to it.
- A `DomainSpec::sandboxed` domain must use `ContainerEntry::user`, and a
  `DomainSpec::isolated` domain must use `ContainerEntry::privileged`. Otherwise the
  build fails.
- Keep the syscall surface small: `DomainSpec { syscalls: syscall::bit(nr::DEV_OPEN) |
  …, ..DomainSpec::sandboxed(..) }`. A call outside the allow-list is a violation and
  kills the domain under `BadHandlePolicy::Kill`.

## 3. Install and start at boot

Register the devices first, then install. `install` creates the domains and grants and
**seals** the security configuration, so it is the last policy step of boot.

```rust
driver::register("temp0", &SENSOR)?;          // or probe_all(&BOARD, FACTORIES)
container::install(&CONTAINERS)?;             // kernel/trusted code only; runs once per boot
let c = container::find("telemetry").unwrap();
container::start(c)?;                          // spawns the root task (detached) in the domain
```

## 4. Supervise

`health` and `restart` are for trusted code: the kernel domain, for example a
supervisor task you spawn without `.domain(..)`.

```rust
fn supervisor(arg: usize) {
    let c = container::ContainerId(security::DomainId(arg as u8));
    loop {
        task::sleep_ms(1000);
        let h = container::health(c).unwrap();
        if !h.running || h.faults > 0 {
            // Fresh generation, fresh DRBG stream, keys purged, peers' old handles invalid.
            let _ = container::restart(c);
        }
    }
}
```

`OnFault` and the `supervisor` field are not acted on automatically yet (**Planned**).
Until they are, a loop like this one is how you implement restart policy.
`Health::cpu_ticks` lets the loop watch CPU use against `container::budget(c)`.
Enforcement in the scheduler is also **Planned**.

## 5. Test it in the simulator

The whole lifecycle runs on the host. The policy checks are identical; the simulator
has no MPU.

```rust
static SENSOR: SimSensor = SimSensor::new(1);

#[test]
fn telemetry_container_lifecycle() {
    sim::run_to_completion(|| {
        driver::register("temp0", &SENSOR).unwrap();
        container::install(&CONTAINERS).unwrap();
        let c = container::find("telemetry").unwrap();
        container::start(c).unwrap();
        task::Builder::new("supervisor").priority(2).spawn(move |d| {
            let c = container::ContainerId(bismuth::security::DomainId(d as u8));
            task::sleep_ticks(50);
            let h = container::health(c).unwrap();
            assert!(h.running && h.violations == 0 && h.faults == 0);
            let g = h.generation;
            container::restart(c).unwrap();
            assert!(container::health(c).unwrap().generation > g);
            task::sleep_ticks(2000);
            assert!(!container::health(c).unwrap().running); // the workload finished
        }, c.0.0 as usize).unwrap();
    });
}
```

`tests/containers.rs` has two more examples: install, start, health and restart; and
untrusted domains being refused `stop` and `install`.

## Troubleshooting

| symptom | cause |
|---------|-------|
| build error `sandboxed container needs a user entry` | the domain is `sandboxed` but the entry is `privileged` (or the reverse) |
| build error `container: soft CPU budgets exceed 100%` | the soft budgets sum to more than one window |
| `install` → `NotFound` | a granted device is not registered yet |
| `install` → `PermissionDenied` | the caller is untrusted, or the system is already sealed (a second `install`) |
| `start` → `Busy` | the root stack is still claimed, for example a `start` without a `stop` first |
| `start` → `Unsupported` | sandboxed container on a core without an MPU |
| build error `entry priority exceeds the domain priority ceiling` | raise the ceiling in the `DomainSpec` or lower the entry priority |
