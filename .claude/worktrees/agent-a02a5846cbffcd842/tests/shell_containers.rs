//! Driving a container's full lifecycle through the serial shell's command dispatch — the
//! "run containers" path end to end: `con ls` / `con start` / `con status` / `con stop` go
//! through `shell::exec`, the container runtime, security domains, and spawn a sandboxed
//! (hardware-isolated on real targets) user task that actually runs.

#![cfg(all(feature = "shell", feature = "containers"))]

use core::fmt::{self, Write};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};

use bismuth::driver;
use bismuth::driver::sensor::SimSensor;
use bismuth::security::container::{self, ContainerDecl, ContainerEntry, ContainerManifest, OnFault, validate_containers};
use bismuth::security::manifest::{DomainDecl, GrantDecl};
use bismuth::security::{DomainSpec, Rights};
use bismuth::{Timeout, UserStack1K, shell, sim, task, user};

static SERIAL: StdMutex<()> = StdMutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A fixed-capacity, heap-free `Write` sink for the shell output.
struct Buf {
    data: [u8; 1024],
    len: usize,
}
impl Buf {
    fn new() -> Self {
        Buf { data: [0; 1024], len: 0 }
    }
    fn s(&self) -> &str {
        core::str::from_utf8(&self.data[..self.len]).unwrap()
    }
}
impl Write for Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.data.len() - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}
fn sh(line: &str) -> Buf {
    let mut b = Buf::new();
    shell::exec(&mut b, line);
    b
}

static LOG: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

static RUNS: AtomicU32 = AtomicU32::new(0);
static WEB_STACK: UserStack1K = UserStack1K::new();

/// A sandboxed container workload: read its granted sensor, then exit.
extern "C-unwind" fn webserver(_: usize) {
    RUNS.fetch_add(1, Ordering::Relaxed);
    if let Ok(h) = user::open("port") {
        let mut raw = [0u8; 4];
        let _ = user::read(h, &mut raw, Timeout::Forever);
    }
    user::log(b"[webserver] served\n");
    user::exit(0)
}

static SENSOR: SimSensor = SimSensor::new(1);

static MANIFEST: ContainerManifest = ContainerManifest {
    containers: &[ContainerDecl {
        domain: DomainDecl {
            spec: DomainSpec::sandboxed("webserver", 8, 2),
            grants: &[GrantDecl { device: "nic", name: "port", rights: Rights::READ }],
            dirs: &[],
        },
        entry: ContainerEntry::user(webserver, 5, &WEB_STACK),
        version: 2,
        cpu: None,
        ram_bytes: 1024,
        on_fault: OnFault::Stop,
        image_hash: [0; 32],
    }],
    supervisor: None,
};
const _: () = validate_containers(&MANIFEST);

#[test]
fn a_container_runs_through_the_shell() {
    let _s = serial();
    RUNS.store(0, Ordering::Relaxed);
    *LOG.lock().unwrap() = Vec::new();
    sim::run_to_completion(|| {
        driver::register("nic", &SENSOR).unwrap();
        container::install(&MANIFEST).unwrap();

        // A trusted control task drives the container the way an operator would at the console.
        task::Builder::new("operator")
            .priority(2)
            .spawn(move |_| {
                let mut l = LOG.lock().unwrap();
                // Listed, initially stopped.
                let ls = sh("con ls");
                l.push(format!("ls0:{}", ls.s().contains("webserver") && ls.s().contains("stopped")));
                // Start it; the sandboxed workload runs.
                l.push(format!("start:{}", sh("con start webserver").s().trim()));
                task::sleep_ticks(5);
                l.push(format!("runs:{}", RUNS.load(Ordering::Relaxed)));
                // Status reflects it (the one-shot workload has exited by now = stopped).
                let st = sh("con status webserver");
                l.push(format!("status_ok:{}", st.s().contains("webserver:")));
                // Stop is idempotent and accepted.
                l.push(format!("stop:{}", sh("con stop webserver").s().trim()));
                // An unknown container is reported cleanly.
                l.push(format!("missing:{}", sh("con status nosuch").s().contains("no such container")));
            }, 0)
            .unwrap();
    });
    let l = LOG.lock().unwrap();
    assert_eq!(
        *l,
        [
            "ls0:true".to_string(),
            "start:webserver: ok".into(),
            "runs:1".into(),
            "status_ok:true".into(),
            "stop:webserver: ok".into(),
            "missing:true".into(),
        ]
    );
}
