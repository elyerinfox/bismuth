//! The interactive serial shell's command dispatch, tested without a device by running
//! `shell::exec` against an in-memory `Write` sink.

#![cfg(feature = "shell")]

use core::fmt::{self, Write};

use bismuth::shell;

/// A fixed-capacity, heap-free `Write` sink.
struct Buf {
    data: [u8; 1024],
    len: usize,
}

impl Buf {
    fn new() -> Self {
        Buf { data: [0; 1024], len: 0 }
    }
    fn as_str(&self) -> &str {
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

fn run(line: &str) -> Buf {
    let mut b = Buf::new();
    shell::exec(&mut b, line);
    b
}

#[test]
fn help_lists_the_builtins() {
    let out = run("help");
    let s = out.as_str();
    assert!(s.contains("echo"));
    assert!(s.contains("uptime"));
    assert!(s.contains("ver"));
}

#[test]
fn echo_prints_its_arguments() {
    assert_eq!(run("echo hello world").as_str(), "hello world\n");
    // No args echoes a blank line.
    assert_eq!(run("echo").as_str(), "\n");
}

#[test]
fn ver_reports_the_version() {
    let out = run("ver");
    assert!(out.as_str().contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn an_empty_line_produces_no_output() {
    assert_eq!(run("").as_str(), "");
    assert_eq!(run("   ").as_str(), "");
}

#[test]
fn an_unknown_command_is_reported() {
    let out = run("frobnicate now");
    assert!(out.as_str().contains("unknown command: frobnicate"));
}

#[cfg(feature = "containers")]
#[test]
fn con_handles_missing_containers() {
    // Nothing installed in this unit test: `ls` says so, `status` on a name fails cleanly.
    assert!(run("con ls").as_str().contains("no containers installed"));
    assert!(run("con status webserver").as_str().contains("no such container: webserver"));
    assert!(run("con bogus").as_str().contains("unknown subcommand"));
    assert!(run("con").as_str().contains("usage:"));
}
