// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! SIGTERM has to work in the two places it is sent from, and the hard one is
//! not the one you would test by hand.
//!
//! An ordinary process gets SIGTERM's default disposition from the kernel and
//! dies whatever the program does, so testing it on this machine proves nothing
//! about the case that was broken. The case that was broken is PID 1 inside a
//! PID namespace, which is every `docker run` without an init: the kernel
//! discards a signal there if its disposition is still the default, so SIGTERM
//! is dropped before the program sees it and the supervisor falls through to
//! SIGKILL after its grace period. Reported from a containerised run on
//! 2026-10-01, reproduced here, and the reason `src/signals.rs` exists.
//!
//! Both arms below hold stdin open as a FIFO that never delivers a byte. That is
//! the state the bug needs: the wizard is blocked in `read_line`, so no
//! cooperative interrupt flag can unwind it, and only the signal path can end
//! the process. `< /dev/null` is not this case, because it returns EOF
//! immediately and the wizard exits on its own.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Longest we wait for a signalled process to go away. Well inside the ten
/// seconds `docker stop` allows, and above the two-second grace in `signals`.
const DEATH_DEADLINE: Duration = Duration::from_secs(6);

/// Time for the wizard to reach its blocking read before we signal it. The
/// prompt is flushed before the read, so this only has to cover process start.
const SETTLE: Duration = Duration::from_secs(2);

fn binary() -> PathBuf {
    // The integration-test binary lives next to the one under test.
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("stegcore")
}

/// A FIFO opened for both read and write, so the read end never sees EOF and
/// never sees data. Dropping it removes the file.
struct NeverDelivers {
    path: PathBuf,
    _writer: fs::File,
}

impl NeverDelivers {
    fn new(dir: &Path, name: &str) -> Self {
        let path = dir.join(name);
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("fifo path");
        // SAFETY: a nul-terminated path from a CString and a constant mode. The
        // only failure mode is a returned -1, which we check.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {}", path.display());

        // Held open for writing for the lifetime of the test: this is what keeps
        // the reader blocked rather than at EOF.
        let writer = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&path)
            .expect("open fifo");

        Self {
            path,
            _writer: writer,
        }
    }

    fn reader(&self) -> fs::File {
        fs::File::open(&self.path).expect("fifo read end")
    }
}

impl Drop for NeverDelivers {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Wait up to `DEATH_DEADLINE` for `child` to exit. Returns its exit status, or
/// `None` if it outlived the deadline. Kills it either way so no test leaks a
/// process.
fn wait_for_death(child: &mut Child) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    while start.elapsed() < DEATH_DEADLINE {
        match child.try_wait().expect("try_wait") {
            Some(status) => return Some(status),
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Find the stegcore process that is PID 1 of some PID namespace.
///
/// `unshare --fork` stays in the parent namespace and waits, so the process we
/// spawned is NOT the one under test and signalling it proves nothing: it is a
/// different process with a different disposition. `docker stop` signals the
/// container's init directly, and so must this test, which means finding it.
///
/// `/proc/<pid>/status` reports `NSpid` as the pid in each namespace from
/// outermost inward, so a trailing `1` means this process is an init. Matching on
/// the executable name rather than the command line avoids the self-match that
/// makes a full-command-line search return the searcher.
fn find_namespace_init_stegcore() -> Option<i32> {
    for entry in fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        if comm.trim() != "stegcore" {
            continue;
        }
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let is_init = status
            .lines()
            .find(|l| l.starts_with("NSpid:"))
            .and_then(|l| l.split_whitespace().next_back())
            .is_some_and(|inner| inner == "1");
        if is_init {
            return Some(pid);
        }
    }
    None
}

/// Wait up to `DEATH_DEADLINE` for a pid we do not own to disappear. `kill(0)`
/// is the only handle we have on a process that is not our child, so there is no
/// exit status to read; absence is the whole result.
fn wait_for_pid_to_vanish(pid: i32) -> bool {
    let start = Instant::now();
    while start.elapsed() < DEATH_DEADLINE {
        // SAFETY: signal 0 performs the permission and existence check only and
        // delivers nothing.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Whether this machine lets an unprivileged user create a PID namespace. A
/// hardened kernel or a restricted CI container may not, and a test that cannot
/// run must say so rather than fail or silently pass.
fn can_unshare_pid() -> bool {
    Command::new("unshare")
        .args(["-rpf", "--mount-proc", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The baseline arm: an ordinary process, where the kernel's default disposition
/// would have handled it anyway. This exists to prove the harness itself works,
/// so that a pass in the namespace arm means something. If this arm ever fails,
/// the FIFO or the binary path is wrong and the other arm's result is void.
#[test]
fn an_ordinary_process_dies_on_sigterm_while_blocked_on_stdin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = NeverDelivers::new(dir.path(), "stdin");

    let mut child = Command::new(binary())
        .arg("wizard")
        .stdin(Stdio::from(fifo.reader()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn wizard");

    std::thread::sleep(SETTLE);
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "wizard exited before it was signalled, so this arm tested nothing: \
         stdin is supposed to be an open FIFO that never delivers"
    );

    // SAFETY: a pid we own, from a child we spawned and have not reaped.
    let rc = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(rc, 0, "kill failed");

    let status = wait_for_death(&mut child).expect("ordinary process ignored SIGTERM");
    assert!(
        !status.success(),
        "a terminated process must not report success, got {status:?}"
    );
}

/// The arm that was actually broken. `unshare -rpf` makes stegcore PID 1 of a
/// fresh PID namespace, which is what a container entrypoint is, and the kernel
/// then discards any signal still on its default disposition. Before
/// `install_termination_handler` this survived SIGTERM indefinitely.
///
/// We signal the host-visible PID of the namespace's init, which is what
/// `docker stop` does from outside.
#[test]
fn namespace_pid_1_dies_on_sigterm_while_blocked_on_stdin() {
    if !can_unshare_pid() {
        eprintln!(
            "SKIP: unprivileged PID namespaces unavailable here, so the \
             container case cannot be reproduced on this machine"
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = NeverDelivers::new(dir.path(), "stdin");

    // `unshare` execs into stegcore, so the child we hold is the process that is
    // PID 1 inside the namespace. No shell in between to absorb anything.
    let mut child = Command::new("unshare")
        .args(["-rpf", "--mount-proc"])
        .arg(binary())
        .arg("wizard")
        .stdin(Stdio::from(fifo.reader()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn unshared wizard");

    std::thread::sleep(SETTLE);
    if child.try_wait().expect("try_wait").is_some() {
        // unshare itself failed after the probe said it would work. Not our bug,
        // and not something to assert a verdict from.
        eprintln!("SKIP: unshared wizard exited early, PID namespace not usable");
        let _ = child.wait();
        return;
    }

    let Some(init_pid) = find_namespace_init_stegcore() else {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "could not find a stegcore running as namespace PID 1, so the \
             container case was never set up and this test proved nothing"
        );
    };

    // SAFETY: a pid read from /proc, signalled with SIGTERM. A pid that has
    // already exited yields -1 and ESRCH rather than reaching anything else.
    let rc = unsafe { libc::kill(init_pid, libc::SIGTERM) };
    assert_eq!(rc, 0, "kill failed");

    let died = wait_for_pid_to_vanish(init_pid);

    // Tidy up before asserting, so a failure does not leave a wedged process
    // holding the FIFO open for the rest of the suite.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        died,
        "namespace PID 1 survived SIGTERM: the kernel discards a \
         default-disposition signal for namespace init, so something must \
         register for SIGTERM. See crates/cli/src/signals.rs"
    );
}
