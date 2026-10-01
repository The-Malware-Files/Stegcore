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

//! Termination-signal handling, separate from Ctrl-C.
//!
//! Ctrl-C (SIGINT) is a request from a person at a keyboard, and the right
//! answer is to set a flag and let the running operation unwind on its own: keys
//! get zeroized, partial output gets removed, the user gets a sentence. That is
//! what `ctrlc` in `main` does.
//!
//! SIGTERM and SIGHUP are different. They come from a supervisor that has
//! already decided this process is going away, and it is holding a stopwatch.
//! Two things make the cooperative flag insufficient there:
//!
//! 1. **The kernel may never deliver the signal at all.** A process that is PID
//!    1 inside its own PID namespace, which is every plain `docker run` without
//!    an init process, has signals DISCARDED by the kernel when their
//!    disposition is still the default. SIGTERM is not ignored by the program in
//!    that case; it is dropped before the program can see it. Registering any
//!    handler changes the disposition and the signal starts arriving. Measured
//!    on 2026-10-01: the same binary blocked on the same read exits 143 as an
//!    ordinary process and survives SIGTERM indefinitely as namespace PID 1.
//!
//! 2. **A blocked read cannot be unwound by a flag.** The wizard sits in
//!    `read_line` on stdin. If stdin is a pipe that is open but never delivers,
//!    that read does not return, so nothing ever looks at the flag. Setting it
//!    makes the hang visible to code that checks; it does not end it.
//!
//! So a termination signal sets the flag, gives the main thread a short grace to
//! finish unwinding properly, and then exits the process itself. The grace is
//! what keeps the clean path clean: an operation that can unwind wins the race
//! and exits first, and this thread never gets to its exit call.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How long the main thread gets to unwind on its own before we exit for it.
///
/// Comfortably inside the ten seconds `docker stop` allows, so the process
/// chooses its own exit code and runs its own cleanup rather than being
/// SIGKILLed. Long enough that an operation already unwinding finishes first.
pub const TERMINATION_GRACE: Duration = Duration::from_secs(2);

/// Exit code for a process terminated by `sig`.
///
/// The shell convention, and the same number the kernel's own default
/// disposition produces, so a supervisor sees no difference between a stegcore
/// that handles the signal and one that did not: 143 for SIGTERM, 129 for
/// SIGHUP.
pub fn termination_exit_code(sig: i32) -> i32 {
    128 + sig
}

/// Register for SIGTERM and SIGHUP.
///
/// Spawns one thread that waits for either. On arrival it raises `interrupted`,
/// waits `TERMINATION_GRACE` for the main thread to leave on its own, and exits
/// if it has not. Best effort: a platform or a sandbox that refuses the
/// registration leaves the process on the kernel's default disposition, which is
/// what it had before, so the failure costs nothing it was not already paying.
#[cfg(unix)]
pub fn install_termination_handler(interrupted: Arc<AtomicBool>) {
    use signal_hook::consts::{SIGHUP, SIGTERM};
    use signal_hook::iterator::Signals;

    let Ok(mut signals) = Signals::new([SIGTERM, SIGHUP]) else {
        return;
    };

    let spawned = std::thread::Builder::new()
        .name("stegcore-term".into())
        .spawn(move || {
            // `forever` blocks on a self-pipe, so this thread costs nothing
            // while idle. One signal is enough: we are leaving either way.
            if let Some(sig) = signals.forever().next() {
                interrupted.store(true, Ordering::SeqCst);
                std::thread::sleep(TERMINATION_GRACE);
                std::process::exit(termination_exit_code(sig));
            }
        });

    // A thread we could not spawn is a registration we do not have. Say nothing:
    // this runs before argument parsing, and a warning here would land on stderr
    // of every single invocation on a machine that is out of threads, which is
    // noise on top of a problem the user already has.
    drop(spawned);
}

/// Non-Unix platforms have no SIGTERM and no namespace-PID-1 rule; Windows
/// console control events are already covered by `ctrlc`.
#[cfg(not(unix))]
pub fn install_termination_handler(_interrupted: Arc<AtomicBool>) {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigterm_maps_to_the_conventional_143() {
        assert_eq!(termination_exit_code(15), 143);
    }

    #[test]
    fn sighup_maps_to_the_conventional_129() {
        assert_eq!(termination_exit_code(1), 129);
    }

    /// The grace only helps if it is comfortably inside the supervisor's own
    /// patience. `docker stop` allows ten seconds; systemd's default
    /// `TimeoutStopSec` is ninety. Ten is the tight one, so bound against it
    /// with room to spare.
    #[test]
    fn the_grace_fits_inside_a_docker_stop() {
        assert!(TERMINATION_GRACE < Duration::from_secs(10));
        assert!(TERMINATION_GRACE <= Duration::from_secs(5));
    }

    /// Zero would defeat the point: an operation mid-unwind would be cut off
    /// before it could zeroize keys or remove a partial output file.
    #[test]
    fn the_grace_leaves_room_to_unwind() {
        assert!(TERMINATION_GRACE >= Duration::from_secs(1));
    }

    /// Installing twice must not panic or abort. The handler is installed once
    /// in `main`, but a test binary or a future embedding may reach it again,
    /// and a signal registration that aborts on a second call is a crash
    /// waiting for a refactor.
    #[test]
    fn installing_is_safe_to_repeat() {
        let flag = Arc::new(AtomicBool::new(false));
        install_termination_handler(Arc::clone(&flag));
        install_termination_handler(Arc::clone(&flag));
        assert!(!flag.load(Ordering::SeqCst));
    }
}
