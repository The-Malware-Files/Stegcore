// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Keeping key material out of swap and out of crash dumps.
//!
//! `Zeroizing` clears a buffer when it drops, which is the right thing and does
//! nothing at all about a copy the kernel already wrote to disk. The forensic
//! footprint audit (2026-08-20) found no `mlock`, no dump guard, and no
//! `madvise` anywhere in the workspace, so both of those paths were open.
//!
//! Two deliberate limits:
//!
//! * Only small buffers are locked. `RLIMIT_MEMLOCK` is commonly 8 MiB, and
//!   Argon2id's working set is 128 MiB, so locking the KDF's scratch space is
//!   not on the table. The derived key and the passphrase are tens of bytes and
//!   fit comfortably.
//! * Locking is best effort. A container or a hardened host may refuse it, and
//!   refusing to encrypt because the kernel would not pin a page would trade a
//!   real failure for a theoretical one. Callers can ask whether it worked.

/// A zeroing byte buffer whose pages are pinned out of swap for its lifetime.
///
/// Allocated once at the requested length and never grown, because a
/// reallocation would copy the secret to a fresh, unlocked allocation and leave
/// the original behind.
pub struct LockedBytes {
    buf: zeroize::Zeroizing<Vec<u8>>,
    locked: bool,
}

impl LockedBytes {
    /// A zeroed buffer of `len` bytes, pinned if the platform allows it.
    pub fn new(len: usize) -> Self {
        let buf = zeroize::Zeroizing::new(vec![0u8; len]);
        let locked = lock(buf.as_ptr(), buf.len());
        Self { buf, locked }
    }

    /// True when the pages are genuinely pinned. False means the allocation is
    /// still zeroed on drop but may reach swap.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl std::ops::Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        // Zeroize first, then unpin: the buffer's own Drop runs after this one,
        // so clearing here means the secret is gone before the pages are
        // allowed to move.
        use zeroize::Zeroize;
        self.buf.zeroize();
        if self.locked {
            unlock(self.buf.as_ptr(), self.buf.len());
        }
    }
}

#[cfg(unix)]
fn lock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    // SAFETY: ptr and len describe a live allocation owned by the caller, and
    // mlock only changes the paging behaviour of that range.
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
fn unlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: as above, and this range was locked by `lock`.
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
fn lock(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
fn unlock(_ptr: *const u8, _len: usize) {}

/// Ask the kernel not to write a core dump for this process.
///
/// A dump of a process holding a derived key writes that key to disk, where
/// `Zeroizing` cannot reach it. Call once at start-up. Best effort, and a
/// no-op off Unix.
///
/// This also stops a debugger attaching under Linux's default `ptrace_scope`,
/// which is a side effect worth knowing about rather than a goal.
pub fn disable_core_dumps() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE takes an integer flag and touches
        // no memory belonging to this process.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) == 0 }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // No prctl. Setting the core limit to zero is the portable equivalent.
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the struct we just built and nothing else.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_bytes_are_usable_and_zeroed_at_the_right_length() {
        let mut b = LockedBytes::new(32);
        assert_eq!(b.len(), 32);
        assert!(!b.is_empty());
        assert!(b.as_slice().iter().all(|&x| x == 0));
        b.as_mut_slice()[0] = 7;
        assert_eq!(b.as_slice()[0], 7);
    }

    /// Locking is best effort, so this asserts the call is answered rather than
    /// that it succeeded: a container with a low RLIMIT_MEMLOCK is a legitimate
    /// environment and must not fail the suite.
    #[test]
    fn locking_reports_its_outcome() {
        let b = LockedBytes::new(32);
        let _ = b.is_locked();
    }

    #[test]
    fn zero_length_is_not_reported_as_locked() {
        let b = LockedBytes::new(0);
        assert!(!b.is_locked());
        assert!(b.is_empty());
    }

    #[test]
    fn disabling_core_dumps_is_answered() {
        let _ = disable_core_dumps();
    }
}
