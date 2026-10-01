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

//! Audio analysis must not grow its memory with the length of the file.
//!
//! Measured before the streaming rewrite: a 120 MB 8-bit WAV drove `score` to
//! 1.80 GiB of peak resident memory and `analyse` to 1.49 GiB, roughly 14 times
//! the file size, with no limit anywhere in the path and exit status 0. The
//! operator's decision was to stream rather than to impose a size ceiling, so
//! there is no number a user can hit; what replaces the ceiling is this test.
//!
//! Peak resident set size is the wrong instrument for a regression gate: it moves
//! with the allocator's own behaviour, with other tests sharing the process and
//! with the machine. So this measures the engine's own peak live heap through a
//! counting allocator, which is deterministic and says exactly what changed.
//!
//! The assertion is a shape, not a threshold: analysing a file sixteen times
//! longer must not cost appreciably more memory. A threshold would need
//! re-tuning every time an unrelated buffer changed size; the shape holds
//! whatever the constants are, and it is the actual property that was broken.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

// ── A counting allocator ──────────────────────────────────────────────────────

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            record(layout.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            record(new_size as isize - layout.size() as isize);
        }
        p
    }
}

/// Fold one allocation or release into the live total, raising the watermark.
///
/// `fetch_max` rather than a load-compare-store, so concurrent allocations from
/// a worker pool cannot lose a peak between them.
fn record(delta: isize) {
    let live = if delta >= 0 {
        LIVE.fetch_add(delta as usize, Ordering::Relaxed) + delta as usize
    } else {
        LIVE.fetch_sub((-delta) as usize, Ordering::Relaxed)
    };
    PEAK.fetch_max(live, Ordering::Relaxed);
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak live heap, in bytes, reached while `f` ran.
fn peak_bytes_of(f: impl FnOnce()) -> usize {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    f();
    PEAK.load(Ordering::Relaxed)
        .saturating_sub(LIVE.load(Ordering::Relaxed))
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Write a mono 8-bit WAV of `frames` samples with content that is neither
/// silent nor smooth, so no detector short circuits on a degenerate input.
fn wav(name: &str, frames: usize) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 8,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(&path, spec).unwrap();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..frames {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        writer.write_sample(((state >> 56) as i32) - 128).unwrap();
    }
    writer.finalize().unwrap();
    path
}

/// One sample per byte at 8 bits, so this is also the file's data size.
const SHORT_SAMPLES: usize = 500_000;
const LONG_SAMPLES: usize = SHORT_SAMPLES * 16;

/// Headroom allowed between the short and the long measurement.
///
/// Not zero, because the path string the report carries grows by a few bytes
/// with the file name and because a chunk buffer is allocated lazily. Measured
/// across a sixty-four-fold range of lengths, `analyse` moved by four bytes and
/// `assess` by none, so a quarter of a mebibyte is generous. One scaling buffer
/// would blow straight through it: holding the long file's samples needs 32 MiB
/// for the `i32` copy alone, and the implementation this replaced held three
/// such copies at once.
const HEADROOM: usize = 256 * 1024;

fn measure(path: &Path, run: fn(&Path)) -> usize {
    // Warm up first: thread pools, lazily built tables and the chunk buffer all
    // allocate once, and counting that against the first measurement would read
    // as scaling when it is start-up.
    run(path);
    peak_bytes_of(|| run(path))
}

/// One audio entry point, named for the assertion message.
type NamedPath = (&'static str, fn(&Path));

fn run_analyse(p: &Path) {
    stegcore_engine::analysis::analyse(p).expect("analyse");
}

fn run_analyse_fast(p: &Path) {
    stegcore_engine::analysis::analyse_fast(p).expect("analyse_fast");
}

fn run_score(p: &Path) {
    stegcore_engine::steg::assess(p).expect("assess");
}

// ── The test ──────────────────────────────────────────────────────────────────

/// One test, not three, and deliberately so.
///
/// The counters above are process wide, and cargo runs the tests in a file
/// concurrently in one process, so three separate tests measure each other's
/// allocations. That is not a flaky test, it is a wrong one: it reported a
/// megabyte of growth that a single-threaded re-run showed to be four bytes.
/// Keeping the measurements in one test keeps them honest.
#[test]
fn the_audio_paths_do_not_grow_with_the_length_of_the_audio() {
    let short = wav("mem_short.wav", SHORT_SAMPLES);
    let long = wav("mem_long.wav", LONG_SAMPLES);

    // `analyse` reads every sample; `analyse_fast` decimates, which used to make
    // its working set a tenth of the full path's rather than constant, and a
    // tenth of an unbounded quantity is still unbounded; `assess` was the worst
    // of the three as measured, because it widened every sample to f64 as well
    // as holding the i32 copy.
    let paths: [NamedPath; 3] = [
        ("analyse", run_analyse),
        ("analyse --fast", run_analyse_fast),
        ("score", run_score),
    ];

    for (label, run) in paths {
        let short_peak = measure(&short, run);
        let long_peak = measure(&long, run);
        assert!(
            long_peak <= short_peak + HEADROOM,
            "{label}: memory scales with input. {SHORT_SAMPLES} samples peaked at \
             {short_peak} bytes, {LONG_SAMPLES} samples at {long_peak} bytes, a rise \
             of {} bytes against a {HEADROOM}-byte allowance.",
            long_peak.saturating_sub(short_peak)
        );
        assert!(
            long_peak < 16 * 1024 * 1024,
            "{label}: {long_peak} bytes is more than the whole audio path should ever hold"
        );
    }

    std::fs::remove_file(&short).ok();
    std::fs::remove_file(&long).ok();
}
