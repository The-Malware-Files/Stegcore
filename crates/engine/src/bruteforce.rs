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

//! Bounded attribution search: recover the key a steganography tool used to
//! place its payload, so the file can be named as that tool's output.
//!
//! # What this is for
//!
//! Some tools leave a signature in the file where anyone can read it. Others
//! write theirs into the hidden payload itself, scattered through the carrier
//! in an order only the password knows. For those, the signature exists but is
//! unreadable until you reproduce the scatter order. That is what this module
//! does: it tries candidate keys, reproduces the order each one implies, reads
//! the first few bytes, and looks for the tool's signature.
//!
//! A hit is decisive. Reading a tool's own signature out of a carrier is not a
//! statistical opinion about whether something is hidden; it is the tool's
//! name, in its own bytes. A miss proves nothing at all, and the search report
//! says so in as many words, because a search that stopped at its attempt cap
//! has examined a fraction of a percent of the space.
//!
//! # Why it is gated
//!
//! This is dual use. The same machinery that attributes a file in an
//! investigation recovers someone's hidden message. `AUP.md` section 3.1 is the
//! governing policy: the capability runs only behind a recorded authorisation,
//! and [`authorisation`] is the surface that records it.
//!
//! # The shape of the search
//!
//! [`Probe`] is the boundary between the search and the tool. A probe owns a
//! candidate space (a wordlist, a seed range, a short list of known constants),
//! decodes its carrier once up front, and answers one question per candidate.
//! Everything about running the search safely, which is most of the code here,
//! lives on this side of that boundary and is shared by every tool.
//!
//! Four properties the search holds, each of which cost real care:
//!
//! - **Bounded.** There is no unbounded loop. [`SearchLimits::max_attempts`]
//!   always applies, [`SearchLimits::deadline`] bounds wall-clock time, and the
//!   candidate space itself reports a finite length.
//! - **Deterministic.** The same carrier and the same cap return the same
//!   answer, on any machine, at any thread count. Threads claim chunks in
//!   whatever order they win the race, but the reported hit is always the
//!   *lowest-indexed* one, and the search only stops claiming work once every
//!   chunk that could hold a lower index has been claimed. Thread scheduling
//!   changes how long it takes and nothing about what it says.
//! - **Interruptible and resumable.** A cancellation flag is checked between
//!   chunks, and an interrupted search reports the index to resume from. That
//!   index is the start of the lowest chunk not known to be complete, so a
//!   resume may re-examine a little work and can never skip any.
//! - **Quiet about nothing.** A long search emits a heartbeat on an interval,
//!   so an operator can see it is alive and can see how far from done it is.
//!
//! # The panic surface, removed rather than caught
//!
//! The hot loop touches no parser. Each probe decodes its carrier once, before
//! the search starts, into a plain buffer of samples; from then on the loop is
//! integer arithmetic over a slice with checked indexing. This is deliberate:
//! wrapping a worker in `catch_unwind` would contain a crash without fixing it,
//! and the carrier decode is the only place a crash could come from, so the
//! decode happens once, on the calling thread, where its error is returned
//! rather than unwound.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::StegError;

pub mod authorisation;
pub mod digest;
pub mod java_random;
pub mod openstego;
pub mod steghide;

/// Default attempt cap.
///
/// Chosen to be a search an operator can sit through rather than one that looks
/// thorough.
///
/// **Measured**, not estimated, on an eight-core laptop against a 96 by 96
/// carrier: the OpenStego probe runs at **132,775 candidates per second** in a
/// release build and 9,725 in a debug one. So this default is under a second of
/// real work, and the numbers that matter follow from it:
///
/// | Space | Width | Cost at the measured rate |
/// |---|---|---|
/// | This default | 100,000 | under a second |
/// | A 32 bit sweep | 4.3 thousand million | about 9 hours |
/// | OpenStego's own key space | 60 bits | about 268 million times the 9 hours |
///
/// Which is the honest shape of the problem: exhaustion does not find keys at
/// any throughput anyone will ever have, and wordlists do. The figure is
/// re-measurable with
/// `cargo test --release -p stegcore-engine --test bruteforce_attribution
/// throughput -- --nocapture`, so nobody has to take this comment's word for it.
pub const DEFAULT_MAX_ATTEMPTS: u64 = 100_000;

/// Chunk size. Workers claim this many consecutive candidates at a time, which
/// keeps the shared counter cold without making the resume point coarse.
pub const DEFAULT_CHUNK: u64 = 1_024;

/// Heartbeat interval. The baseline asks for one every 30 to 60 seconds on a
/// long-running loop; 30 is the attentive end of that range.
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(30);

/// How long to keep trying for the shared result lock before giving up on it.
/// Nothing in this module holds that lock for more than a few instructions, so
/// reaching this deadline means something is badly wrong and the search says so
/// rather than blocking forever.
const LOCK_DEADLINE: Duration = Duration::from_secs(5);

/// How the search was bounded. Every field has a limit; none of them is
/// optional in the sense of "run until it finishes".
#[derive(Debug, Clone)]
pub struct SearchLimits {
    /// Candidates to examine, counting from `resume_from`.
    pub max_attempts: u64,
    /// Index to start at. Zero for a fresh search; for a resumed one, the
    /// `resume_from` of the search that stopped.
    pub resume_from: u64,
    /// Worker threads. Zero means "ask the machine", clamped to a sane band.
    pub threads: usize,
    /// Candidates claimed per chunk.
    pub chunk: u64,
    /// How often to emit a heartbeat.
    pub heartbeat: Duration,
    /// Wall-clock ceiling on the whole search, if any. A search with neither a
    /// deadline nor a reachable cap is still bounded by the cap.
    pub deadline: Option<Duration>,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            resume_from: 0,
            threads: 0,
            chunk: DEFAULT_CHUNK,
            heartbeat: DEFAULT_HEARTBEAT,
            deadline: None,
        }
    }
}

impl SearchLimits {
    /// Threads to use, clamped. One thread is always valid; the upper clamp
    /// exists so a machine reporting an implausible core count cannot be talked
    /// into spawning thousands of workers.
    fn worker_count(&self) -> usize {
        let requested = if self.threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.threads
        };
        requested.clamp(1, 256)
    }

    /// Chunk size, clamped away from zero (which would make no progress).
    fn chunk_size(&self) -> u64 {
        self.chunk.clamp(1, 1 << 24)
    }
}

/// A snapshot handed to the heartbeat callback.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Candidates examined so far in this run.
    pub attempted: u64,
    /// Candidates this run will examine at most.
    pub planned: u64,
    /// Time since the search started.
    pub elapsed: Duration,
    /// Candidates per second, averaged over the run so far.
    pub rate_per_second: f64,
}

impl Progress {
    /// Fraction of the planned work done, in 0.0 to 1.0.
    pub fn fraction(&self) -> f64 {
        if self.planned == 0 {
            return 1.0;
        }
        (self.attempted as f64 / self.planned as f64).clamp(0.0, 1.0)
    }
}

/// Why the search stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// A candidate matched. This is the decisive outcome.
    Found,
    /// Every candidate in the space was examined without a match. For a space
    /// small enough to exhaust, and only then, this is a real negative.
    Exhausted,
    /// The attempt cap was reached first.
    CapReached,
    /// The wall-clock deadline was reached first.
    DeadlineReached,
    /// The caller cancelled.
    Cancelled,
}

impl StopReason {
    /// Whether a reader may treat the absence of a hit as meaningful. Only an
    /// exhausted space licenses that; every other stop reason means the search
    /// simply stopped looking.
    pub fn is_conclusive_negative(&self) -> bool {
        matches!(self, StopReason::Exhausted)
    }
}

/// What a search produced.
#[derive(Debug, Clone)]
pub struct SearchReport<E> {
    /// The tool this search was looking for.
    pub tool: &'static str,
    /// The matching candidate's index and what it proved, if there was one.
    pub hit: Option<Hit<E>>,
    /// Why it stopped.
    pub stop_reason: StopReason,
    /// Candidates examined.
    pub attempted: u64,
    /// Size of the whole candidate space, which is usually far larger than
    /// `attempted` and is the number that makes a miss meaningless.
    pub space_size: u64,
    /// Where a resumed search should start. Equal to the start of the lowest
    /// chunk not known to have finished, so resuming never skips a candidate.
    pub resume_from: u64,
    /// Wall-clock duration.
    pub elapsed: Duration,
    /// Observed throughput, which is the number to quote when telling an
    /// operator what a larger search would cost.
    pub rate_per_second: f64,
}

impl<E> SearchReport<E> {
    /// Plain-language summary, suitable for printing to an operator.
    pub fn summary(&self) -> String {
        match (&self.hit, &self.stop_reason) {
            (Some(hit), _) => format!(
                "Confirmed {}: candidate {} matched after {} attempts.",
                self.tool, hit.label, self.attempted
            ),
            (None, StopReason::Exhausted) => format!(
                "Not {}: every one of the {} candidates was tried and none matched.",
                self.tool, self.space_size
            ),
            (None, StopReason::Cancelled) => format!(
                "Stopped at your request after {} of {} candidates. Nothing was ruled out. Resume from {}.",
                self.attempted, self.space_size, self.resume_from
            ),
            (None, StopReason::DeadlineReached) => format!(
                "Time limit reached after {} of {} candidates. Nothing was ruled out. Resume from {}.",
                self.attempted, self.space_size, self.resume_from
            ),
            (None, _) => format!(
                "Attempt limit reached after {} of {} candidates. Nothing was ruled out. Resume from {}.",
                self.attempted, self.space_size, self.resume_from
            ),
        }
    }
}

/// A matching candidate.
#[derive(Debug, Clone)]
pub struct Hit<E> {
    /// Index of the candidate within the probe's space.
    pub index: u64,
    /// How to describe the candidate to a human: the password that worked, the
    /// seed value, whatever the probe's space is made of.
    pub label: String,
    /// What the match revealed, which is the attribution evidence itself.
    pub evidence: E,
}

/// One tool's side of the search.
///
/// A probe is the trait boundary that keeps every tool's format knowledge out
/// of the search and every piece of search discipline out of the tools. It must
/// be cheap per candidate, free of side effects, and free of panics: the search
/// calls it from several threads at once and will not catch a crash for it.
pub trait Probe: Sync {
    /// What a match reveals.
    type Evidence: Send + Clone;

    /// The tool being looked for, for reports. A fixed string so a report can
    /// never attribute a file to a name assembled at runtime.
    fn tool(&self) -> &'static str;

    /// Size of the candidate space. Finite, always: a probe over a space it
    /// cannot count reports the largest range it is willing to search.
    fn space_size(&self) -> u64;

    /// Try candidate `index`. `Ok(None)` is an ordinary miss; `Err` is a real
    /// problem with the carrier or the candidate source and aborts the search
    /// loudly rather than being counted as a miss.
    fn try_candidate(&self, index: u64) -> Result<Option<Self::Evidence>, StegError>;

    /// How to name candidate `index` in a report.
    fn label(&self, index: u64) -> String;
}

/// Shared mutable search state. Separated out so the worker closure holds one
/// `Arc` rather than six.
struct Shared<E> {
    /// Next unclaimed candidate index.
    next: AtomicU64,
    /// Candidates examined.
    attempted: AtomicU64,
    /// Set when a worker hits an error, so the others stop promptly.
    failed: AtomicBool,
    /// Lowest-indexed hit found so far, and the first error seen.
    outcome: Mutex<Outcome<E>>,
    /// Chunk start currently being scanned by each worker, or `u64::MAX` when
    /// that worker holds no chunk. One slot per worker keeps the resume
    /// calculation exact without a set that grows with the search.
    in_flight: Vec<AtomicU64>,
}

struct Outcome<E> {
    hit: Option<Hit<E>>,
    error: Option<StegError>,
}

/// Acquire a mutex within [`LOCK_DEADLINE`], treating a poisoned lock as
/// recoverable (a worker that panicked while holding it has already been
/// reported through its own join error, and the data behind the lock is a plain
/// struct that cannot be left inconsistent).
fn lock_with_deadline<'a, T>(
    lock: &'a Mutex<T>,
) -> Result<std::sync::MutexGuard<'a, T>, StegError> {
    let deadline = Instant::now() + LOCK_DEADLINE;
    loop {
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(StegError::Internal(format!(
                        "the brute-force result lock was still held after {} seconds; \
                         the search has been abandoned rather than left waiting",
                        LOCK_DEADLINE.as_secs()
                    )));
                }
                std::thread::yield_now();
            }
        }
    }
}

/// Run a bounded search for `probe`.
///
/// `cancel` is polled between chunks, so a Ctrl+C reaches the search within one
/// chunk's work rather than at the end. `heartbeat` is called on the calling
/// thread at the configured interval while the search runs.
pub fn search<P, H>(
    probe: &P,
    limits: &SearchLimits,
    cancel: &Arc<AtomicBool>,
    mut heartbeat: H,
) -> Result<SearchReport<P::Evidence>, StegError>
where
    P: Probe,
    H: FnMut(&Progress),
{
    let space = probe.space_size();
    let start = limits.resume_from.min(space);
    let planned = limits.max_attempts.min(space.saturating_sub(start));
    let end = start.saturating_add(planned);
    let chunk = limits.chunk_size();
    let workers = limits.worker_count();
    let began = Instant::now();
    let wall_deadline = limits.deadline.map(|d| began + d);

    let shared: Arc<Shared<P::Evidence>> = Arc::new(Shared {
        next: AtomicU64::new(start),
        attempted: AtomicU64::new(0),
        failed: AtomicBool::new(false),
        outcome: Mutex::new(Outcome {
            hit: None,
            error: None,
        }),
        in_flight: (0..workers).map(|_| AtomicU64::new(u64::MAX)).collect(),
    });

    // `thread::scope` lets the workers borrow `probe` and the shared state
    // without `'static` bounds, and guarantees every worker is joined before
    // this function returns even on an early error.
    let deadline_hit = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for slot in 0..workers {
            let shared = Arc::clone(&shared);
            let cancel = Arc::clone(cancel);
            let deadline_hit = &deadline_hit;
            handles.push(scope.spawn(move || {
                worker(
                    probe,
                    &shared,
                    slot,
                    chunk,
                    end,
                    &cancel,
                    wall_deadline,
                    deadline_hit,
                );
            }));
        }

        // The calling thread is the heartbeat. It never blocks on a wait that
        // has no timeout: it sleeps in short fixed steps and checks state, so
        // cancellation and the deadline are honoured regardless of what the
        // workers are doing.
        let mut last_beat = Instant::now();
        let poll = Duration::from_millis(100);
        loop {
            let done = handles.iter().all(|h| h.is_finished());
            if done {
                break;
            }
            if last_beat.elapsed() >= limits.heartbeat {
                let attempted = shared.attempted.load(Ordering::Relaxed);
                let elapsed = began.elapsed();
                heartbeat(&Progress {
                    attempted,
                    planned,
                    elapsed,
                    rate_per_second: rate(attempted, elapsed),
                });
                last_beat = Instant::now();
            }
            std::thread::sleep(poll);
        }

        // Joining reports a worker crash rather than swallowing it. A probe is
        // required not to panic; if one did, that is a defect and the operator
        // needs to see it, not a silently short search.
        let mut crashed = 0usize;
        for handle in handles {
            if handle.join().is_err() {
                crashed += 1;
            }
        }
        if crashed > 0 {
            let mut guard = lock_with_deadline(&shared.outcome)?;
            if guard.error.is_none() {
                guard.error = Some(StegError::Internal(format!(
                    "{crashed} of {workers} brute-force workers crashed; the search result is \
                     incomplete and must not be read as a negative. This is a defect in the \
                     probe for this tool, not bad input."
                )));
            }
        }
        Ok::<(), StegError>(())
    })?;

    let attempted = shared.attempted.load(Ordering::Relaxed);
    let elapsed = began.elapsed();

    // Unwrap the Arc rather than cloning the evidence out from under the lock.
    let outcome = match Arc::try_unwrap(shared) {
        Ok(shared) => {
            let in_flight = shared.in_flight;
            let resume = lowest_unfinished(&in_flight, &shared.next, end);
            let inner = shared
                .outcome
                .into_inner()
                .unwrap_or_else(|p| p.into_inner());
            (inner, resume)
        }
        Err(_) => {
            return Err(StegError::Internal(
                "a brute-force worker outlived the search scope, which cannot happen; \
                 the result has been discarded rather than reported as a negative"
                    .into(),
            ))
        }
    };
    let (inner, resume_from) = outcome;
    if let Some(e) = inner.error {
        return Err(e);
    }

    let stop_reason = if inner.hit.is_some() {
        StopReason::Found
    } else if cancel.load(Ordering::Relaxed) {
        StopReason::Cancelled
    } else if deadline_hit.load(Ordering::Relaxed) {
        StopReason::DeadlineReached
    } else if end >= space && start == 0 {
        StopReason::Exhausted
    } else {
        StopReason::CapReached
    };

    Ok(SearchReport {
        tool: probe.tool(),
        hit: inner.hit,
        stop_reason,
        attempted,
        space_size: space,
        resume_from,
        elapsed,
        rate_per_second: rate(attempted, elapsed),
    })
}

fn rate(attempted: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    attempted as f64 / secs
}

/// The lowest candidate index not known to have been examined: the minimum of
/// every in-flight chunk start and the next unclaimed index.
fn lowest_unfinished(in_flight: &[AtomicU64], next: &AtomicU64, end: u64) -> u64 {
    let mut lowest = next.load(Ordering::Relaxed).min(end);
    for slot in in_flight {
        let held = slot.load(Ordering::Relaxed);
        if held != u64::MAX {
            lowest = lowest.min(held);
        }
    }
    lowest
}

#[allow(clippy::too_many_arguments)]
fn worker<P: Probe>(
    probe: &P,
    shared: &Shared<P::Evidence>,
    slot: usize,
    chunk: u64,
    end: u64,
    cancel: &AtomicBool,
    wall_deadline: Option<Instant>,
    deadline_hit: &AtomicBool,
) {
    loop {
        if cancel.load(Ordering::Relaxed) || shared.failed.load(Ordering::Relaxed) {
            return;
        }
        if let Some(deadline) = wall_deadline {
            if Instant::now() >= deadline {
                deadline_hit.store(true, Ordering::Relaxed);
                return;
            }
        }

        // Stop claiming work once a hit exists whose index is at or below every
        // remaining chunk. Claiming is strictly increasing, so any chunk that
        // could hold a lower index has already been claimed and will finish;
        // that is what makes the reported hit the lowest one regardless of the
        // order the threads happened to run in.
        if let Some(best) = current_best_index(shared) {
            if shared.next.load(Ordering::Relaxed) > best {
                return;
            }
        }

        let claimed = shared.next.fetch_add(chunk, Ordering::Relaxed);
        if claimed >= end {
            return;
        }
        let stop = claimed.saturating_add(chunk).min(end);
        shared.in_flight[slot].store(claimed, Ordering::Relaxed);

        // Counted rather than assumed: a chunk that stops early on a hit has
        // examined fewer candidates than it claimed, and the difference would
        // otherwise inflate the throughput figure the report quotes.
        let mut examined = 0u64;
        for index in claimed..stop {
            examined += 1;
            match probe.try_candidate(index) {
                Ok(None) => {}
                Ok(Some(evidence)) => {
                    record_hit(shared, probe, index, evidence);
                    break;
                }
                Err(e) => {
                    record_error(shared, e);
                    shared.failed.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        shared.attempted.fetch_add(examined, Ordering::Relaxed);
        shared.in_flight[slot].store(u64::MAX, Ordering::Relaxed);
    }
}

fn current_best_index<E>(shared: &Shared<E>) -> Option<u64> {
    // A contended read here only delays the stop decision by one chunk, so the
    // cheap non-blocking attempt is the right trade; correctness does not
    // depend on seeing the hit immediately.
    shared
        .outcome
        .try_lock()
        .ok()
        .and_then(|guard| guard.hit.as_ref().map(|h| h.index))
}

fn record_hit<P: Probe>(
    shared: &Shared<P::Evidence>,
    probe: &P,
    index: u64,
    evidence: P::Evidence,
) {
    match lock_with_deadline(&shared.outcome) {
        Ok(mut guard) => {
            let better = guard.hit.as_ref().map(|h| index < h.index).unwrap_or(true);
            if better {
                guard.hit = Some(Hit {
                    index,
                    label: probe.label(index),
                    evidence,
                });
            }
        }
        Err(e) => {
            // Losing a hit to a jammed lock would silently turn a positive into
            // a negative, which is the one failure this module must not have.
            shared.failed.store(true, Ordering::Relaxed);
            if let Ok(mut guard) = shared.outcome.try_lock() {
                if guard.error.is_none() {
                    guard.error = Some(e);
                }
            }
        }
    }
}

fn record_error<E>(shared: &Shared<E>, error: StegError) {
    if let Ok(mut guard) = lock_with_deadline(&shared.outcome) {
        if guard.error.is_none() {
            guard.error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe whose space is the integers and whose "tool signature" is a
    /// chosen set of indices. Lets the search be tested on its own terms.
    struct FakeProbe {
        size: u64,
        hits: Vec<u64>,
        fail_at: Option<u64>,
    }

    impl FakeProbe {
        fn new(size: u64, hits: &[u64]) -> Self {
            Self {
                size,
                hits: hits.to_vec(),
                fail_at: None,
            }
        }
    }

    impl Probe for FakeProbe {
        type Evidence = u64;
        fn tool(&self) -> &'static str {
            "FakeTool"
        }
        fn space_size(&self) -> u64 {
            self.size
        }
        fn try_candidate(&self, index: u64) -> Result<Option<u64>, StegError> {
            if self.fail_at == Some(index) {
                return Err(StegError::Internal("probe failed on purpose".into()));
            }
            Ok(self.hits.contains(&index).then_some(index * 2))
        }
        fn label(&self, index: u64) -> String {
            format!("candidate {index}")
        }
    }

    fn limits(max: u64) -> SearchLimits {
        SearchLimits {
            max_attempts: max,
            chunk: 16,
            threads: 4,
            ..Default::default()
        }
    }

    fn never_cancelled() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn finds_a_single_hit_and_reports_its_evidence() {
        let probe = FakeProbe::new(1000, &[777]);
        let report = search(&probe, &limits(1000), &never_cancelled(), |_| {}).unwrap();
        let hit = report.hit.expect("the hit at 777 should have been found");
        assert_eq!(hit.index, 777);
        assert_eq!(hit.evidence, 1554);
        assert_eq!(hit.label, "candidate 777");
        assert_eq!(report.stop_reason, StopReason::Found);
    }

    #[test]
    fn reports_the_lowest_hit_regardless_of_thread_count() {
        // The same space searched at one, two, three and eight threads must
        // return the same candidate. This is the determinism guarantee.
        for threads in [1usize, 2, 3, 8] {
            let probe = FakeProbe::new(5000, &[4000, 123, 2500, 99]);
            let mut lim = limits(5000);
            lim.threads = threads;
            let report = search(&probe, &lim, &never_cancelled(), |_| {}).unwrap();
            assert_eq!(
                report.hit.map(|h| h.index),
                Some(99),
                "thread count {threads} changed the answer"
            );
        }
    }

    #[test]
    fn exhausting_a_space_with_no_hit_is_a_conclusive_negative() {
        let probe = FakeProbe::new(500, &[]);
        let report = search(&probe, &limits(500), &never_cancelled(), |_| {}).unwrap();
        assert!(report.hit.is_none());
        assert_eq!(report.stop_reason, StopReason::Exhausted);
        assert!(report.stop_reason.is_conclusive_negative());
        assert_eq!(report.attempted, 500);
    }

    #[test]
    fn stopping_at_the_cap_is_not_a_negative() {
        let probe = FakeProbe::new(1_000_000, &[999_999]);
        let report = search(&probe, &limits(100), &never_cancelled(), |_| {}).unwrap();
        assert!(report.hit.is_none());
        assert_eq!(report.stop_reason, StopReason::CapReached);
        assert!(!report.stop_reason.is_conclusive_negative());
        assert_eq!(report.attempted, 100);
        assert!(report.summary().contains("Nothing was ruled out"));
    }

    #[test]
    fn a_cap_of_zero_examines_nothing_and_says_so() {
        let probe = FakeProbe::new(1000, &[1]);
        let report = search(&probe, &limits(0), &never_cancelled(), |_| {}).unwrap();
        assert_eq!(report.attempted, 0);
        assert!(report.hit.is_none());
        assert_eq!(report.resume_from, 0);
    }

    #[test]
    fn an_empty_space_is_exhausted_immediately() {
        let probe = FakeProbe::new(0, &[]);
        let report = search(&probe, &limits(10), &never_cancelled(), |_| {}).unwrap();
        assert_eq!(report.attempted, 0);
        assert_eq!(report.stop_reason, StopReason::Exhausted);
    }

    #[test]
    fn resuming_from_a_cursor_skips_the_earlier_range() {
        let probe = FakeProbe::new(1000, &[10, 900]);
        let mut lim = limits(1000);
        lim.resume_from = 500;
        let report = search(&probe, &lim, &never_cancelled(), |_| {}).unwrap();
        assert_eq!(report.hit.map(|h| h.index), Some(900));
        // A resumed run has not seen the whole space, so it cannot be an
        // exhaustive negative even though it reached the end.
        assert_eq!(report.stop_reason, StopReason::Found);
    }

    #[test]
    fn a_resumed_miss_is_never_reported_as_exhausted() {
        let probe = FakeProbe::new(1000, &[10]);
        let mut lim = limits(1000);
        lim.resume_from = 500;
        let report = search(&probe, &lim, &never_cancelled(), |_| {}).unwrap();
        assert!(report.hit.is_none());
        assert_eq!(report.stop_reason, StopReason::CapReached);
        assert!(!report.stop_reason.is_conclusive_negative());
    }

    #[test]
    fn cancellation_stops_the_search_and_reports_a_resume_point() {
        let cancel = Arc::new(AtomicBool::new(true));
        let probe = FakeProbe::new(10_000_000, &[9_000_000]);
        let report = search(&probe, &limits(10_000_000), &cancel, |_| {}).unwrap();
        assert!(report.hit.is_none());
        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert!(report.summary().contains("Stopped at your request"));
    }

    #[test]
    fn a_probe_error_aborts_loudly_rather_than_counting_as_a_miss() {
        let probe = FakeProbe {
            size: 1000,
            hits: vec![],
            fail_at: Some(50),
        };
        let err = search(&probe, &limits(1000), &never_cancelled(), |_| {}).unwrap_err();
        assert!(err.to_string().contains("probe failed on purpose"));
    }

    #[test]
    fn a_deadline_stops_the_search() {
        struct SlowProbe;
        impl Probe for SlowProbe {
            type Evidence = ();
            fn tool(&self) -> &'static str {
                "SlowTool"
            }
            fn space_size(&self) -> u64 {
                u64::MAX
            }
            fn try_candidate(&self, _index: u64) -> Result<Option<()>, StegError> {
                std::thread::sleep(Duration::from_millis(2));
                Ok(None)
            }
            fn label(&self, index: u64) -> String {
                index.to_string()
            }
        }
        let lim = SearchLimits {
            max_attempts: u64::MAX,
            chunk: 1,
            threads: 2,
            deadline: Some(Duration::from_millis(200)),
            ..Default::default()
        };
        let report = search(&SlowProbe, &lim, &never_cancelled(), |_| {}).unwrap();
        assert_eq!(report.stop_reason, StopReason::DeadlineReached);
        assert!(report.summary().contains("Time limit reached"));
    }

    #[test]
    fn the_heartbeat_fires_on_a_long_search() {
        struct SlowProbe;
        impl Probe for SlowProbe {
            type Evidence = ();
            fn tool(&self) -> &'static str {
                "SlowTool"
            }
            fn space_size(&self) -> u64 {
                u64::MAX
            }
            fn try_candidate(&self, _index: u64) -> Result<Option<()>, StegError> {
                std::thread::sleep(Duration::from_millis(2));
                Ok(None)
            }
            fn label(&self, index: u64) -> String {
                index.to_string()
            }
        }
        let beats = Mutex::new(0usize);
        let lim = SearchLimits {
            max_attempts: u64::MAX,
            chunk: 1,
            threads: 1,
            heartbeat: Duration::from_millis(120),
            deadline: Some(Duration::from_millis(600)),
            ..Default::default()
        };
        let report = search(&SlowProbe, &lim, &never_cancelled(), |p| {
            assert!(p.fraction() >= 0.0);
            if let Ok(mut n) = beats.lock() {
                *n += 1;
            }
        })
        .unwrap();
        assert!(report.rate_per_second > 0.0);
        let fired = *beats.lock().unwrap();
        assert!(fired >= 1, "expected at least one heartbeat, saw {fired}");
    }

    #[test]
    fn worker_and_chunk_counts_are_clamped_into_a_usable_band() {
        let zero = SearchLimits {
            threads: 0,
            chunk: 0,
            ..Default::default()
        };
        assert!(zero.worker_count() >= 1);
        assert_eq!(zero.chunk_size(), 1);

        let absurd = SearchLimits {
            threads: 100_000,
            chunk: u64::MAX,
            ..Default::default()
        };
        assert_eq!(absurd.worker_count(), 256);
        assert_eq!(absurd.chunk_size(), 1 << 24);
    }

    #[test]
    fn progress_fraction_is_bounded_and_defined_for_an_empty_plan() {
        let empty = Progress {
            attempted: 0,
            planned: 0,
            elapsed: Duration::from_secs(1),
            rate_per_second: 0.0,
        };
        assert_eq!(empty.fraction(), 1.0);
        let over = Progress {
            attempted: 50,
            planned: 10,
            elapsed: Duration::from_secs(1),
            rate_per_second: 0.0,
        };
        assert_eq!(over.fraction(), 1.0);
    }

    #[test]
    fn rate_is_zero_rather_than_infinite_for_a_zero_duration() {
        assert_eq!(rate(100, Duration::ZERO), 0.0);
    }

    #[test]
    fn a_resume_point_is_never_past_an_unfinished_chunk() {
        let in_flight = vec![AtomicU64::new(u64::MAX), AtomicU64::new(300)];
        let next = AtomicU64::new(900);
        assert_eq!(lowest_unfinished(&in_flight, &next, 1000), 300);
        let idle = vec![AtomicU64::new(u64::MAX)];
        assert_eq!(lowest_unfinished(&idle, &AtomicU64::new(1500), 1000), 1000);
    }

    #[test]
    fn an_uncontended_lock_is_acquired_and_a_poisoned_one_recovered() {
        let lock = Mutex::new(5u32);
        assert_eq!(*lock_with_deadline(&lock).unwrap(), 5);

        let poisoned = Arc::new(Mutex::new(7u32));
        let clone = Arc::clone(&poisoned);
        let _ = std::thread::spawn(move || {
            let _guard = clone.lock().unwrap();
            panic!("poisoning on purpose");
        })
        .join();
        assert_eq!(*lock_with_deadline(&poisoned).unwrap(), 7);
    }
}
