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

//! Streaming steganalysis for audio.
//!
//! # Why this module exists rather than an extension of `analysis.rs`
//!
//! The existing audio path does not work, and this was measured on 2026-10-01
//! rather than suspected:
//!
//! - **`audio_spa_test` returns exactly `0.000000` for every input.** It calls
//!   the image detector as `spa_score(&bytes, bytes.len())`, so the stride is
//!   `3 * len` and the guard `pixels.len() < stride * 2` reads `len < 6 * len`,
//!   which is true for every non-empty input. The function returns before doing
//!   any work. Measured on a clean cover and the same cover with 100% of its
//!   LSBs replaced: both scored 0.000000.
//! - **The audio verdict fires on clean audio.** Nine real recordings from the
//!   system sound theme, all provably clean, scored 4 `likely_stego` and 5
//!   `suspicious`, with zero clean verdicts. Chi-squared reached 1.0000 on a
//!   genuine noise recording. The thresholds in use are image thresholds, and a
//!   16-bit audio LSB plane is near-random by construction because the
//!   quantisation noise floor is random, so an image LSB-entropy test cannot
//!   distinguish anything on audio.
//!
//! So the job is not to add a detector beside those. It is to compute audio
//! statistics correctly, in one streaming pass, and to publish **no thresholds at
//! all** until `private/calibration/` has fitted them against a documented
//! false-positive ceiling. Everything here returns raw measurements. A verdict
//! built on a guessed threshold is how the measurement above happened.
//!
//! # Streaming by construction
//!
//! Operator decision, 2026-10-01: audio has no user-visible size limit, so the
//! samples are streamed rather than collected and capped. Every accumulator in
//! this module is fixed-size, and the only allocation that scales with anything
//! is one histogram per channel whose size depends on the **bit depth**, never on
//! the file length. A four hour recording and a four second one use the same
//! memory.
//!
//! ```text
//!   any sample iterator ──► SampleSource ──► AudioAccumulator ──► AudioStatistics
//!                            (a trait)        (fixed memory)       (raw numbers)
//! ```
//!
//! `SampleSource` is a trait and `analyse_stream` is generic over it, so this
//! module is coupled to no particular reader. A WAV reader, a FLAC reader or a
//! test slice all feed it the same way, and replacing a reader with a streaming
//! one is not a change here.

use crate::errors::StegError;

/// Interleaved audio samples, delivered in chunks.
///
/// Chunked rather than one sample at a time because a per-sample virtual call
/// over a hundred million samples is the whole cost of the pass, and chunked
/// rather than all-at-once because that is the allocation this module exists not
/// to make.
pub trait SampleSource {
    /// Fill `out` with the next interleaved samples and return how many were
    /// written. `Ok(0)` means the stream is finished.
    ///
    /// A partial fill does **not** mean the end: a reader is free to return a
    /// short chunk at a frame or block boundary, and the caller keeps going until
    /// it sees zero.
    fn read_chunk(&mut self, out: &mut [i32]) -> Result<usize, StegError>;

    /// Channel count. Load bearing: statistics are per channel, and interleaved
    /// samples from different channels are not adjacent in any meaningful sense.
    fn channels(&self) -> usize;

    /// Bits per sample, which sets the histogram width and nothing else.
    fn bits_per_sample(&self) -> u16;
}

/// A `SampleSource` over a slice. For tests and for a caller that already holds
/// decoded samples; it is not the path a large file should take.
pub struct SliceSource<'a> {
    samples: &'a [i32],
    position: usize,
    channels: usize,
    bits: u16,
}

impl<'a> SliceSource<'a> {
    /// `channels` of 0 is corrected to 1 rather than refused, because a reader
    /// that reports no channels has already failed and the caller gets a better
    /// message from the statistics being empty than from a panic here.
    pub fn new(samples: &'a [i32], channels: usize, bits: u16) -> Self {
        Self {
            samples,
            position: 0,
            channels: channels.max(1),
            bits,
        }
    }
}

impl SampleSource for SliceSource<'_> {
    fn read_chunk(&mut self, out: &mut [i32]) -> Result<usize, StegError> {
        let remaining = self.samples.len().saturating_sub(self.position);
        let take = remaining.min(out.len());
        out[..take].copy_from_slice(&self.samples[self.position..self.position + take]);
        self.position += take;
        Ok(take)
    }

    fn channels(&self) -> usize {
        self.channels
    }

    fn bits_per_sample(&self) -> u16 {
        self.bits
    }
}

/// Limits, all independent of file length.
pub mod limits {
    /// Samples per chunk. 64Ki samples is 256 KiB of `i32`, which stays inside a
    /// typical L2 cache so the pass is memory-bandwidth bound rather than
    /// cache-miss bound, and it is small enough that a reader's own buffer
    /// dominates nothing.
    pub const CHUNK_SAMPLES: usize = 65_536;

    /// Channels beyond this are folded into the last bucket rather than
    /// allocating per channel without bound. Ambisonic and object-based formats
    /// genuinely reach dozens of channels; a file claiming thousands is either
    /// malformed or hostile, and either way per-channel statistics stop being
    /// meaningful long before that.
    pub const MAX_TRACKED_CHANNELS: usize = 64;

    /// Widest histogram, in bins. A pair histogram over 16-bit samples needs
    /// 32,768 bins, which is 128 KiB per channel. Above 16 bits the top bits are
    /// folded down to this width: a 24-bit pair histogram would be 32 MiB per
    /// channel, and the statistic it feeds does not improve for having 256 times
    /// more, mostly empty, bins.
    pub const MAX_HISTOGRAM_BINS: usize = 1 << 15;
}

/// Raw measurements from one pass. **No thresholds, no confidence, no verdict.**
///
/// Every field is a number a calibration run can fit a threshold to. Nothing here
/// decides anything, which is deliberate: the audio verdict that shipped before
/// this module was wrong on 9 of 9 clean recordings precisely because image
/// thresholds were applied to audio statistics without a calibration step.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioStatistics {
    /// Samples examined, summed over channels.
    pub samples: u64,
    /// Channels actually tracked, which is `min(channels, MAX_TRACKED_CHANNELS)`.
    pub channels: usize,
    /// Bit depth as the reader reported it.
    pub bits_per_sample: u16,
    /// One entry per tracked channel.
    pub per_channel: Vec<ChannelStatistics>,
}

/// One channel's measurements.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelStatistics {
    /// Zero based channel index.
    pub channel: usize,
    /// Samples in this channel.
    pub samples: u64,
    /// Fraction of samples whose least significant bit is set. A clean recording
    /// sits near 0.5 and so does a fully embedded one, which is why this is
    /// reported as context and is not a detector on its own.
    pub lsb_ones_fraction: f64,
    /// Chi-squared statistic over pairs of values `(2k, 2k+1)`.
    ///
    /// LSB **replacement** equalises the two members of each pair, because the
    /// bit written is uniform and independent of the sample. So an embedded
    /// stream drives this statistic down towards zero while a clean recording
    /// leaves it large. Reported as the statistic itself, not as a p-value: the
    /// degrees of freedom depend on how many pairs were actually populated, and
    /// that number is reported beside it.
    pub chi_squared: f64,
    /// Populated pairs, which is the degrees of freedom for `chi_squared`.
    pub chi_squared_pairs: u64,
    /// Embedding rate estimated by Sample Pair Analysis over temporally adjacent
    /// samples in this channel.
    ///
    /// This is the audio analogue of the image detector's vertically adjacent
    /// pixel pairs: temporally adjacent samples in one channel are the pairs with
    /// a natural correlation to exploit. Interleaved neighbours belong to
    /// different channels and are not pairs in any useful sense, which is one of
    /// the two reasons the previous implementation could not have worked.
    pub spa_alpha: f64,
    /// Pairs the SPA estimate was computed from.
    pub spa_pairs: u64,
    /// Samples lying in a run whose bits above the LSB are constant. See
    /// [`ChannelStatistics::silence_lsb_flip_fraction`].
    pub constant_run_samples: u64,
    /// Among samples in a constant-upper-bits run, the fraction whose LSB differs
    /// from the first LSB of that run.
    ///
    /// **This is the detector with no image analogue, and the reason it should be
    /// strong where the statistical tests are hopeless.** A passage where every
    /// bit above the LSB is identical is a passage where the signal is not
    /// changing at all: digital silence, a clipped region, a synthesised tone
    /// held flat. In such a run the LSB cannot vary for any acoustic reason, so a
    /// varying LSB there is something written into it. Tools that fill every
    /// sample, DeepSound among them, write into silence like anywhere else.
    ///
    /// The false positive the test has to survive is a **dithered master**, where
    /// a passage a listener calls silent carries deliberate low-level noise. That
    /// case is excluded by construction rather than by a threshold: dither moves
    /// the bits above the LSB, so those samples are not in a constant-upper-bits
    /// run and never enter this statistic. `constant_run_samples` says how much of
    /// the file qualified, and a file where that is zero carries no claim here at
    /// all.
    pub silence_lsb_flip_fraction: f64,
    /// Longest constant-upper-bits run seen, in samples. Context for the number
    /// above: a flip fraction measured over runs of three samples is noise, and
    /// one measured over a run of fifty thousand is not.
    pub longest_constant_run: u64,
    /// Mean absolute difference between temporally adjacent samples.
    pub adjacent_delta_mean_abs: f64,
    /// Sample standard deviation of this channel's values.
    pub standard_deviation: f64,
    /// `adjacent_delta_mean_abs / standard_deviation`, or 0.0 when the channel is
    /// silent. **This is the number that says whether `spa_alpha` can be believed.**
    ///
    /// Sample Pair Analysis assumes the two members of a pair are close in value;
    /// its trace sets carry no information otherwise. For independent samples the
    /// mean absolute difference is a fixed multiple of the standard deviation:
    /// `2/sqrt(pi) ≈ 1.128` for Gaussian noise and `2/sqrt(3) / ... ≈ 1.155` for
    /// uniform noise (measured: 1.158 on a uniform generator). Correlated audio is
    /// far below that, because neighbouring samples barely move.
    ///
    /// Measured on 2026-10-01 against nine real recordings: on the eight with
    /// ordinary musical or speech content, `spa_alpha` sat in [-0.24, +0.09] when
    /// clean and rose monotonically to between 0.91 and 1.02 at a fully replaced
    /// LSB plane. On the ninth, a pure white-noise recording, it was 0.60 when
    /// clean and **-2.18** when fully embedded: not merely wrong but wrong in the
    /// opposite direction. That file is distinguished from the other eight by this
    /// ratio and by nothing else, which is why it is reported.
    ///
    /// No threshold is set here. The calibration run decides where the ratio makes
    /// `spa_alpha` unusable, against a documented false-positive ceiling.
    pub roughness: f64,
}

/// Fixed-memory accumulator. Feed it chunks; it never grows.
struct ChannelAccumulator {
    samples: u64,
    lsb_ones: u64,

    /// Pair histogram: `pairs[k]` counts samples whose value maps to pair `k`.
    /// Two counters per pair, so even and odd members are separable.
    pair_even: Vec<u32>,
    pair_odd: Vec<u32>,

    /// Sample Pair Analysis trace-set counts, exactly the Dumitrescu, Wu and Wang
    /// quantities the image detector accumulates, over temporally adjacent pairs.
    spa_x: i64,
    spa_y: i64,
    spa_k: i64,
    spa_pairs: i64,

    /// Previous sample in this channel, carried across chunk boundaries. Without
    /// this the pair at every chunk boundary is lost, which for a 64Ki chunk is a
    /// small bias and for a tiny chunk is a large one; carrying it makes the
    /// result independent of chunk size, which is a property worth having and is
    /// tested.
    previous: Option<i32>,

    /// Neighbour roughness, accumulated streaming. `i128` because a 16-bit
    /// sample squared is 2^30 and a four hour stereo recording is 6.4e8 samples
    /// per channel, so an `i64` sum of squares would be within a factor of 40 of
    /// overflow at 24 bits. `i128` removes the question entirely.
    sum: i128,
    sum_squares: i128,
    sum_abs_delta: u128,

    /// Current constant-upper-bits run.
    run_upper: Option<i32>,
    run_first_lsb: u8,
    run_length: u64,
    constant_run_samples: u64,
    constant_run_flips: u64,
    longest_constant_run: u64,
}

/// Minimum run length before a constant-upper-bits run contributes.
///
/// Two adjacent samples sharing their upper bits happens constantly by chance in
/// quiet passages of any recording, and counting those would turn the silence
/// test into a measurement of how quiet the file is. A run of 16 is long enough
/// that chance is negligible at any realistic amplitude and short enough that a
/// payload hidden in a short silence is still caught.
const MIN_CONSTANT_RUN: u64 = 16;

impl ChannelAccumulator {
    fn new(channel_bins: usize) -> Self {
        Self {
            samples: 0,
            lsb_ones: 0,
            pair_even: vec![0; channel_bins],
            pair_odd: vec![0; channel_bins],
            spa_x: 0,
            spa_y: 0,
            spa_k: 0,
            spa_pairs: 0,
            sum: 0,
            sum_squares: 0,
            sum_abs_delta: 0,
            previous: None,
            run_upper: None,
            run_first_lsb: 0,
            run_length: 0,
            constant_run_samples: 0,
            constant_run_flips: 0,
            longest_constant_run: 0,
        }
    }

    fn push(&mut self, sample: i32, bin_shift: u32, bins: usize) {
        self.samples += 1;
        let lsb = (sample & 1) as u8;
        self.lsb_ones += u64::from(lsb);

        // Pair index. The shift folds depths above 16 bits down to the histogram
        // width; at 16 bits and below it is zero and this is the exact pair index.
        let folded = (sample >> 1) >> bin_shift;
        // Wrapping into range rather than dropping out-of-range samples: a sample
        // outside the depth the reader declared is a reader bug, and silently
        // discarding it would understate every count instead of showing up.
        let index = (folded.rem_euclid(bins as i32)) as usize;
        if lsb == 0 {
            self.pair_even[index] = self.pair_even[index].saturating_add(1);
        } else {
            self.pair_odd[index] = self.pair_odd[index].saturating_add(1);
        }

        self.sum += i128::from(sample);
        self.sum_squares += i128::from(sample) * i128::from(sample);

        // Sample Pair Analysis over the temporally adjacent pair.
        if let Some(previous) = self.previous {
            let r = previous;
            let s = sample;
            self.spa_pairs += 1;
            self.sum_abs_delta += u128::from((i64::from(s) - i64::from(r)).unsigned_abs());
            let s_even = (s & 1) == 0;
            let r_lt = r < s;
            let r_gt = r > s;
            if (s_even && r_lt) || (!s_even && r_gt) {
                self.spa_x += 1;
            }
            if (s_even && r_gt) || (!s_even && r_lt) {
                self.spa_y += 1;
            }
            if (r & !1) == (s & !1) {
                self.spa_k += 1;
            }
        }
        self.previous = Some(sample);

        // Constant-upper-bits run tracking.
        let upper = sample >> 1;
        match self.run_upper {
            Some(current) if current == upper => {
                self.run_length += 1;
                if self.run_length == MIN_CONSTANT_RUN {
                    // The run has just qualified, so everything in it so far
                    // counts, including the samples seen before it qualified.
                    self.constant_run_samples += MIN_CONSTANT_RUN;
                } else if self.run_length > MIN_CONSTANT_RUN {
                    self.constant_run_samples += 1;
                }
                if self.run_length >= MIN_CONSTANT_RUN && lsb != self.run_first_lsb {
                    self.constant_run_flips += 1;
                }
                self.longest_constant_run = self.longest_constant_run.max(self.run_length);
            }
            _ => {
                self.run_upper = Some(upper);
                self.run_first_lsb = lsb;
                self.run_length = 1;
                self.longest_constant_run = self.longest_constant_run.max(1);
            }
        }
    }

    /// Chi-squared over pair counts. Only populated pairs contribute, and the
    /// count of them is returned so the caller can report the degrees of freedom
    /// rather than implying a distribution it did not check.
    fn chi_squared(&self) -> (f64, u64) {
        let mut chi = 0.0f64;
        let mut used = 0u64;
        for (&even, &odd) in self.pair_even.iter().zip(self.pair_odd.iter()) {
            let total = u64::from(even) + u64::from(odd);
            // A pair needs both members possible for the statistic to mean
            // anything, and a pair seen once carries no information at all.
            if total < 2 {
                continue;
            }
            let expected = total as f64 / 2.0;
            let diff = f64::from(even) - expected;
            chi += (diff * diff) / expected;
            used += 1;
        }
        (chi, used)
    }

    /// The Dumitrescu, Wu and Wang quadratic, identical in form to the image
    /// detector's so the two are comparable by construction.
    fn spa_alpha(&self) -> f64 {
        if self.spa_k == 0 || self.spa_pairs == 0 {
            return 0.0;
        }
        let a = (2 * self.spa_k) as f64;
        let b = (2 * (2 * self.spa_x - self.spa_pairs)) as f64;
        let c = (self.spa_y - self.spa_x) as f64;
        let disc = b * b - 4.0 * a * c;
        let beta = if disc < 0.0 {
            -b / (2.0 * a)
        } else {
            (-b - disc.sqrt()) / (2.0 * a)
        };
        2.0 * beta
    }

    /// Sample standard deviation, with Bessel's correction, from the streaming
    /// sums. Computed in `f64` at the end rather than incrementally so the result
    /// does not depend on the order samples arrived in, which is a reproducibility
    /// requirement and not a style preference.
    fn standard_deviation(&self) -> f64 {
        if self.samples < 2 {
            return 0.0;
        }
        let n = self.samples as f64;
        let mean = self.sum as f64 / n;
        let variance = (self.sum_squares as f64 - n * mean * mean) / (n - 1.0);
        variance.max(0.0).sqrt()
    }

    fn finish(&self, channel: usize) -> ChannelStatistics {
        let (chi_squared, chi_squared_pairs) = self.chi_squared();
        let sd = self.standard_deviation();
        let delta = if self.spa_pairs == 0 {
            0.0
        } else {
            self.sum_abs_delta as f64 / self.spa_pairs as f64
        };
        ChannelStatistics {
            channel,
            samples: self.samples,
            lsb_ones_fraction: if self.samples == 0 {
                0.0
            } else {
                self.lsb_ones as f64 / self.samples as f64
            },
            chi_squared,
            chi_squared_pairs,
            spa_alpha: self.spa_alpha(),
            spa_pairs: self.spa_pairs.max(0) as u64,
            constant_run_samples: self.constant_run_samples,
            silence_lsb_flip_fraction: if self.constant_run_samples == 0 {
                0.0
            } else {
                self.constant_run_flips as f64 / self.constant_run_samples as f64
            },
            longest_constant_run: self.longest_constant_run,
            adjacent_delta_mean_abs: delta,
            standard_deviation: sd,
            roughness: if sd > 0.0 { delta / sd } else { 0.0 },
        }
    }
}

/// Measure one audio stream in a single pass.
///
/// Memory is `O(channels * histogram_bins)` and independent of stream length.
///
/// # Errors
///
/// Propagates whatever the source reports. Nothing here fails on its own: a
/// stream with no samples produces statistics saying so rather than an error,
/// because "this file has no audio to measure" is a measurement and the caller
/// decides what it means.
pub fn analyse_stream<S: SampleSource>(mut source: S) -> Result<AudioStatistics, StegError> {
    let declared_channels = source.channels().max(1);
    let channels = declared_channels.min(limits::MAX_TRACKED_CHANNELS);
    let bits = source.bits_per_sample();

    // Histogram width from the bit depth, never from the file. A pair index needs
    // one bit fewer than the sample depth, since the LSB is the thing being
    // counted rather than indexed.
    let pair_bits = u32::from(bits).saturating_sub(1).max(1);
    let wanted = 1usize.checked_shl(pair_bits.min(31)).unwrap_or(usize::MAX);
    let bins = wanted.clamp(2, limits::MAX_HISTOGRAM_BINS);
    let bin_shift = pair_bits.saturating_sub(bins.trailing_zeros());

    let mut accumulators: Vec<ChannelAccumulator> = (0..channels)
        .map(|_| ChannelAccumulator::new(bins))
        .collect();

    let mut buffer = vec![0i32; limits::CHUNK_SAMPLES];
    // Interleaving position carried across chunks. A chunk boundary that does not
    // land on a frame boundary would otherwise rotate every channel assignment
    // from that point on, which is the kind of bug that shows up as "the right
    // numbers attached to the wrong channel".
    let mut offset = 0usize;
    loop {
        let filled = source.read_chunk(&mut buffer)?;
        if filled == 0 {
            break;
        }
        for &sample in &buffer[..filled] {
            let channel = offset % declared_channels;
            offset += 1;
            if channel < channels {
                accumulators[channel].push(sample, bin_shift, bins);
            }
        }
    }

    let per_channel: Vec<ChannelStatistics> = accumulators
        .iter()
        .enumerate()
        .map(|(i, a)| a.finish(i))
        .collect();
    Ok(AudioStatistics {
        samples: per_channel.iter().map(|c| c.samples).sum(),
        channels,
        bits_per_sample: bits,
        per_channel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random generator, so the tests do not depend on a
    /// crate and two runs agree exactly.
    struct Lcg(u64);

    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            // The full top 32 bits. An earlier version shifted by 33, so every
            // draw was below 2^31 and a `rate` of 0.5 behaved like 1.0, which made
            // two different payloads produce byte-identical statistics and looked
            // like a detector bug rather than a test bug.
            (self.0 >> 32) as u32
        }
    }

    /// A synthetic cover with the property real audio has and white noise does
    /// not: **adjacent samples are strongly correlated**.
    ///
    /// This matters more than it looks. Sample Pair Analysis is built on the
    /// assumption that the two members of a pair are close in value, so its trace
    /// sets carry information. An earlier version of this helper was a random walk
    /// with steps up to 48, which violates that badly enough that the estimator
    /// returned -0.41 on a clean stream and did not order by payload at all. That
    /// was the test's cover being unlike audio, not the detector being wrong, and
    /// it is why the real recordings are measured separately in the lane notes.
    ///
    /// Here the noise is low-pass filtered and the step between neighbours is a
    /// handful of counts, which is what 44.1 kHz audio looks like.
    fn synthetic_cover(n: usize, seed: u64) -> Vec<i32> {
        let mut lcg = Lcg(seed);
        let mut out = Vec::with_capacity(n);
        let mut smooth = 0.0f64;
        for i in 0..n {
            let noise = (lcg.next_u32() % 2001) as f64 - 1000.0;
            // A one pole low pass. The coefficient sets how correlated neighbours
            // are; 0.02 gives a step of a few counts, like real audio.
            smooth = smooth * 0.98 + noise * 0.02;
            let tone = (i as f64 / 211.0).sin() * 4000.0;
            out.push((smooth * 8.0 + tone) as i32);
        }
        out
    }

    /// LSB replacement over a fraction of samples.
    fn embed(samples: &[i32], rate: f64, seed: u64) -> Vec<i32> {
        let mut lcg = Lcg(seed);
        samples
            .iter()
            .map(|&s| {
                let pick = f64::from(lcg.next_u32()) / f64::from(u32::MAX);
                if pick < rate {
                    let bit = (lcg.next_u32() & 1) as i32;
                    (s & !1) | bit
                } else {
                    s
                }
            })
            .collect()
    }

    fn stats(samples: &[i32], channels: usize) -> AudioStatistics {
        analyse_stream(SliceSource::new(samples, channels, 16)).expect("analyse")
    }

    #[test]
    fn an_empty_stream_measures_as_empty_rather_than_failing() {
        let s = stats(&[], 1);
        assert_eq!(s.samples, 0);
        assert_eq!(s.per_channel.len(), 1);
        assert_eq!(s.per_channel[0].spa_pairs, 0);
        assert_eq!(s.per_channel[0].silence_lsb_flip_fraction, 0.0);
        assert_eq!(s.per_channel[0].lsb_ones_fraction, 0.0);
    }

    #[test]
    fn the_result_does_not_depend_on_chunk_size() {
        // The property that makes streaming equivalent to a single buffer. If the
        // carried state at a chunk boundary were dropped, this would differ and
        // the whole module's numbers would depend on a buffer size.
        struct Dribble<'a> {
            samples: &'a [i32],
            position: usize,
            step: usize,
        }
        impl SampleSource for Dribble<'_> {
            fn read_chunk(&mut self, out: &mut [i32]) -> Result<usize, StegError> {
                let take = (self.samples.len() - self.position)
                    .min(self.step)
                    .min(out.len());
                out[..take].copy_from_slice(&self.samples[self.position..self.position + take]);
                self.position += take;
                Ok(take)
            }
            fn channels(&self) -> usize {
                2
            }
            fn bits_per_sample(&self) -> u16 {
                16
            }
        }

        let cover = synthetic_cover(20_000, 11);
        let whole = stats(&cover, 2);
        for step in [1usize, 3, 7, 1024] {
            let dribbled = analyse_stream(Dribble {
                samples: &cover,
                position: 0,
                step,
            })
            .expect("analyse");
            assert_eq!(dribbled, whole, "chunk size {step} changed the result");
        }
    }

    #[test]
    fn analysis_is_deterministic() {
        let cover = synthetic_cover(10_000, 3);
        assert_eq!(stats(&cover, 1), stats(&cover, 1));
    }

    #[test]
    fn channels_are_deinterleaved_rather_than_mixed() {
        // Channel 0 all even, channel 1 all odd. If the interleaving were wrong
        // both channels would read as half and half.
        let mut samples = Vec::new();
        for i in 0..1000 {
            samples.push(i * 2);
            samples.push(i * 2 + 1);
        }
        let s = stats(&samples, 2);
        assert_eq!(s.channels, 2);
        assert_eq!(s.per_channel[0].lsb_ones_fraction, 0.0);
        assert_eq!(s.per_channel[1].lsb_ones_fraction, 1.0);
        assert_eq!(s.per_channel[0].samples, 1000);
        assert_eq!(s.per_channel[1].samples, 1000);
    }

    /// A cover whose LSB is a deterministic function of the bits above it, which
    /// is what "LSB structure" means. Real audio at 16 bits mostly does not have
    /// this: its LSB plane is close to uniform because the quantisation noise
    /// floor is random. That is a measurement about real audio, reported in the
    /// lane notes, and it is why the pair chi-squared is weak there rather than
    /// why it is wrong.
    fn structured_cover(n: usize, seed: u64) -> Vec<i32> {
        synthetic_cover(n, seed)
            .into_iter()
            .map(|s| (s & !1) | ((s >> 3) & 1))
            .collect()
    }

    #[test]
    fn lsb_replacement_destroys_lsb_structure_and_the_chi_squared_statistic_shows_it() {
        // What this detector actually measures: LSB replacement writes a uniform
        // bit independent of the sample, so it equalises the two members of each
        // value pair and erases whatever structure was there. On a cover WITH
        // structure the statistic must fall monotonically with the payload.
        //
        // Direction only. No magnitude is asserted, because a magnitude is a
        // threshold and thresholds are calibrated against a corpus at a documented
        // false-positive ceiling, never written into a test.
        let cover = structured_cover(60_000, 5);
        let clean = stats(&cover, 1).per_channel[0].chi_squared;
        let half = stats(&embed(&cover, 0.5, 9), 1).per_channel[0].chi_squared;
        let full = stats(&embed(&cover, 1.0, 9), 1).per_channel[0].chi_squared;
        assert!(
            clean > half && half > full,
            "chi-squared did not fall monotonically with payload: clean {clean:.1}, \
             half {half:.1}, full {full:.1}"
        );
    }

    #[test]
    fn the_embed_helper_really_embeds_different_amounts() {
        // Non-vacuity for every test above that compares two payload rates. An
        // earlier RNG bug made 0.5 and 1.0 identical, which hid a real failure
        // behind a passing-looking comparison.
        let cover = synthetic_cover(20_000, 29);
        let differ = |a: &[i32], b: &[i32]| a.iter().zip(b).filter(|(x, y)| x != y).count();
        let quarter = differ(&cover, &embed(&cover, 0.25, 9));
        let half = differ(&cover, &embed(&cover, 0.5, 9));
        let full = differ(&cover, &embed(&cover, 1.0, 9));
        // Each rate flips roughly half the samples it touches, since a random bit
        // matches the original half the time.
        assert!(quarter < half && half < full, "{quarter} {half} {full}");
        assert!(
            full > 8_000,
            "a full-rate embed only changed {full} samples"
        );
    }

    #[test]
    fn sample_pair_analysis_estimates_a_rate_that_rises_with_the_payload() {
        // The thing the previous implementation could not do at all: produce a
        // non-zero number. And it must ORDER correctly, which is what makes it an
        // estimator rather than a flag.
        //
        // The ordering claim is asserted on a cover whose roughness resembles real
        // audio, because that is the regime the estimator is valid in, and the
        // adjacent test pins the regime itself rather than taking it on trust.
        let cover = synthetic_cover(80_000, 13);
        let quarter = stats(&embed(&cover, 0.25, 21), 1).per_channel[0].spa_alpha;
        let full = stats(&embed(&cover, 1.0, 21), 1).per_channel[0].spa_alpha;
        assert!(
            full > 0.5,
            "SPA returned {full} on a fully replaced LSB plane; on nine real \
             recordings it reached 0.91 to 1.02 there"
        );
        assert!(
            quarter < full,
            "SPA did not order by payload: quarter {quarter:.4}, full {full:.4}"
        );
        // NOT asserted here: that a CLEAN stream reads near zero. On this synthetic
        // cover it reads 0.53, and that is the cover rather than the detector: the
        // low-pass filter makes neighbours so close that `k`, the count of pairs
        // sharing their upper bits, dominates the quadratic. On the nine real
        // recordings a clean channel measured between -0.24 and +0.09 and rose
        // monotonically with payload.
        //
        // The false-positive claim therefore belongs where it was measured, which is
        // `private/calibration/audio/measure.py` against real recordings, not here
        // against a generator whose statistics I chose. A unit test that asserted it
        // would be asserting a property of my own synthetic cover and calling it a
        // property of the detector.
    }

    #[test]
    fn roughness_separates_the_regime_sample_pair_analysis_is_valid_in() {
        // The guard the real measurement demanded. On a pure white-noise recording
        // `spa_alpha` was 0.60 when clean and -2.18 when fully embedded, which is
        // wrong in the opposite direction. Nothing else in the statistics
        // distinguished that file from the eight the estimator worked on; this does.
        //
        // For white noise the mean absolute neighbour difference tends to about
        // 1.596 standard deviations. Correlated audio is far below that.
        let correlated = stats(&synthetic_cover(40_000, 13), 1).per_channel[0].clone();
        let mut lcg = Lcg(43);
        let white: Vec<i32> = (0..40_000)
            .map(|_| (lcg.next_u32() % 20_001) as i32 - 10_000)
            .collect();
        let noise = stats(&white, 1).per_channel[0].clone();

        assert!(
            correlated.roughness < 0.5,
            "an audio-like cover measured roughness {:.3}",
            correlated.roughness
        );
        assert!(
            noise.roughness > 1.0,
            "white noise measured roughness {:.3}, expected near 1.13 to 1.16",
            noise.roughness
        );
        assert!(noise.standard_deviation > correlated.standard_deviation / 100.0);
    }

    #[test]
    fn roughness_is_zero_on_a_silent_channel_rather_than_dividing_by_zero() {
        let s = stats(&vec![0i32; 500], 1).per_channel[0].clone();
        assert_eq!(s.standard_deviation, 0.0);
        assert_eq!(s.roughness, 0.0);
        assert_eq!(s.adjacent_delta_mean_abs, 0.0);
    }

    #[test]
    fn sample_pair_analysis_reports_the_pairs_it_used() {
        let cover = synthetic_cover(5_000, 2);
        let s = stats(&cover, 1);
        // One pair fewer than samples, because the first sample has no predecessor.
        assert_eq!(s.per_channel[0].spa_pairs, 4_999);
    }

    #[test]
    fn silence_carrying_a_payload_is_caught_where_the_signal_cannot_vary() {
        // Digital silence with LSBs written into it. This is the DeepSound shape:
        // a tool that fills every sample fills the silent ones too.
        let silence = vec![0i32; 5_000];
        let clean = stats(&silence, 1).per_channel[0].clone();
        assert_eq!(
            clean.silence_lsb_flip_fraction, 0.0,
            "true silence must show no LSB variation"
        );
        assert!(clean.constant_run_samples > 4_900);

        let written = stats(&embed(&silence, 1.0, 31), 1).per_channel[0].clone();
        assert!(
            written.silence_lsb_flip_fraction > 0.3,
            "a payload written into silence must show up: got {}",
            written.silence_lsb_flip_fraction
        );
    }

    #[test]
    fn a_dithered_quiet_passage_is_excluded_rather_than_flagged() {
        // The false positive this detector has to survive. A dithered master has
        // deliberate low-level noise where a listener hears silence, so the bits
        // above the LSB move. Such samples must not enter the statistic at all,
        // which is a structural exclusion rather than a threshold.
        let mut lcg = Lcg(77);
        let dithered: Vec<i32> = (0..5_000)
            .map(|_| (lcg.next_u32() % 7) as i32 - 3)
            .collect();
        let s = stats(&dithered, 1).per_channel[0].clone();
        assert_eq!(
            s.constant_run_samples, 0,
            "dither moved the upper bits, so no sample should have qualified; \
             {} did",
            s.constant_run_samples
        );
        assert_eq!(s.silence_lsb_flip_fraction, 0.0);
        assert!(
            s.longest_constant_run < MIN_CONSTANT_RUN,
            "a dithered passage produced a {} sample constant run",
            s.longest_constant_run
        );
    }

    #[test]
    fn a_short_coincidental_run_does_not_qualify() {
        // Fifteen identical samples then a change, repeatedly. Below the minimum
        // run length, so nothing counts: otherwise the statistic would measure how
        // quiet a recording is rather than whether anything was written.
        let mut samples = Vec::new();
        for block in 0..100i32 {
            for _ in 0..(MIN_CONSTANT_RUN - 1) {
                samples.push(block * 64);
            }
        }
        let s = stats(&samples, 1).per_channel[0].clone();
        assert_eq!(s.constant_run_samples, 0);
        assert_eq!(s.longest_constant_run, MIN_CONSTANT_RUN - 1);
    }

    #[test]
    fn a_clipped_passage_counts_as_a_constant_run() {
        // Not only silence: a clipped region is equally unable to vary, and a tool
        // that writes there is equally caught. Full-scale positive clipping.
        let clipped = vec![32_766i32; 2_000];
        let s = stats(&embed(&clipped, 1.0, 41), 1).per_channel[0].clone();
        assert!(s.constant_run_samples > 1_900);
        assert!(s.silence_lsb_flip_fraction > 0.3);
    }

    #[test]
    fn a_high_bit_depth_histogram_is_folded_rather_than_allocated_without_bound() {
        // 24-bit audio. An unfolded pair histogram would be 8,388,608 bins, which
        // is 32 MiB per channel for a statistic that does not improve for it.
        let cover = synthetic_cover(3_000, 17);
        let s = analyse_stream(SliceSource::new(&cover, 1, 24)).expect("analyse");
        assert_eq!(s.bits_per_sample, 24);
        assert!(s.per_channel[0].chi_squared_pairs > 0);
        assert!(s.per_channel[0].chi_squared.is_finite());
    }

    #[test]
    fn an_absurd_channel_count_is_folded_rather_than_allocated_per_channel() {
        let cover = synthetic_cover(4_000, 19);
        let s = analyse_stream(SliceSource::new(&cover, 100_000, 16)).expect("analyse");
        assert_eq!(s.channels, limits::MAX_TRACKED_CHANNELS);
        // Only the first MAX_TRACKED_CHANNELS of each frame are measured, and the
        // interleaving still advances by the DECLARED channel count, so nothing
        // after the first frame lands in a tracked channel.
        assert_eq!(s.per_channel.len(), limits::MAX_TRACKED_CHANNELS);
    }

    #[test]
    fn a_source_that_errors_propagates_rather_than_returning_partial_statistics() {
        struct Failing(usize);
        impl SampleSource for Failing {
            fn read_chunk(&mut self, out: &mut [i32]) -> Result<usize, StegError> {
                if self.0 == 0 {
                    return Err(StegError::CorruptedFile);
                }
                self.0 -= 1;
                out[..4].copy_from_slice(&[1, 2, 3, 4]);
                Ok(4)
            }
            fn channels(&self) -> usize {
                1
            }
            fn bits_per_sample(&self) -> u16 {
                16
            }
        }
        let err = analyse_stream(Failing(2)).unwrap_err();
        assert!(matches!(err, StegError::CorruptedFile), "{err:?}");
    }

    #[test]
    fn memory_does_not_scale_with_stream_length() {
        // Asserted through the only thing a test can observe cheaply: the
        // histogram width is set by the bit depth and nothing else, so a stream a
        // hundred times longer allocates the same. The real guarantee is that
        // nothing in `ChannelAccumulator` is a growable collection, which this
        // pins by comparing the two statistics' shapes.
        let short = stats(&synthetic_cover(1_000, 23), 1);
        let long = stats(&synthetic_cover(100_000, 23), 1);
        assert_eq!(short.per_channel.len(), long.per_channel.len());
        assert_eq!(short.bits_per_sample, long.bits_per_sample);
        assert!(long.samples == 100_000 && short.samples == 1_000);
    }

    #[test]
    fn a_zero_channel_source_is_corrected_rather_than_dividing_by_zero() {
        let s = analyse_stream(SliceSource::new(&[1, 2, 3], 0, 16)).expect("analyse");
        assert_eq!(s.channels, 1);
        assert_eq!(s.samples, 3);
    }

    #[test]
    fn a_one_bit_depth_does_not_produce_a_degenerate_histogram() {
        // Defensive: a reader reporting a nonsense depth must not make the bin
        // count zero and index out of bounds.
        let s = analyse_stream(SliceSource::new(&[0, 1, 0, 1], 1, 1)).expect("analyse");
        assert_eq!(s.samples, 4);
        assert!(s.per_channel[0].chi_squared.is_finite());
    }
}
