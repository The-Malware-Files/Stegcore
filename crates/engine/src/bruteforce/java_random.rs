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

//! A bit-exact reimplementation of `java.util.Random`.
//!
//! OpenStego is a Java program and scatters its payload bits with
//! `new Random(seed).nextInt(bound)`. Reproducing where it put those bits means
//! reproducing that generator exactly, including the two details that are easy
//! to get wrong: a power-of-two bound takes a different arithmetic path, and a
//! non-power-of-two bound rejects and redraws when the raw value would bias the
//! result.
//!
//! This is a 48-bit linear congruential generator. It is a *compatibility
//! shim*, not a source of randomness, and nothing in Stegcore may use it for
//! anything that needs to be unpredictable.
//!
//! The algorithm is specified in the `java.util.Random` class documentation,
//! which fixes the multiplier, the addend and the scrambling of the seed, so
//! this is an implementation of a published specification rather than a guess.

/// `0x5DEECE66D`, the multiplier fixed by the `java.util.Random` specification.
const MULTIPLIER: u64 = 0x5_DEEC_E66D;
/// `0xB`, the addend fixed by the same specification.
const ADDEND: u64 = 0xB;
/// The generator keeps 48 bits of state.
const MASK: u64 = (1 << 48) - 1;

/// A `java.util.Random` work-alike.
#[derive(Debug, Clone)]
pub struct JavaRandom {
    state: u64,
}

impl JavaRandom {
    /// Construct from a seed, applying the same initial scramble Java does.
    ///
    /// The seed is an `i64` because that is what Java's constructor takes and
    /// what OpenStego passes it; only the low 48 bits survive the scramble.
    pub fn new(seed: i64) -> Self {
        Self {
            state: ((seed as u64) ^ MULTIPLIER) & MASK,
        }
    }

    /// `protected int next(int bits)`: advance the state and return the top
    /// `bits` bits of it. `bits` is expected in 1..=32; a larger value would
    /// shift by a negative amount in Java, which never happens through the
    /// public API, so it is clamped here rather than allowed to misbehave.
    fn next(&mut self, bits: u32) -> u32 {
        self.state = self.state.wrapping_mul(MULTIPLIER).wrapping_add(ADDEND) & MASK;
        let bits = bits.clamp(1, 32);
        (self.state >> (48 - bits)) as u32
    }

    /// `public int nextInt(int bound)`.
    ///
    /// Returns `None` for a bound that is not positive, which Java signals by
    /// throwing. Callers in this module validate the bound before they get
    /// here; returning an option rather than panicking keeps the promise that
    /// no non-test code in this workspace panics on bad input.
    pub fn next_int(&mut self, bound: u32) -> Option<u32> {
        if bound == 0 || bound > i32::MAX as u32 {
            return None;
        }
        if bound & bound.wrapping_sub(1) == 0 {
            // Power of two: Java takes the high bits rather than a remainder.
            let r = self.next(31) as u64;
            return Some(((bound as u64).wrapping_mul(r) >> 31) as u32);
        }
        // Java redraws while the candidate would come from a short final
        // bucket, which is what keeps the distribution uniform. The loop is
        // bounded below rather than trusted to terminate: the expected number
        // of redraws is under two, and a hundred is far past any plausible run
        // while still guaranteeing the loop ends.
        for _ in 0..100 {
            let bits = self.next(31) as i32;
            let val = bits % bound as i32;
            if bits.wrapping_sub(val).wrapping_add(bound as i32 - 1) >= 0 {
                return Some(val as u32);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values captured from a real JVM: `new Random(42)` then five
    /// `nextInt(100)` calls. Pins the generator against the implementation it
    /// has to agree with, not against our own arithmetic.
    #[test]
    fn matches_reference_values_for_seed_42() {
        let mut r = JavaRandom::new(42);
        let got: Vec<u32> = (0..5).map(|_| r.next_int(100).unwrap()).collect();
        assert_eq!(got, vec![30, 63, 48, 84, 70]);
    }

    #[test]
    fn matches_reference_values_for_a_power_of_two_bound() {
        // `new Random(12345)` then nextInt(256) five times, from a real JVM.
        let mut r = JavaRandom::new(12345);
        let got: Vec<u32> = (0..5).map(|_| r.next_int(256).unwrap()).collect();
        assert_eq!(got, vec![92, 131, 238, 234, 213]);
    }

    #[test]
    fn bound_of_one_always_returns_zero_but_still_consumes_a_draw() {
        // Both figures come from a real JVM, so this pins the side effect of a
        // bound of one rather than merely observing that two numbers differ.
        let mut a = JavaRandom::new(7);
        assert_eq!(a.next_int(1), Some(0));
        assert_eq!(a.next_int(1000), Some(164));

        let mut b = JavaRandom::new(7);
        assert_eq!(b.next_int(1000), Some(236));
    }

    #[test]
    fn rejects_a_non_positive_or_over_large_bound() {
        let mut r = JavaRandom::new(1);
        assert_eq!(r.next_int(0), None);
        assert_eq!(r.next_int(u32::MAX), None);
    }

    #[test]
    fn a_negative_seed_is_accepted_and_deterministic() {
        let mut a = JavaRandom::new(-99);
        let mut b = JavaRandom::new(-99);
        let left: Vec<u32> = (0..8).map(|_| a.next_int(1000).unwrap()).collect();
        let right: Vec<u32> = (0..8).map(|_| b.next_int(1000).unwrap()).collect();
        assert_eq!(left, right);
    }

    #[test]
    fn values_stay_inside_the_bound() {
        let mut r = JavaRandom::new(2026);
        for _ in 0..2000 {
            let v = r.next_int(37).unwrap();
            assert!(v < 37);
        }
    }
}
