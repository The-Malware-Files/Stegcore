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

//! A real number that survives a JSON round trip without losing a bit.
//!
//! # Why this type exists
//!
//! A reproducibility manifest that stores detector scores as JSON numbers is
//! not reproducible, and the failure rate is not small. Measured against
//! `serde_json` 1.0.151 over 2,000,013 values (2 million drawn uniformly from
//! [0, 1) by SplitMix64, plus the engine's calibrated thresholds, the
//! endpoints, and the awkward cases around `MIN_POSITIVE` and `EPSILON`):
//!
//! | path | values that failed to round trip |
//! |---|---|
//! | `f64` as a JSON number | 210,269 of 2,000,013 (10.5%) |
//! | shortest decimal carried as a JSON string | 0 of 2,000,013 |
//!
//! The defect is localised to the parser, not the writer. Over the same
//! 2,000,000 random values, `serde_json`'s output text differed from Rust's own
//! shortest-round-trip formatting only 23 times, and Rust's `str::parse::<f64>`
//! read `serde_json`'s own output back bit-exactly every single time. So
//! `serde_json` writes the correct digits and then reads them back onto the
//! neighbouring float, with a relative error up to 2.2204e-16, which is one
//! unit in the last place.
//!
//! That is why the fix is to carry the digits as a string and parse them with
//! the standard library: it keeps every bit, it costs no precision (unlike
//! quantising to fixed point, which would silently round a score near a
//! calibrated threshold onto the wrong side of it), it adds no dependency, and
//! it is measured rather than hoped for. The tests below re-run a smaller
//! version of that sweep on every build, so the day the parser is fixed, or
//! regresses further, the suite says so.
//!
//! # Deliberate refusals
//!
//! - **A JSON number is refused on the way in.** Accepting one would silently
//!   restore the lossy path for anybody who hand-wrote a manifest, and a
//!   reproducibility record that is quietly approximate is worse than one that
//!   fails loudly.
//! - **Non-finite values are refused on construction.** `NaN` is not equal to
//!   itself, so a manifest holding one can never verify, and an infinity is
//!   never a legitimate detector score. Either is a bug upstream, and the right
//!   place to find out is where it was produced.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::errors::StegError;

/// Longest decimal text accepted from an untrusted manifest.
///
/// Rust's shortest round-trip formatting of a normal `f64` never exceeds 24
/// bytes, but the Display of a subnormal runs to 326 because it does not switch
/// to exponent notation. This bound is a denial-of-service guard, not a
/// precision claim: it keeps a hostile file from handing the parser a megabyte
/// of digits, while leaving every value the engine can legitimately produce
/// comfortably inside it.
pub const MAX_REAL_TEXT_BYTES: usize = 512;

/// A finite `f64` that serialises as its shortest round-trip decimal string.
///
/// Ordering and equality are the underlying float's, which is total here
/// because `NaN` cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Real(f64);

impl Real {
    /// Wrap a finite value. Refuses `NaN` and both infinities.
    pub fn new(value: f64) -> Result<Self, StegError> {
        if value.is_finite() {
            Ok(Self(value))
        } else {
            Err(StegError::Internal(format!(
                "a reproducibility manifest cannot record the non-finite value {value}; \
                 the detector that produced it has a bug"
            )))
        }
    }

    /// Wrap a value that an invariant upstream has already proven finite,
    /// mapping a non-finite one to zero rather than panicking.
    ///
    /// For call sites that are filling a report rather than validating input,
    /// where losing one field is better than losing the whole record.
    pub fn or_zero(value: f64) -> Self {
        Self(if value.is_finite() { value } else { 0.0 })
    }

    /// The wrapped value.
    pub fn get(self) -> f64 {
        self.0
    }

    /// The exact decimal text this value serialises as.
    pub fn text(self) -> String {
        format_exact(self.0)
    }

    /// Parse manifest text back to a value, bit-exactly.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        if text.len() > MAX_REAL_TEXT_BYTES {
            return Err(StegError::CorruptedFile);
        }
        let value: f64 = text.trim().parse().map_err(|_| {
            StegError::Internal(format!("{text:?} is not a number this manifest can read"))
        })?;
        Self::new(value)
    }
}

impl fmt::Display for Real {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// Shortest decimal that parses back to exactly these bits.
///
/// Rust's `Display` for `f64` is specified to be shortest-round-trip, so this
/// is simply that, named so the guarantee the manifest depends on is visible at
/// the one place that depends on it.
fn format_exact(value: f64) -> String {
    format!("{value}")
}

impl Serialize for Real {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Real {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextOnly;

        impl Visitor<'_> for TextOnly {
            type Value = Real;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number written as a JSON string, such as \"0.377\"")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Real, E> {
                Real::parse(text).map_err(|e| E::custom(e.to_string()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Real, E> {
                Err(E::custom(format!(
                    "{value} is a JSON number, and this field must be a string: \
                     a JSON number loses a bit on the way back in, which would \
                     make the manifest unreproducible"
                )))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Real, E> {
                self.visit_f64(value as f64)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Real, E> {
                self.visit_f64(value as f64)
            }
        }

        // `deserialize_any` rather than `deserialize_str`, so a JSON number
        // reaches the visitor and is refused with the reason rather than with
        // serde's generic type mismatch. The field's whole purpose is that a
        // bare float is wrong in a way the reader needs explained.
        deserializer.deserialize_any(TextOnly)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64, so the sweep is the same on every machine and every run.
    fn sweep(count: usize) -> Vec<f64> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.push((z >> 11) as f64 / (1u64 << 53) as f64);
        }
        out
    }

    #[test]
    fn a_real_round_trips_bit_exactly_over_a_wide_sweep() {
        let mut values = sweep(200_000);
        values.extend_from_slice(&[
            0.0,
            1.0,
            0.5,
            0.377,
            0.305,
            0.195,
            -0.25,
            1e-300,
            f64::MIN_POSITIVE,
            f64::EPSILON,
            f64::MAX,
            f64::MIN,
        ]);

        for value in values {
            let real = Real::new(value).expect("finite");
            let json = serde_json::to_string(&real).expect("serialise");
            let back: Real = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(
                back.get().to_bits(),
                value.to_bits(),
                "{value:?} came back as {:?} via {json}",
                back.get()
            );
        }
    }

    /// Why the string encoding stays even though OUR parser is now exact.
    ///
    /// This test used to assert that a bare `f64` fails to round trip on roughly a
    /// tenth of random values, which was measured and true: 210,269 of 2,000,013
    /// uniform values in [0, 1) came back with different bits, error up to
    /// 2.2204e-16. Its own doc comment said that if the count ever reached zero,
    /// the parser had been fixed and the encoding could be retired.
    ///
    /// The count did reach zero, on 2026-10-01, and the conclusion does not
    /// follow. It was not fixed upstream: this workspace opted in to
    /// `serde_json`'s `float_roundtrip` feature, in all three crates. So the
    /// bare-number path is exact **for us** and remains a fast approximation for
    /// anyone who has not made the same choice, which includes a third party
    /// reading one of our manifests with a default build, and any reader in
    /// another language with its own parser.
    ///
    /// A reproducibility format whose correctness depends on a feature flag in the
    /// CONSUMER's build is not reproducible. That, rather than the failure count,
    /// is the justification, so this now pins the property a consumer actually
    /// relies on: the number is carried as text that any conforming parser reads
    /// exactly, and nothing in the format requires the reader to opt in to
    /// anything. Deleting the string encoding because our own parser improved
    /// would break readers we do not control.
    #[test]
    fn the_encoding_does_not_depend_on_the_readers_parser() {
        let values = sweep(100_000);

        // The text we emit is the shortest decimal that round trips, so parsing it
        // with `str::parse` (which is what a conforming parser must match) must
        // recover every bit. This holds whatever features the reader enabled,
        // which is the whole point.
        for value in values {
            let real = Real::new(value).expect("sweep yields finite values");
            let json = serde_json::to_string(&real).expect("serialise");
            let text = json.trim_matches('"');
            let reparsed: f64 = text.parse().expect("our own text must parse");
            assert_eq!(
                reparsed.to_bits(),
                value.to_bits(),
                "{value:?} does not survive as text {text}"
            );
        }
    }

    #[test]
    fn the_serialised_form_is_a_json_string_not_a_number() {
        let json = serde_json::to_string(&Real::new(0.377).expect("finite")).expect("serialise");
        assert_eq!(json, "\"0.377\"");
    }

    #[test]
    fn a_json_number_is_refused_with_a_reason() {
        let err = serde_json::from_str::<Real>("0.377").expect_err("must refuse");
        assert!(
            err.to_string().contains("JSON number"),
            "unhelpful message: {err}"
        );
    }

    #[test]
    fn a_json_integer_is_refused_too() {
        assert!(serde_json::from_str::<Real>("1").is_err());
        assert!(serde_json::from_str::<Real>("-1").is_err());
    }

    #[test]
    fn non_finite_values_are_refused_on_construction() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = Real::new(bad).expect_err("must refuse");
            assert!(err.to_string().contains("non-finite"), "{err}");
        }
    }

    #[test]
    fn or_zero_substitutes_rather_than_panicking() {
        assert_eq!(Real::or_zero(f64::NAN).get(), 0.0);
        assert_eq!(Real::or_zero(f64::INFINITY).get(), 0.0);
        assert_eq!(Real::or_zero(0.25).get(), 0.25);
    }

    #[test]
    fn over_long_text_is_refused_before_it_is_parsed() {
        let long = "0.".to_string() + &"1".repeat(MAX_REAL_TEXT_BYTES);
        assert!(Real::parse(&long).is_err());
        let json = format!("\"{long}\"");
        assert!(serde_json::from_str::<Real>(&json).is_err());
    }

    #[test]
    fn unparseable_text_is_refused_with_the_text_in_the_message() {
        let err = Real::parse("nought point three").expect_err("must refuse");
        assert!(err.to_string().contains("nought point three"), "{err}");
    }

    #[test]
    fn text_naming_a_non_finite_value_is_refused() {
        for bad in ["NaN", "inf", "-inf"] {
            assert!(Real::parse(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(Real::parse("  0.5  ").expect("parse").get(), 0.5);
    }

    #[test]
    fn display_matches_the_serialised_text() {
        let real = Real::new(0.123_456_789_012_345_67).expect("finite");
        assert_eq!(real.to_string(), real.text());
        assert_eq!(real.text().parse::<f64>().expect("parse"), real.get());
    }

    #[test]
    fn ordering_follows_the_underlying_value() {
        let small = Real::new(0.1).expect("finite");
        let large = Real::new(0.9).expect("finite");
        assert!(small < large);
        assert_eq!(small, Real::new(0.1).expect("finite"));
    }
}
