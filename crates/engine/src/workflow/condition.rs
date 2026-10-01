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

//! The condition language: one comparison, and deliberately nothing more.
//!
//! # The grammar, in full
//!
//! ```text
//! condition := metric operator number
//! metric    := an identifier from Detector::SLUGS, or "verdict"
//! operator  := ">" | ">=" | "<" | "<=" | "==" | "!="
//! number    := a decimal the standard library can parse
//! ```
//!
//! That is the whole language. There is no `and`, no `or`, no arithmetic, no
//! function call, no variable and no way to reach anything the engine did not
//! put in the report. A pipeline file is a configuration file, and a
//! configuration file that can evaluate expressions is a scripting engine
//! wearing a different extension: it has to be sandboxed, its failure modes
//! become unbounded, and a reviewer can no longer tell what a file will do by
//! reading it. Two conditions on two steps express everything an `and` would,
//! and they stay readable.
//!
//! # Why `==` exists on a float
//!
//! It parses, and then [`Condition::validate`] refuses it, with the reason. A
//! grammar that quietly accepted `spa == 0.377` would produce a step that never
//! runs, which is the worst failure shape available: silent, and indistinguishable
//! from a file that was never reached. Refusing at validation turns it into a
//! message before anything executes.

use serde::{Deserialize, Serialize};

use crate::errors::StegError;
use crate::workflow::dsl::Detector;

/// The metric name a verdict condition reads.
pub const VERDICT_METRIC: &str = "verdict";

/// Longest condition text accepted, a bound on the parser's input.
pub const MAX_CONDITION_BYTES: usize = 128;

/// How two numbers are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    /// Strictly greater.
    Greater,
    /// Greater or equal.
    AtLeast,
    /// Strictly less.
    Less,
    /// Less or equal.
    AtMost,
    /// Exactly equal. Parses, and is then refused; see the module docs.
    Equal,
    /// Not equal. Parses, and is then refused, for the same reason.
    NotEqual,
}

impl Comparison {
    /// The operator as it is written in a pipeline file.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Greater => ">",
            Self::AtLeast => ">=",
            Self::Less => "<",
            Self::AtMost => "<=",
            Self::Equal => "==",
            Self::NotEqual => "!=",
        }
    }

    /// Apply it.
    pub fn holds(self, measured: f64, threshold: f64) -> bool {
        match self {
            Self::Greater => measured > threshold,
            Self::AtLeast => measured >= threshold,
            Self::Less => measured < threshold,
            Self::AtMost => measured <= threshold,
            Self::Equal => measured == threshold,
            Self::NotEqual => measured != threshold,
        }
    }

    /// Whether comparing floats this way is meaningful.
    fn is_ordering(self) -> bool {
        !matches!(self, Self::Equal | Self::NotEqual)
    }
}

/// One parsed comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    /// The metric read from the report.
    pub metric: String,
    /// How it is compared.
    pub comparison: Comparison,
    /// What it is compared against.
    pub threshold: f64,
    /// The text it was parsed from, kept so an error message can quote the file
    /// rather than a reconstruction of it.
    pub source: String,
}

impl Condition {
    /// Parse a condition. Shape only; [`Self::validate`] checks meaning.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        if text.len() > MAX_CONDITION_BYTES {
            return Err(bad(format!(
                "a condition of {} characters, past the {MAX_CONDITION_BYTES} limit",
                text.len()
            )));
        }

        // Two-character operators first, so `>=` is not read as `>` followed by
        // a number beginning `=`.
        let operators = [
            (">=", Comparison::AtLeast),
            ("<=", Comparison::AtMost),
            ("==", Comparison::Equal),
            ("!=", Comparison::NotEqual),
            (">", Comparison::Greater),
            ("<", Comparison::Less),
        ];

        let found = operators
            .iter()
            .filter_map(|(symbol, comparison)| {
                text.find(symbol).map(|at| (at, *symbol, *comparison))
            })
            .min_by_key(|(at, symbol, _)| (*at, std::cmp::Reverse(symbol.len())));

        let Some((at, symbol, comparison)) = found else {
            return Err(bad(format!(
                "{text:?} has no comparison in it. A condition looks like \
                 \"verdict > 0.7\", with one of > >= < <= == != in the middle"
            )));
        };

        let metric = text[..at].trim();
        let threshold_text = text[at + symbol.len()..].trim();

        if metric.is_empty() {
            return Err(bad(format!(
                "{text:?} compares nothing: there is no metric before the {symbol}"
            )));
        }
        if threshold_text.is_empty() {
            return Err(bad(format!(
                "{text:?} compares against nothing: there is no number after the {symbol}"
            )));
        }

        let threshold: f64 = threshold_text.parse().map_err(|_| {
            bad(format!(
                "{threshold_text:?} in {text:?} is not a number this condition can compare against"
            ))
        })?;
        if !threshold.is_finite() {
            return Err(bad(format!(
                "{text:?} compares against {threshold}, which no measurement can be"
            )));
        }

        Ok(Self {
            metric: metric.to_string(),
            comparison,
            threshold,
            source: text.to_string(),
        })
    }

    /// Check the condition means something: a metric that exists, an operator
    /// that is sound on a float, a threshold in the metric's range.
    pub fn validate(&self) -> Result<(), StegError> {
        if !known_metric(&self.metric) {
            return Err(bad(format!(
                "{:?} reads {:?}, which is not a metric this engine produces. \
                 The metrics are: {}",
                self.source,
                self.metric,
                known_metrics().join(", ")
            )));
        }

        if !self.comparison.is_ordering() {
            return Err(bad(format!(
                "{:?} tests a measured number for exact {}equality. A detector \
                 score is a float computed from pixel data, so it will essentially \
                 never land on a written-down value, and the step would be either \
                 unreachable or always taken. Write it as a threshold, such as \
                 {} {} {}.",
                self.source,
                if self.comparison == Comparison::Equal {
                    ""
                } else {
                    "in"
                },
                self.metric,
                if self.comparison == Comparison::Equal {
                    ">="
                } else {
                    "<"
                },
                self.threshold
            )));
        }

        // Every metric the engine publishes is a normalised score, so a
        // threshold outside the unit interval makes the step constant. That is
        // nearly always a typo for a value ten times smaller.
        if self.threshold < 0.0 || self.threshold > 1.0 {
            return Err(bad(format!(
                "{:?} compares against {}, and every score this engine produces is \
                 between 0 and 1, so the step would always behave the same way",
                self.source, self.threshold
            )));
        }

        Ok(())
    }

    /// Evaluate against a measured value.
    pub fn holds(&self, measured: f64) -> bool {
        self.comparison.holds(measured, self.threshold)
    }
}

/// Every metric a condition may read.
pub fn known_metrics() -> Vec<&'static str> {
    let mut all = vec![VERDICT_METRIC];
    all.extend_from_slice(Detector::SLUGS);
    all
}

fn known_metric(name: &str) -> bool {
    name == VERDICT_METRIC || Detector::SLUGS.contains(&name)
}

/// A condition we will not accept. `UnsupportedFormat` for the same reason
/// `dsl::problem` uses it: this is a verdict on what the user wrote, not a
/// report that our own code broke.
fn bad(reason: String) -> StegError {
    StegError::UnsupportedFormat(format!("this pipeline cannot be run: {reason}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_roadmaps_own_example_parses_and_validates() {
        let condition = Condition::parse("verdict > 0.7").expect("parse");
        condition.validate().expect("valid");
        assert_eq!(condition.metric, "verdict");
        assert_eq!(condition.comparison, Comparison::Greater);
        assert_eq!(condition.threshold, 0.7);
        assert!(condition.holds(0.71));
        assert!(!condition.holds(0.7));
    }

    #[test]
    fn every_operator_parses_to_its_own_symbol() {
        for (text, expected) in [
            ("spa > 0.3", Comparison::Greater),
            ("spa >= 0.3", Comparison::AtLeast),
            ("spa < 0.3", Comparison::Less),
            ("spa <= 0.3", Comparison::AtMost),
            ("spa == 0.3", Comparison::Equal),
            ("spa != 0.3", Comparison::NotEqual),
        ] {
            let condition = Condition::parse(text).expect(text);
            assert_eq!(condition.comparison, expected, "{text}");
            assert_eq!(condition.comparison.symbol(), expected.symbol());
        }
    }

    #[test]
    fn a_two_character_operator_is_not_read_as_a_one_character_one() {
        let condition = Condition::parse("ws>=0.195").expect("parse");
        assert_eq!(condition.comparison, Comparison::AtLeast);
        assert_eq!(condition.threshold, 0.195);
    }

    #[test]
    fn whitespace_around_the_operator_is_optional() {
        for text in ["verdict>0.7", "verdict > 0.7", "  verdict   >   0.7  "] {
            let condition = Condition::parse(text).expect(text);
            assert_eq!(condition.metric, "verdict");
            assert_eq!(condition.threshold, 0.7);
        }
    }

    #[test]
    fn each_comparison_evaluates_correctly() {
        assert!(Comparison::Greater.holds(0.8, 0.7));
        assert!(!Comparison::Greater.holds(0.7, 0.7));
        assert!(Comparison::AtLeast.holds(0.7, 0.7));
        assert!(Comparison::Less.holds(0.6, 0.7));
        assert!(!Comparison::Less.holds(0.7, 0.7));
        assert!(Comparison::AtMost.holds(0.7, 0.7));
        assert!(Comparison::Equal.holds(0.7, 0.7));
        assert!(Comparison::NotEqual.holds(0.6, 0.7));
    }

    #[test]
    fn a_condition_with_no_operator_explains_the_shape() {
        let err = Condition::parse("verdict 0.7").expect_err("must refuse");
        assert!(err.to_string().contains("verdict > 0.7"), "{err}");
    }

    #[test]
    fn a_condition_with_no_metric_is_refused() {
        let err = Condition::parse("> 0.7").expect_err("must refuse");
        assert!(err.to_string().contains("compares nothing"), "{err}");
    }

    #[test]
    fn a_condition_with_no_threshold_is_refused() {
        let err = Condition::parse("verdict >").expect_err("must refuse");
        assert!(
            err.to_string().contains("compares against nothing"),
            "{err}"
        );
    }

    #[test]
    fn a_threshold_that_is_not_a_number_is_refused_with_the_text_quoted() {
        let err = Condition::parse("verdict > high").expect_err("must refuse");
        assert!(err.to_string().contains("high"), "{err}");
    }

    #[test]
    fn a_non_finite_threshold_is_refused() {
        for text in ["verdict > inf", "verdict > NaN", "verdict < -inf"] {
            assert!(Condition::parse(text).is_err(), "{text} was accepted");
        }
    }

    #[test]
    fn an_over_long_condition_is_refused_before_it_is_parsed() {
        let long = format!("verdict > 0.{}", "7".repeat(MAX_CONDITION_BYTES));
        let err = Condition::parse(&long).expect_err("must refuse");
        assert!(err.to_string().contains("past the"), "{err}");
    }

    /// The property the whole design rests on: a typo in a metric name is a
    /// validation failure, not a step that silently never fires.
    #[test]
    fn a_misspelled_metric_is_refused_and_the_real_ones_are_listed() {
        let condition = Condition::parse("verdcit > 0.7").expect("parses");
        let err = condition.validate().expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("verdcit"), "{message}");
        assert!(message.contains("verdict"), "{message}");
        assert!(message.contains("spa"), "{message}");
    }

    #[test]
    fn float_equality_is_refused_with_a_rewrite_suggested() {
        let condition = Condition::parse("spa == 0.377").expect("parses");
        let err = condition.validate().expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("exact equality"), "{message}");
        assert!(message.contains("spa >= 0.377"), "{message}");

        let inequality = Condition::parse("spa != 0.377").expect("parses");
        let err = inequality.validate().expect_err("must refuse");
        assert!(err.to_string().contains("inequality"), "{err}");
    }

    #[test]
    fn a_threshold_outside_the_unit_interval_is_refused() {
        for text in ["verdict > 7", "verdict < -0.5", "spa >= 1.5"] {
            let condition = Condition::parse(text).expect("parses");
            let err = condition.validate().expect_err("must refuse");
            assert!(err.to_string().contains("between 0 and 1"), "{err}");
        }
    }

    #[test]
    fn the_endpoints_are_inside_the_accepted_range() {
        for text in [
            "verdict > 0",
            "verdict < 1",
            "verdict >= 0.0",
            "verdict <= 1.0",
        ] {
            Condition::parse(text)
                .expect("parses")
                .validate()
                .expect(text);
        }
    }

    #[test]
    fn every_detector_slug_is_a_usable_metric() {
        for slug in Detector::SLUGS {
            let condition = Condition::parse(&format!("{slug} > 0.5")).expect(slug);
            condition
                .validate()
                .unwrap_or_else(|e| panic!("{slug}: {e}"));
        }
        assert!(known_metrics().contains(&VERDICT_METRIC));
    }

    #[test]
    fn the_source_text_is_kept_for_error_messages() {
        let condition = Condition::parse("  verdict > 0.7 ").expect("parse");
        assert_eq!(condition.source, "  verdict > 0.7 ");
    }

    #[test]
    fn a_condition_round_trips_through_json() {
        let condition = Condition::parse("verdict >= 0.42").expect("parse");
        let text = serde_json::to_string(&condition).expect("json");
        let back: Condition = serde_json::from_str(&text).expect("read");
        assert_eq!(back, condition);
    }
}
