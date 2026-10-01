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

//! The wild-sample manifest: a corpus described by hashes and honesty, never by
//! content.
//!
//! # Why a manifest rather than a directory
//!
//! A wild-sample corpus cannot be committed, cannot be published, and in
//! several cases cannot lawfully be redistributed at all. What can be written
//! down is which files it consists of, what each one is, and how somebody with
//! the right account and the right isolated machine gets it again. That record
//! is the manifest, and it is the only part of a wild corpus that ever exists
//! on a machine holding keys.
//!
//! The format is TOML because its reader is a human reviewing a diff, and it
//! matches the fleet provenance convention already in the tree
//! (`private/datasets.provenance.toml`).
//!
//! # The standard of honesty the provenance fields are held to
//!
//! The convention this follows writes things like:
//!
//! > The page returned HTTP 200 on the verified date. That confirms the
//! > competition still exists; it does not confirm the archive downloads
//! > without accepting terms, which needs a human with an account.
//!
//! That is the bar, and it is why [`Provenance::note`] is mandatory rather than
//! optional. A provenance record whose note is missing reads as a guarantee
//! that re-obtaining the sample works, and nobody checked that. The validator
//! refuses an empty one.
//!
//! # A worked entry
//!
//! ```toml
//! format = 1
//! corpus = "wild-d2"
//! note = """
//! Candidate list for deferred item D2. No sample in this manifest has been
//! fetched; the digests come from the vendor reports and the repository
//! listings cited per entry, so a digest here is a claim by a third party and
//! not something we have verified against bytes.
//! """
//! compiled = "2026-10-01"
//!
//! [[sample]]
//! id = "worok-png-001"
//! sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
//! bytes = 184_320
//! media = "image/png"
//! family = "worok"
//! campaign = "worok-2022-png-loader"
//! payload = "carries"
//! tool = "worok-custom-lsb"
//! truth_basis = "Vendor report names this file as a PNG carrying a CLR loader in the low bits. Not independently confirmed."
//!
//! [sample.provenance]
//! origin = "Named in a published vendor write-up; the file itself is on a sample-sharing service behind an account."
//! reobtain = "Search the service by SHA-256 with a researcher account, download the password-protected archive."
//! verified = "2026-10-01"
//! note = """
//! The digest was copied from the write-up on the verified date. That confirms
//! the write-up states this digest; it does not confirm the file is still
//! available, and nothing here has been compared against bytes.
//! """
//!
//! [sample.terms]
//! licence = "none-stated"
//! redistributable = false
//! note = "A sample-sharing service's terms permit research use by the account holder and say nothing about onward distribution. Treat as not redistributable."
//! ```
//!
//! Note the shape of the digest in that example. A manifest written before the
//! samples exist carries digests that are *claims*, and
//! [`WildSample::digest_is_a_placeholder`] exists so the verifier can say so
//! out loud rather than reporting a mismatch against an obvious stand-in.
//!
//! # Deliberate refusals
//!
//! - **No content field.** There is no `Vec<u8>` anywhere in this format.
//! - **No path field.** Identifiers are checked for path separators, because a
//!   manifest is shared with whoever provisions the isolated machine and a
//!   field called "id" is where somebody writes a local path without thinking.
//! - **No URL field.** [`Provenance::reobtain`] is prose for a human, and that
//!   is on purpose: a machine-readable URL is one `reqwest` call away from
//!   being fetched, and the whole point of this module is that nothing fetches.
//! - **Dates are quoted strings.** An unquoted TOML date is a different type
//!   and would be rejected with an unhelpful message, so [`from_toml`] catches
//!   that case and says which line to quote.
//! - **A tool name on a clean sample is a hard error,** not a warning. The two
//!   fields contradict each other and the grader would believe the label.
//!
//! [`from_toml`]: WildManifest::from_toml

use serde::{Deserialize, Serialize};

use crate::errors::StegError;

/// Format version of a wild-sample manifest.
pub const WILD_MANIFEST_FORMAT: u32 = 1;

/// Largest manifest file accepted, as a denial-of-service bound on the parser.
///
/// An entry is roughly a kilobyte with its provenance prose, so this is room
/// for far more samples than [`MAX_SAMPLES`] allows anyway.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// Most samples in one manifest.
pub const MAX_SAMPLES: usize = 100_000;

/// Longest identifier, family name, campaign name or licence string.
pub const MAX_ID_BYTES: usize = 64;

/// Longest free-text field: the notes a human writes.
pub const MAX_TEXT_BYTES: usize = 8 * 1024;

/// Largest size a manifest entry may claim.
///
/// Not a limit on what the verifier can hash (it streams), a limit on what is
/// plausible. A wild image or audio sample past two gigabytes is a mistyped
/// figure, and catching it here is cheaper than catching it after the verifier
/// has read two gigabytes off a cloud disk.
pub const MAX_SAMPLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How old a provenance check may be before [`WildManifest::stale`] reports it.
///
/// Six months. Long enough that a stable corpus is not re-checked for no
/// reason, short enough that "verified" never silently means "verified at some
/// point in the past two years".
pub const PROVENANCE_STALE_AFTER_DAYS: i64 = 180;

/// What is known about whether a sample carries a payload.
///
/// Three states and not two. An unlabelled sample is excluded from grading by
/// [`WildManifest::labelled`] rather than quietly counted as clean, which is
/// how a false-positive rate ends up measured against stego files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// Known to carry hidden data.
    Carries,
    /// Known to carry nothing. The arm that sets the false-positive rate, and
    /// the arm a wild corpus is always short of.
    Clean,
    /// Nobody has established it. Recorded honestly rather than guessed.
    Unknown,
}

/// Where a sample came from and how to get it again.
///
/// Every field is mandatory. An optional provenance field is one that gets left
/// blank, and a blank one reads as "fine" when it means "unknown".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Where it came from, in the words a human would use. Not a URL: see the
    /// module docs on why this format has no machine-readable location.
    pub origin: String,
    /// How to obtain it again, including the accounts, terms or approvals that
    /// a person has to go through. Prose, for a person.
    pub reobtain: String,
    /// The date a human last confirmed the two fields above, as `"YYYY-MM-DD"`.
    pub verified: String,
    /// What the check on the verified date actually established, and what it
    /// did not. Mandatory, because this is the field that stops the record
    /// reading as a guarantee.
    pub note: String,
}

/// The licence or terms position on one sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// An SPDX identifier where one applies, or `"none-stated"`. Malware
    /// samples usually have no licence at all, and `"none-stated"` is the
    /// honest value rather than a guess at fair use.
    pub licence: String,
    /// May we pass this file on to anybody else? Explicit, with no default, so
    /// the author of the entry has to answer it.
    pub redistributable: bool,
    /// What the position above rests on.
    pub note: String,
}

/// One sample, described without being held.
///
/// Field order is the TOML serialisation order, so the scalars come before the
/// `[sample.provenance]` and `[sample.terms]` tables. TOML cannot write a
/// scalar after a table inside the same entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildSample {
    /// Short identifier, unique in the manifest. A label for humans and the key
    /// the grading report is keyed by. Never a path.
    pub id: String,
    /// Lowercase hex SHA-256 of the file. The actual identity.
    pub sha256: String,
    /// Size in bytes. Checked before hashing, so a truncated or substituted
    /// file is caught without reading it.
    pub bytes: u64,
    /// Media type, such as `image/png`. Declared, never sniffed.
    pub media: String,
    /// Family or campaign group. Lowercase, because per-family metrics split a
    /// row in two if the same family arrives in two spellings.
    pub family: String,
    /// A narrower campaign label where one is known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub campaign: Option<String>,
    /// The ground truth.
    pub payload: Payload,
    /// Which tool or loader did the embedding, where that is known. Only
    /// meaningful with [`Payload::Carries`]; anything else is a hard error.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool: Option<String>,
    /// How the ground truth was established: a vendor report, our own
    /// extraction, somebody's blog post. Mandatory for a labelled sample,
    /// because "known to carry a payload" with no basis is a rumour, and the
    /// grader cannot tell the difference.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub truth_basis: Option<String>,
    /// Where it came from and how to get it again.
    pub provenance: Provenance,
    /// The licence or terms position.
    pub terms: Terms,
}

/// A whole manifest: one corpus, described.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildManifest {
    /// Format version.
    pub format: u32,
    /// Short name for the corpus, used in filenames and report headers.
    pub corpus: String,
    /// What this corpus is and what its digests do and do not rest on. The one
    /// field that is read by a person and nothing else.
    pub note: String,
    /// The date the manifest was compiled, as `"YYYY-MM-DD"`.
    pub compiled: String,
    /// The entries, sorted by id after [`WildManifest::canonicalise`].
    #[serde(rename = "sample", default)]
    pub samples: Vec<WildSample>,
}

/// A provenance record whose last human check is older than
/// [`PROVENANCE_STALE_AFTER_DAYS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleProvenance {
    /// Which sample.
    pub id: String,
    /// The date on the record.
    pub verified: String,
    /// How many days before the reference date that was.
    pub age_days: i64,
}

impl WildSample {
    /// Check one entry.
    pub fn validate(&self) -> Result<(), StegError> {
        check_id("sample id", &self.id)?;
        check_lowercase_digest(&self.id, &self.sha256)?;

        if self.bytes == 0 {
            return Err(reject(format!(
                "sample {:?} declares zero bytes; a zero-byte file carries nothing \
                 and hashes to a constant, so it is either a mistake or a placeholder \
                 that should say so in the note",
                self.id
            )));
        }
        if self.bytes > MAX_SAMPLE_BYTES {
            return Err(reject(format!(
                "sample {:?} declares {} bytes, past the {MAX_SAMPLE_BYTES} limit one \
                 entry may claim",
                self.id, self.bytes
            )));
        }

        check_media(&self.id, &self.media)?;
        check_id("family", &self.family)?;
        check_lowercase(&self.id, "family", &self.family)?;
        if let Some(campaign) = &self.campaign {
            check_id("campaign", campaign)?;
            check_lowercase(&self.id, "campaign", campaign)?;
        }

        match (self.payload, &self.tool) {
            (Payload::Carries, Some(tool)) => {
                check_id("tool", tool)?;
                check_lowercase(&self.id, "tool", tool)?;
            }
            (Payload::Carries, None) => {}
            (_, Some(tool)) => {
                return Err(reject(format!(
                    "sample {:?} names the embedding tool {tool:?} but its payload field \
                     says {:?}; one of the two is wrong and the grader would believe the \
                     payload field",
                    self.id, self.payload
                )));
            }
            (_, None) => {}
        }

        match (self.payload, &self.truth_basis) {
            (Payload::Unknown, _) => {}
            (_, Some(basis)) => check_text(&self.id, "truth_basis", basis)?,
            (_, None) => {
                return Err(reject(format!(
                    "sample {:?} claims a known ground truth with no truth_basis; a label \
                     with no stated basis cannot be told apart from a guess, and the \
                     grading run would treat it as fact",
                    self.id
                )));
            }
        }

        self.provenance.validate(&self.id)?;
        self.terms.validate(&self.id)?;
        Ok(())
    }

    /// Whether the digest is an obvious stand-in rather than a measurement.
    ///
    /// A manifest drafted before the samples exist has to carry something in
    /// the digest field, and the honest something is a run of one repeated hex
    /// character. The verifier reports these separately from a real mismatch,
    /// because "you have not filled this in yet" and "this file is not the file
    /// you recorded" are different problems with different fixes.
    pub fn digest_is_a_placeholder(&self) -> bool {
        let mut chars = self.sha256.chars();
        match chars.next() {
            Some(first) => chars.all(|c| c == first),
            None => false,
        }
    }
}

impl Provenance {
    fn validate(&self, sample_id: &str) -> Result<(), StegError> {
        check_text(sample_id, "provenance.origin", &self.origin)?;
        check_text(sample_id, "provenance.reobtain", &self.reobtain)?;
        check_text(sample_id, "provenance.note", &self.note)?;
        parse_iso_date(&self.verified).map_err(|why| {
            reject(format!(
                "sample {sample_id:?} has a provenance.verified of {:?}: {why}",
                self.verified
            ))
        })?;
        Ok(())
    }
}

impl Terms {
    fn validate(&self, sample_id: &str) -> Result<(), StegError> {
        check_id("terms.licence", &self.licence)?;
        check_text(sample_id, "terms.note", &self.note)?;
        Ok(())
    }
}

impl WildManifest {
    /// Put the manifest into its one canonical shape, so two people who
    /// recorded the same corpus produce the same diff.
    pub fn canonicalise(&mut self) {
        self.samples.sort_by(|a, b| a.id.cmp(&b.id));
    }

    /// Check the whole manifest, naming the entry that failed.
    pub fn validate(&self) -> Result<(), StegError> {
        if self.format != WILD_MANIFEST_FORMAT {
            return Err(StegError::UnsupportedFormat(format!(
                "wild-sample manifest format {} is not the format \
                 {WILD_MANIFEST_FORMAT} this build reads",
                self.format
            )));
        }
        check_id("corpus name", &self.corpus)?;
        check_text(&self.corpus, "note", &self.note)?;
        parse_iso_date(&self.compiled).map_err(|why| {
            reject(format!(
                "the manifest's compiled date {:?} is not usable: {why}",
                self.compiled
            ))
        })?;

        if self.samples.len() > MAX_SAMPLES {
            return Err(reject(format!(
                "{} samples, past the {MAX_SAMPLES} limit for one manifest",
                self.samples.len()
            )));
        }

        for sample in &self.samples {
            sample.validate()?;
        }

        let mut ids: Vec<&str> = self.samples.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        for pair in ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(reject(format!(
                    "two samples share the id {:?}, so one of them would be lost from \
                     every report keyed by id",
                    pair[0]
                )));
            }
        }

        // Duplicate digests are checked separately from duplicate ids, and
        // only among the real ones: placeholders are all alike by design, and
        // refusing them here would make a draft manifest unparseable.
        let mut digests: Vec<&str> = self
            .samples
            .iter()
            .filter(|s| !s.digest_is_a_placeholder())
            .map(|s| s.sha256.as_str())
            .collect();
        digests.sort_unstable();
        for pair in digests.windows(2) {
            if pair[0] == pair[1] {
                return Err(reject(format!(
                    "two samples share the digest {}, so they are the same file under two \
                     labels and every per-family rate counts it twice",
                    pair[0]
                )));
            }
        }

        Ok(())
    }

    /// Parse and validate in one step, so no caller can hold an unvalidated
    /// manifest.
    ///
    /// Refuses an oversized file before handing it to the parser, and
    /// translates the one TOML type error that is easy to hit by accident.
    pub fn from_toml(text: &str) -> Result<Self, StegError> {
        if text.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(reject(format!(
                "the manifest is {} bytes, past the {MAX_MANIFEST_BYTES} limit",
                text.len()
            )));
        }
        let manifest: Self = toml::from_str(text).map_err(|e| {
            // An unquoted date arrives as a TOML datetime, which serde reports
            // as a map where a string was wanted. The message is accurate and
            // tells the author nothing they can act on, so it gets a hint.
            let text = e.to_string();
            let hint = if text.contains("expected a string") || text.contains("datetime") {
                "\nHint: dates in this format are quoted strings, so write \
                 verified = \"2026-10-01\" and not verified = 2026-10-01. An \
                 unquoted date is a TOML datetime, which is a different type."
            } else {
                ""
            };
            reject(format!("the manifest did not parse: {e}{hint}"))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Serialise for review: the reader is a person looking at a diff.
    pub fn to_review_toml(&self) -> Result<String, StegError> {
        let mut ordered = self.clone();
        ordered.canonicalise();
        toml::to_string_pretty(&ordered)
            .map_err(|e| StegError::Internal(format!("the manifest would not serialise: {e}")))
    }

    /// The samples a grading run may use, in canonical id order.
    ///
    /// [`Payload::Unknown`] entries are dropped here and nowhere earlier, so
    /// they stay in the file for whoever later establishes the truth.
    pub fn labelled(&self) -> Vec<&WildSample> {
        let mut labelled: Vec<&WildSample> = self
            .samples
            .iter()
            .filter(|s| s.payload != Payload::Unknown)
            .collect();
        labelled.sort_by(|a, b| a.id.cmp(&b.id));
        labelled
    }

    /// Provenance records whose last human check predates
    /// [`PROVENANCE_STALE_AFTER_DAYS`] before `today`.
    ///
    /// The reference date is a parameter rather than a clock read, so the
    /// result is reproducible and a caller can only read the clock once per
    /// run. `today` is `"YYYY-MM-DD"`.
    pub fn stale(&self, today: &str) -> Result<Vec<StaleProvenance>, StegError> {
        let now = parse_iso_date(today)
            .map_err(|why| reject(format!("the reference date {today:?} is not usable: {why}")))?;
        let mut stale = Vec::new();
        for sample in &self.samples {
            // Validated on construction, so this cannot fail for a manifest
            // that came through `from_toml`; a hand-built one is the caller's
            // problem and gets the same loud error.
            let then = parse_iso_date(&sample.provenance.verified).map_err(|why| {
                reject(format!(
                    "sample {:?} has an unusable provenance.verified: {why}",
                    sample.id
                ))
            })?;
            let age = now - then;
            if age > PROVENANCE_STALE_AFTER_DAYS {
                stale.push(StaleProvenance {
                    id: sample.id.clone(),
                    verified: sample.provenance.verified.clone(),
                    age_days: age,
                });
            }
        }
        stale.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(stale)
    }
}

/// A short, boring identifier: printable ASCII, no separators, no whitespace.
///
/// The separators are the point. This manifest is handed to whoever provisions
/// the isolated machine, and a field called `id` is exactly where somebody
/// writes `/home/me/cases/2026-114/exhibit-3.png` without thinking twice.
fn check_id(field: &str, value: &str) -> Result<(), StegError> {
    if value.is_empty() {
        return Err(reject(format!("an empty {field}")));
    }
    if value.len() > MAX_ID_BYTES {
        return Err(reject(format!(
            "a {field} of {} bytes, past the {MAX_ID_BYTES} limit",
            value.len()
        )));
    }
    if let Some(bad) = value.chars().find(|c| {
        matches!(c, '/' | '\\' | ':') || c.is_whitespace() || c.is_control() || !c.is_ascii()
    }) {
        return Err(reject(format!(
            "the {field} {value:?} contains {bad:?}; these fields hold a short \
             identifier and never a path or a description"
        )));
    }
    Ok(())
}

/// A media type: `type/subtype`, lowercase, with the restricted character set
/// RFC 6838 allows.
///
/// Checked separately from [`check_id`] rather than by relaxing it, because the
/// one character a media type needs is the one character an identifier most
/// needs to refuse. `image/png` is a media type; `image/../../etc/passwd` is
/// not, and neither is anything with a second slash in it.
fn check_media(sample_id: &str, value: &str) -> Result<(), StegError> {
    let ok = value.len() <= MAX_ID_BYTES
        && value.split('/').count() == 2
        && value.split('/').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'+' | b'-')
                })
        });
    if !ok {
        return Err(reject(format!(
            "sample {sample_id:?} has a media type of {value:?}. This field is one \
             lowercase media type such as \"image/png\", and nothing else: a path would \
             fit here otherwise"
        )));
    }
    Ok(())
}

/// Free text: bounded, non-blank, and no control characters other than the
/// newlines a multi-line TOML string legitimately carries.
fn check_text(sample_id: &str, field: &str, value: &str) -> Result<(), StegError> {
    if value.trim().is_empty() {
        return Err(reject(format!(
            "{sample_id:?} leaves {field} blank. Every note field in this format is \
             mandatory: a blank one reads as \"fine\" when what it means is \"nobody \
             wrote down what was checked\""
        )));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(reject(format!(
            "{sample_id:?} has a {field} of {} bytes, past the {MAX_TEXT_BYTES} limit",
            value.len()
        )));
    }
    if let Some(bad) = value
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        return Err(reject(format!(
            "{sample_id:?} has a {field} containing the control character {bad:?}"
        )));
    }
    Ok(())
}

fn check_lowercase(sample_id: &str, field: &str, value: &str) -> Result<(), StegError> {
    if value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(reject(format!(
            "sample {sample_id:?} writes its {field} as {value:?} in mixed case; this \
             format is lowercase so the same {field} is one row in a per-{field} table \
             and not two"
        )));
    }
    Ok(())
}

fn check_lowercase_digest(sample_id: &str, digest: &str) -> Result<(), StegError> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(reject(format!(
            "sample {sample_id:?} has a sha256 field that is not 64 hex characters"
        )));
    }
    if digest.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(reject(format!(
            "sample {sample_id:?} writes its sha256 in uppercase; this format is \
             lowercase so one file is one entry and not two"
        )));
    }
    Ok(())
}

/// Days since 1970-01-01 for a `"YYYY-MM-DD"` string, by the proleptic
/// Gregorian calendar.
///
/// Hand-rolled rather than taken from a date crate, because the only arithmetic
/// this module needs is "how many days between these two dates" and a
/// dependency is a decision (baseline Section 5). The algorithm is Howard
/// Hinnant's `days_from_civil`, which is the standard one and is covered by its
/// own tests below.
fn parse_iso_date(text: &str) -> Result<i64, String> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err("expected exactly YYYY-MM-DD, as a quoted string".to_string());
    }
    let field = |from: usize, to: usize, what: &str| -> Result<i64, String> {
        let slice = &text[from..to];
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("the {what} is not all digits"));
        }
        slice
            .parse::<i64>()
            .map_err(|_| format!("the {what} is not a number"))
    };
    let year = field(0, 4, "year")?;
    let month = field(5, 7, "month")?;
    let day = field(8, 10, "day")?;

    if !(1..=12).contains(&month) {
        return Err(format!("month {month} is not a month"));
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    };
    if !(1..=last).contains(&day) {
        return Err(format!(
            "day {day} is not a day in month {month} of {year}, which has {last}"
        ));
    }

    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(era * 146_097 + day_of_era - 719_468)
}

fn reject(reason: String) -> StegError {
    StegError::Internal(format!(
        "this wild-sample manifest cannot be used: {reason}"
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn provenance() -> Provenance {
        Provenance {
            origin: "Named in a published vendor write-up.".to_string(),
            reobtain: "Search the sharing service by digest with a researcher account.".to_string(),
            verified: "2026-10-01".to_string(),
            note: "The write-up states this digest. Nothing here was compared against bytes."
                .to_string(),
        }
    }

    fn terms() -> Terms {
        Terms {
            licence: "none-stated".to_string(),
            redistributable: false,
            note: "No licence attaches. Research use by the account holder only.".to_string(),
        }
    }

    pub(crate) fn sample(id: &str, digest_char: char, payload: Payload) -> WildSample {
        WildSample {
            id: id.to_string(),
            sha256: digest_char.to_string().repeat(64),
            bytes: 184_320,
            media: "image/png".to_string(),
            family: "worok".to_string(),
            campaign: Some("worok-2022-png-loader".to_string()),
            payload,
            tool: match payload {
                Payload::Carries => Some("worok-custom-lsb".to_string()),
                _ => None,
            },
            truth_basis: match payload {
                Payload::Unknown => None,
                _ => Some("Vendor report, not independently confirmed.".to_string()),
            },
            provenance: provenance(),
            terms: terms(),
        }
    }

    pub(crate) fn manifest() -> WildManifest {
        WildManifest {
            format: WILD_MANIFEST_FORMAT,
            corpus: "wild-d2".to_string(),
            note: "Candidate list for D2. Nothing in it has been fetched.".to_string(),
            compiled: "2026-10-01".to_string(),
            samples: vec![
                sample("b-002", 'b', Payload::Clean),
                sample("a-001", 'a', Payload::Carries),
                sample("c-003", 'c', Payload::Unknown),
            ],
        }
    }

    #[test]
    fn a_well_formed_manifest_validates() {
        manifest().validate().expect("valid");
    }

    #[test]
    fn it_round_trips_through_toml() {
        let written = manifest();
        let text = written.to_review_toml().expect("serialise");
        let read = WildManifest::from_toml(&text).expect("parse");
        let mut expected = written;
        expected.canonicalise();
        assert_eq!(expected, read);
    }

    #[test]
    fn canonicalising_sorts_by_id_so_a_diff_is_stable() {
        let mut once = manifest();
        once.canonicalise();
        let ids: Vec<&str> = once.samples.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["a-001", "b-002", "c-003"]);
    }

    #[test]
    fn the_format_has_nowhere_to_put_sample_content() {
        // Structural, not aspirational: the serialised form of a whole
        // manifest is text, and the only long fields in it are prose a human
        // wrote. If anybody ever adds a bytes field, this stops being true and
        // the review that lets it through has this test to answer to.
        let text = manifest().to_review_toml().expect("serialise");
        assert!(text.is_ascii(), "the example manifest is plain text");
        assert!(!text.contains("content"));
    }

    #[test]
    fn an_unlabelled_sample_is_excluded_from_grading() {
        let labelled = manifest();
        let ids: Vec<&str> = labelled.labelled().iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["a-001", "b-002"]);
    }

    #[test]
    fn a_tool_name_on_a_clean_sample_is_refused() {
        let mut m = manifest();
        m.samples[0].tool = Some("steghide".to_string());
        let err = m.validate().expect_err("contradiction");
        assert!(err.to_string().contains("one of the two is wrong"));
    }

    #[test]
    fn a_label_with_no_truth_basis_is_refused() {
        let mut m = manifest();
        m.samples[1].truth_basis = None;
        let err = m.validate().expect_err("no basis");
        assert!(err
            .to_string()
            .contains("cannot be told apart from a guess"));
    }

    #[test]
    fn a_blank_provenance_note_is_refused() {
        let mut m = manifest();
        m.samples[0].provenance.note = "   \n".to_string();
        let err = m.validate().expect_err("blank note");
        assert!(err.to_string().contains("mandatory"));
    }

    #[test]
    fn an_id_holding_a_path_is_refused() {
        let mut m = manifest();
        m.samples[0].id = "/home/me/cases/exhibit-3.png".to_string();
        let err = m.validate().expect_err("path in id");
        assert!(err.to_string().contains("never a path"));
    }

    #[test]
    fn an_uppercase_digest_is_refused_rather_than_silently_lowercased() {
        let mut m = manifest();
        m.samples[0].sha256 = m.samples[0].sha256.to_uppercase();
        let err = m.validate().expect_err("uppercase");
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn a_short_digest_is_refused() {
        let mut m = manifest();
        m.samples[0].sha256 = "abc".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn a_mixed_case_family_is_refused_so_a_per_family_table_has_one_row() {
        let mut m = manifest();
        m.samples[0].family = "Worok".to_string();
        let err = m.validate().expect_err("mixed case");
        assert!(err.to_string().contains("one row"));
    }

    #[test]
    fn two_samples_with_one_id_are_refused() {
        let mut m = manifest();
        m.samples[1].id = m.samples[0].id.clone();
        let err = m.validate().expect_err("duplicate id");
        assert!(err.to_string().contains("share the id"));
    }

    #[test]
    fn two_samples_with_one_real_digest_are_refused() {
        let mut m = manifest();
        m.samples[1].sha256 = "a".repeat(63) + "b";
        m.samples[0].sha256 = m.samples[1].sha256.clone();
        let err = m.validate().expect_err("duplicate digest");
        assert!(err.to_string().contains("counts it twice"));
    }

    #[test]
    fn placeholder_digests_may_repeat_because_a_draft_has_nothing_else_to_write() {
        let mut m = manifest();
        m.samples[0].sha256 = "0".repeat(64);
        m.samples[1].sha256 = "0".repeat(64);
        m.validate().expect("placeholders are allowed to collide");
        assert!(m.samples[0].digest_is_a_placeholder());
    }

    #[test]
    fn a_measured_digest_is_not_mistaken_for_a_placeholder() {
        let real = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut m = manifest();
        m.samples[0].sha256 = real.to_string();
        assert!(!m.samples[0].digest_is_a_placeholder());
    }

    #[test]
    fn a_zero_byte_entry_is_refused() {
        let mut m = manifest();
        m.samples[0].bytes = 0;
        assert!(m.validate().is_err());
    }

    #[test]
    fn an_implausible_size_is_refused_before_anything_reads_it() {
        let mut m = manifest();
        m.samples[0].bytes = MAX_SAMPLE_BYTES + 1;
        assert!(m.validate().is_err());
    }

    #[test]
    fn a_wrong_format_version_is_refused_loudly() {
        let mut m = manifest();
        m.format = 99;
        let err = m.validate().expect_err("format");
        assert!(err.to_string().contains("this build reads"));
    }

    #[test]
    fn an_oversized_manifest_is_refused_before_the_parser_sees_it() {
        let huge = "#".repeat(MAX_MANIFEST_BYTES as usize + 1);
        let err = WildManifest::from_toml(&huge).expect_err("too big");
        assert!(err.to_string().contains("past the"));
    }

    #[test]
    fn an_unquoted_date_gets_an_explanation_rather_than_a_type_error() {
        let text = "\
format = 1
corpus = \"wild-d2\"
note = \"draft\"
compiled = 2026-10-01
";
        let err = WildManifest::from_toml(text).expect_err("unquoted date");
        assert!(err.to_string().contains("quoted strings"), "got: {err}");
    }

    #[test]
    fn iso_dates_parse_and_the_epoch_is_where_it_should_be() {
        assert_eq!(parse_iso_date("1970-01-01").expect("epoch"), 0);
        assert_eq!(parse_iso_date("1970-01-02").expect("day one"), 1);
        assert_eq!(parse_iso_date("1969-12-31").expect("before"), -1);
        assert_eq!(
            parse_iso_date("2000-03-01").expect("after a leap day"),
            11_017
        );
        assert_eq!(parse_iso_date("2026-10-01").expect("today"), 20_727);
    }

    #[test]
    fn a_leap_day_is_accepted_only_in_a_leap_year() {
        parse_iso_date("2024-02-29").expect("2024 is a leap year");
        parse_iso_date("2000-02-29").expect("2000 is a leap year");
        assert!(parse_iso_date("1900-02-29").is_err(), "1900 is not");
        assert!(parse_iso_date("2026-02-29").is_err(), "2026 is not");
    }

    #[test]
    fn malformed_dates_are_refused_with_a_reason() {
        for bad in [
            "2026-13-01",
            "2026-00-10",
            "2026-10-32",
            "2026-10-00",
            "26-10-01",
            "2026/10/01",
            "2026-1x-01",
            "",
            "2026-10-01T00:00:00Z",
        ] {
            assert!(parse_iso_date(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn stale_provenance_is_reported_against_a_passed_in_date_not_a_clock() {
        let m = manifest();
        assert!(m.stale("2026-10-01").expect("same day").is_empty());
        assert!(m.stale("2027-01-01").expect("92 days later").is_empty());
        let stale = m.stale("2027-06-01").expect("243 days later");
        assert_eq!(stale.len(), 3);
        assert_eq!(stale[0].id, "a-001");
        assert_eq!(stale[0].age_days, 243);
    }

    #[test]
    fn a_bad_reference_date_fails_loudly_rather_than_reporting_nothing_stale() {
        let err = manifest().stale("yesterday").expect_err("not a date");
        assert!(err.to_string().contains("not usable"));
    }

    #[test]
    fn a_manifest_with_no_samples_is_allowed_because_a_draft_starts_empty() {
        let mut m = manifest();
        m.samples.clear();
        m.validate()
            .expect("an empty manifest is a legitimate draft");
        assert!(m.labelled().is_empty());
    }
}
