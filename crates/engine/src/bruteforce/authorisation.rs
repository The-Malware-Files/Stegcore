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

//! The authorisation gate in front of key recovery.
//!
//! Recovering the key a steganography tool used is the same operation whether
//! the person running it is an examiner with a warrant or somebody reading
//! another person's private message. Nothing in software can tell those apart,
//! and this module does not pretend to. What it does is make the operation
//! deliberate and recorded: it cannot be reached by accident, it cannot be
//! reached by a script that stumbled into the wrong subcommand, and when it is
//! reached it writes down who ran it, against what, and when.
//!
//! `AUP.md` section 3.1 is the governing policy and it names five things the
//! record must carry: the invocation, the operator's account and host, a
//! timestamp, a SHA-256 of the input, and the recovered key or the fact that
//! nothing was recovered. [`Record`] is that list, in that order.
//!
//! # Three layers, and what each is honestly worth
//!
//! | Layer | Stops | Does not stop |
//! |---|---|---|
//! | The flag | Running it by accident, or without having read what it does | Anybody who means to run it |
//! | The policy file | An organisation's own machines running it where policy says no | Somebody who can edit the file |
//! | The signed manifest | Claiming an engagement nobody authorised | Somebody holding the signing key |
//!
//! That table is the whole security model and it is deliberately unflattering.
//! The gate is a discipline, not a lock, and `AUP.md` says as much: *"The gates
//! are not technical DRM."* Writing the limits down here is what keeps a later
//! reader from mistaking the gate for an enforcement mechanism and relying on
//! it as one.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bruteforce::digest::{digests_equal, hex, hmac_sha256, Sha256};
use crate::errors::StegError;

/// File name of the organisation policy file.
pub const POLICY_FILE: &str = ".stegcore-policy.toml";

/// Largest policy file that will be read. A policy is a handful of lines; a
/// larger file is a mistake or an attempt to make the parser work.
const MAX_POLICY_BYTES: u64 = 64 * 1024;

/// Largest manifest that will be read, for the same reason.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Directories above the working directory that are searched for a policy file.
///
/// Bounded so a deeply nested path cannot turn one invocation into thousands of
/// directory reads, and so a policy cannot be planted twenty levels up where
/// nobody would look for it.
const MAX_POLICY_SEARCH_DEPTH: usize = 32;

/// Why an attempt to run key recovery was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The operator did not confirm they are authorised.
    NotConfirmed,
    /// A policy file in force disables the capability.
    DisabledByPolicy {
        /// Where the policy was found, so the operator can go and read it.
        policy_path: PathBuf,
        /// What the policy gave as its reason, if it gave one.
        reason: Option<String>,
    },
    /// A policy file requires a signed engagement manifest and none was given.
    ManifestRequired {
        /// Where the policy was found.
        policy_path: PathBuf,
    },
    /// A manifest was given and did not verify.
    ManifestRejected {
        /// Why, in terms an operator can act on.
        reason: String,
    },
}

impl Refusal {
    /// What to tell the operator. Plain language, and always with the next step,
    /// because a refusal that does not say how to proceed legitimately just
    /// reads as a broken tool.
    pub fn message(&self) -> String {
        match self {
            Refusal::NotConfirmed => "Key recovery requires authorisation. Run it again with \
                 --i-am-authorised to confirm you are permitted to recover keys from this file. \
                 Your account name, this machine's name, the time and a checksum of the file are \
                 written into the report."
                .to_string(),
            Refusal::DisabledByPolicy {
                policy_path,
                reason,
            } => match reason {
                Some(reason) => format!(
                    "Key recovery is switched off by the policy file at {}. The reason it gives: \
                     {reason}",
                    policy_path.display()
                ),
                None => format!(
                    "Key recovery is switched off by the policy file at {}. Ask whoever \
                     maintains that file.",
                    policy_path.display()
                ),
            },
            Refusal::ManifestRequired { policy_path } => format!(
                "The policy file at {} requires a signed engagement manifest for key recovery. \
                 Pass one with --manifest, along with the key that signs it.",
                policy_path.display()
            ),
            Refusal::ManifestRejected { reason } => {
                format!("The engagement manifest was not accepted: {reason}")
            }
        }
    }
}

/// An organisation's policy on key recovery, read from [`POLICY_FILE`].
///
/// The default, when no file is found, is that the capability is available and
/// no manifest is required. That is deliberate: a tool that refused to work
/// until an organisation wrote a policy file would simply not be used, and an
/// unused tool enforces nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Policy {
    /// Whether key recovery may run at all.
    #[serde(default = "default_true")]
    pub brute_force_enabled: bool,
    /// Whether a signed engagement manifest is required.
    #[serde(default)]
    pub require_signed_manifest: bool,
    /// The reason to show when the capability is switched off.
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            brute_force_enabled: true,
            require_signed_manifest: false,
            reason: None,
        }
    }
}

impl Policy {
    /// Parse a policy from TOML-shaped text.
    ///
    /// Deliberately **fails loud on malformed input** rather than falling back
    /// to the permissive default. A policy file that cannot be parsed is the one
    /// case where guessing is dangerous: an organisation that wrote
    /// `brute_force_enabled = flase` must get an error, not a capability.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        parse_policy_toml(text)
    }

    /// Find and read the policy file in force for `start`, searching it and then
    /// each parent directory.
    ///
    /// Returns `Ok(None)` when no policy file exists anywhere on the path, which
    /// is the ordinary case.
    pub fn discover(start: &Path) -> Result<Option<(PathBuf, Self)>, StegError> {
        let mut directory = if start.is_dir() {
            Some(start.to_path_buf())
        } else {
            start.parent().map(|p| p.to_path_buf())
        };
        for _ in 0..MAX_POLICY_SEARCH_DEPTH {
            let Some(current) = directory else { break };
            let candidate = current.join(POLICY_FILE);
            if candidate.is_file() {
                let size = std::fs::metadata(&candidate)?.len();
                if size > MAX_POLICY_BYTES {
                    return Err(StegError::UnsupportedFormat(format!(
                        "the policy file at {} is {size} bytes, far larger than a policy should \
                         be. It has not been read. Check whether it is the file you think it is.",
                        candidate.display()
                    )));
                }
                let text = std::fs::read_to_string(&candidate)?;
                let policy = Self::parse(&text).map_err(|e| {
                    StegError::UnsupportedFormat(format!(
                        "the policy file at {} could not be read: {e}. Key recovery has been \
                         refused rather than allowed, because a policy nobody can read is not a \
                         policy that permits anything.",
                        candidate.display()
                    ))
                })?;
                return Ok(Some((candidate, policy)));
            }
            directory = current.parent().map(|p| p.to_path_buf());
        }
        Ok(None)
    }
}

/// A minimal reader for the three keys a policy file carries.
///
/// The engine takes no TOML dependency, and this grammar is three scalar
/// assignments: enough to be written out here, and small enough that its
/// failure modes are all visible. Unknown keys are an error rather than being
/// ignored, because a policy whose author misspelled the key that switches the
/// capability off must not silently leave it on.
fn parse_policy_toml(text: &str) -> Result<Policy, StegError> {
    let mut policy = Policy::default();
    let mut seen_section = false;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            // One section is allowed, `[brute_force]`, and it is optional.
            if line == "[brute_force]" && !seen_section {
                seen_section = true;
                continue;
            }
            return Err(StegError::UnsupportedFormat(format!(
                "line {}: {line:?} is not a section this policy file may contain. The only one \
                 allowed is [brute_force].",
                number + 1
            )));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(StegError::UnsupportedFormat(format!(
                "line {}: {line:?} is not a setting. Each line reads name = value.",
                number + 1
            )));
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "brute_force_enabled" => policy.brute_force_enabled = parse_bool(value, number + 1)?,
            "require_signed_manifest" => {
                policy.require_signed_manifest = parse_bool(value, number + 1)?
            }
            "reason" => policy.reason = Some(parse_string(value, number + 1)?),
            other => {
                return Err(StegError::UnsupportedFormat(format!(
                    "line {}: {other:?} is not a setting this policy file understands. Allowed: \
                     brute_force_enabled, require_signed_manifest, reason.",
                    number + 1
                )))
            }
        }
    }
    Ok(policy)
}

fn parse_bool(value: &str, line: usize) -> Result<bool, StegError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(StegError::UnsupportedFormat(format!(
            "line {line}: {other:?} is not true or false."
        ))),
    }
}

fn parse_string(value: &str, line: usize) -> Result<String, StegError> {
    let trimmed = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| {
            StegError::UnsupportedFormat(format!(
                "line {line}: a text setting must be in double quotes."
            ))
        })?;
    if trimmed.contains('"') {
        return Err(StegError::UnsupportedFormat(format!(
            "line {line}: a text setting may not contain a double quote."
        )));
    }
    Ok(trimmed.to_string())
}

/// A signed statement that an engagement authorises this work.
///
/// The body is whatever the authorising party wrote; this module does not
/// interpret it beyond requiring that it is not empty. What it does check is
/// that the tag was produced by somebody holding the key, which is what
/// separates a manifest from a text file anybody could write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The body as signed, byte for byte. Kept exactly as read, because
    /// re-serialising it would change what the signature covers.
    pub body: String,
    /// The tag, as the hexadecimal the file carries.
    pub tag_hex: String,
}

impl Manifest {
    /// Read a manifest file.
    ///
    /// The format is the body, then a line reading `signature = <hex>` as the
    /// last non-empty line. The signature line is not part of what is signed,
    /// which is the one subtlety and the reason it has to be last.
    pub fn load(path: &Path) -> Result<Self, StegError> {
        if !path.exists() {
            return Err(StegError::FileNotFound(path.display().to_string()));
        }
        let size = std::fs::metadata(path)?.len();
        if size > MAX_MANIFEST_BYTES {
            return Err(StegError::UnsupportedFormat(format!(
                "the manifest at {} is {size} bytes, larger than a manifest should be. It has \
                 not been read.",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse a manifest from its text.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        let mut body_lines: Vec<&str> = Vec::new();
        let mut tag_hex = None;
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("signature") {
                if let Some(value) = rest.trim().strip_prefix('=') {
                    if tag_hex.is_some() {
                        return Err(StegError::UnsupportedFormat(
                            "the manifest carries more than one signature line, so there is no \
                             way to tell which one is meant to be checked."
                                .into(),
                        ));
                    }
                    tag_hex = Some(value.trim().trim_matches('"').to_string());
                    continue;
                }
            }
            body_lines.push(line);
        }
        let tag_hex = tag_hex.ok_or_else(|| {
            StegError::UnsupportedFormat(
                "the manifest has no signature line. Add one reading: signature = <hexadecimal>."
                    .into(),
            )
        })?;
        // Trailing blank lines left by the signature line's removal are dropped,
        // so a manifest signs the same bytes whether or not an editor added a
        // final newline.
        while body_lines.last().map(|l| l.trim().is_empty()) == Some(true) {
            body_lines.pop();
        }
        let body = body_lines.join("\n");
        if body.trim().is_empty() {
            return Err(StegError::UnsupportedFormat(
                "the manifest has a signature but nothing signed. It must describe what work is \
                 authorised, by whom, and for how long."
                    .into(),
            ));
        }
        Ok(Self { body, tag_hex })
    }

    /// The tag this manifest's body should carry for `key`.
    pub fn expected_tag(&self, key: &[u8]) -> [u8; 32] {
        hmac_sha256(key, self.body.as_bytes())
    }

    /// Whether the tag was produced by a holder of `key`.
    ///
    /// Compared in constant time, so a forged tag cannot be refined one byte at
    /// a time by watching how long the check takes.
    pub fn verify(&self, key: &[u8]) -> Result<(), Refusal> {
        if key.is_empty() {
            return Err(Refusal::ManifestRejected {
                reason: "the signing key is empty, so the signature could not be checked".into(),
            });
        }
        let Some(presented) = decode_hex(&self.tag_hex) else {
            return Err(Refusal::ManifestRejected {
                reason: format!(
                    "the signature {:?} is not hexadecimal, so it cannot be a signature",
                    truncate(&self.tag_hex, 24)
                ),
            });
        };
        if presented.len() != 32 {
            return Err(Refusal::ManifestRejected {
                reason: format!(
                    "the signature is {} bytes; a valid one is 32",
                    presented.len()
                ),
            });
        }
        if digests_equal(&presented, &self.expected_tag(key)) {
            Ok(())
        } else {
            Err(Refusal::ManifestRejected {
                reason: "the signature does not match the text it covers. Either the manifest was \
                         edited after it was signed, or it was signed with a different key."
                    .into(),
            })
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect::<String>() + "…"
}

/// What the caller is asking to do, and what it brought with it.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Whether the operator passed the confirmation flag.
    pub confirmed: bool,
    /// A manifest and the key to check it with, if one was supplied.
    pub manifest: Option<(Manifest, Vec<u8>)>,
    /// The exact command line, recorded verbatim in the report.
    pub invocation: String,
}

/// The record written when key recovery runs, per `AUP.md` section 3.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The exact invocation string.
    pub invocation: String,
    /// The operator's account name, as the environment reports it.
    pub operator: String,
    /// This machine's name.
    pub hostname: String,
    /// Seconds since the Unix epoch. Captured once per operation, so every line
    /// of one report carries the same time.
    pub timestamp_unix: u64,
    /// SHA-256 of the file examined, as lowercase hexadecimal.
    pub input_sha256: String,
    /// Whether a signed manifest was presented and verified.
    pub manifest_verified: bool,
    /// SHA-256 of the manifest body, when there was one, so the report names
    /// which authorisation it ran under without copying the text of it.
    pub manifest_sha256: Option<String>,
    /// The recovered key, or the words that nothing was recovered. `AUP.md`
    /// commits to recording either, and the negative matters as much as the
    /// positive: it is the evidence that the search ran and came back empty.
    pub outcome: String,
}

/// The phrase recorded when a search found nothing, fixed so a report is
/// searchable and two runs agree.
pub const NOTHING_RECOVERED: &str = "not recovered";

/// Decide whether key recovery may run, and build the record if it may.
///
/// The order of the checks is the order of increasing authority: the flag is the
/// operator's own word, the policy is their organisation's, and the manifest is
/// a third party's. A later layer may forbid what an earlier one allowed and
/// never the reverse.
pub fn authorise(
    request: &Request,
    input: &Path,
    policy_root: &Path,
) -> Result<Record, Box<Refusal>> {
    if !request.confirmed {
        return Err(Box::new(Refusal::NotConfirmed));
    }

    let discovered = Policy::discover(policy_root).map_err(|e| {
        Box::new(Refusal::ManifestRejected {
            reason: e.to_string(),
        })
    })?;

    let mut manifest_verified = false;
    let mut manifest_sha256 = None;

    if let Some((policy_path, policy)) = &discovered {
        if !policy.brute_force_enabled {
            return Err(Box::new(Refusal::DisabledByPolicy {
                policy_path: policy_path.clone(),
                reason: policy.reason.clone(),
            }));
        }
        if policy.require_signed_manifest && request.manifest.is_none() {
            return Err(Box::new(Refusal::ManifestRequired {
                policy_path: policy_path.clone(),
            }));
        }
    }

    if let Some((manifest, key)) = &request.manifest {
        manifest.verify(key).map_err(Box::new)?;
        manifest_verified = true;
        manifest_sha256 = Some(hex(&crate::bruteforce::digest::sha256_bytes(
            manifest.body.as_bytes(),
        )));
    }

    let input_sha256 = hash_file(input).map_err(|e| {
        Box::new(Refusal::ManifestRejected {
            reason: format!("the file to examine could not be read to record its checksum: {e}"),
        })
    })?;

    Ok(Record {
        invocation: request.invocation.clone(),
        operator: operator_name(),
        hostname: host_name(),
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        input_sha256,
        manifest_verified,
        manifest_sha256,
        outcome: NOTHING_RECOVERED.to_string(),
    })
}

/// SHA-256 of a file, read in bounded chunks so a large carrier is not held in
/// memory just to be hashed.
pub fn hash_file(path: &Path) -> Result<String, StegError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalise()))
}

/// The operator's account name.
///
/// Read from the environment, which an operator can of course set to anything.
/// That is acceptable and worth being explicit about: the record is evidence
/// that somebody ran the tool and accepted the terms, not proof of identity. A
/// record nobody can forge would need an identity system this tool does not have
/// and should not pretend to.
fn operator_name() -> String {
    for key in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                return value;
            }
        }
    }
    "unknown".to_string()
}

/// This machine's name, by the same reasoning as [`operator_name`].
fn host_name() -> String {
    if let Ok(value) = std::env::var("HOSTNAME") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    // `/etc/hostname` is the portable-enough fallback on the platforms this
    // ships for, and its absence is not worth failing an operation over.
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn signed(body: &str, key: &[u8]) -> String {
        let tag = hmac_sha256(key, body.as_bytes());
        format!("{body}\nsignature = {}\n", hex(&tag))
    }

    #[test]
    fn without_the_flag_the_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "data");
        let request = Request {
            confirmed: false,
            ..Default::default()
        };
        let refusal = *authorise(&request, &input, dir.path()).unwrap_err();
        assert_eq!(refusal, Refusal::NotConfirmed);
        assert!(refusal.message().contains("--i-am-authorised"));
    }

    #[test]
    fn with_the_flag_the_record_carries_everything_the_policy_requires() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "abc");
        let request = Request {
            confirmed: true,
            manifest: None,
            invocation: "stegcore brute-force --openstego carrier.bin --i-am-authorised".into(),
        };
        let record = authorise(&request, &input, dir.path()).unwrap();
        assert_eq!(record.invocation, request.invocation);
        assert!(!record.operator.is_empty());
        assert!(!record.hostname.is_empty());
        assert!(record.timestamp_unix > 1_577_836_800);
        assert_eq!(
            record.input_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!record.manifest_verified);
        assert_eq!(record.outcome, NOTHING_RECOVERED);
    }

    #[test]
    fn a_policy_that_disables_the_capability_overrides_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "data");
        write(
            dir.path(),
            POLICY_FILE,
            "brute_force_enabled = false\nreason = \"not permitted on company machines\"\n",
        );
        let request = Request {
            confirmed: true,
            ..Default::default()
        };
        let refusal = *authorise(&request, &input, dir.path()).unwrap_err();
        match &refusal {
            Refusal::DisabledByPolicy { reason, .. } => {
                assert_eq!(reason.as_deref(), Some("not permitted on company machines"));
            }
            other => panic!("expected a policy refusal, got {other:?}"),
        }
        assert!(refusal
            .message()
            .contains("not permitted on company machines"));
    }

    #[test]
    fn a_policy_in_a_parent_directory_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        write(dir.path(), POLICY_FILE, "brute_force_enabled = false\n");
        let (found, policy) = Policy::discover(&nested).unwrap().expect("should be found");
        assert_eq!(found, dir.path().join(POLICY_FILE));
        assert!(!policy.brute_force_enabled);
    }

    #[test]
    fn the_nearest_policy_wins_over_one_further_up() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("team");
        std::fs::create_dir_all(&nested).unwrap();
        write(dir.path(), POLICY_FILE, "brute_force_enabled = false\n");
        write(&nested, POLICY_FILE, "brute_force_enabled = true\n");
        let (found, policy) = Policy::discover(&nested).unwrap().unwrap();
        assert_eq!(found, nested.join(POLICY_FILE));
        assert!(policy.brute_force_enabled);
    }

    #[test]
    fn no_policy_file_anywhere_means_the_default() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Policy::discover(dir.path()).unwrap().is_none());
        let default = Policy::default();
        assert!(default.brute_force_enabled);
        assert!(!default.require_signed_manifest);
    }

    #[test]
    fn a_policy_requiring_a_manifest_refuses_a_bare_run() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "data");
        write(dir.path(), POLICY_FILE, "require_signed_manifest = true\n");
        let request = Request {
            confirmed: true,
            ..Default::default()
        };
        let refusal = *authorise(&request, &input, dir.path()).unwrap_err();
        assert!(matches!(refusal, Refusal::ManifestRequired { .. }));
        assert!(refusal.message().contains("--manifest"));
    }

    #[test]
    fn a_valid_manifest_is_accepted_and_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "data");
        write(dir.path(), POLICY_FILE, "require_signed_manifest = true\n");
        let key = b"an engagement signing key".to_vec();
        let body = "client = Acme\nscope = one laptop image\nuntil = 2026-12-31";
        let manifest = Manifest::parse(&signed(body, &key)).unwrap();
        let request = Request {
            confirmed: true,
            manifest: Some((manifest, key)),
            invocation: "stegcore brute-force".into(),
        };
        let record = authorise(&request, &input, dir.path()).unwrap();
        assert!(record.manifest_verified);
        assert!(record.manifest_sha256.is_some());
    }

    #[test]
    fn a_forged_manifest_is_rejected() {
        let key = b"the real key".to_vec();
        let body = "client = Acme\nscope = one laptop image";
        let mut text = signed(body, &key);
        // Edit the body after signing, which is the forgery that matters: the
        // attacker widens the scope and keeps the tag.
        text = text.replace("one laptop image", "the entire fleet");
        let manifest = Manifest::parse(&text).unwrap();
        let refusal = manifest.verify(&key).unwrap_err();
        match &refusal {
            Refusal::ManifestRejected { reason } => assert!(reason.contains("does not match")),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_signed_with_the_wrong_key_is_rejected() {
        let body = "client = Acme";
        let manifest = Manifest::parse(&signed(body, b"key one")).unwrap();
        assert!(manifest.verify(b"key two").is_err());
    }

    #[test]
    fn a_manifest_with_a_malformed_or_missing_signature_is_rejected() {
        let manifest = Manifest::parse("client = Acme\nsignature = not-hex-at-all\n").unwrap();
        match manifest.verify(b"key").unwrap_err() {
            Refusal::ManifestRejected { reason } => assert!(reason.contains("not hexadecimal")),
            other => panic!("expected a rejection, got {other:?}"),
        }

        let short = Manifest::parse("client = Acme\nsignature = abcd\n").unwrap();
        match short.verify(b"key").unwrap_err() {
            Refusal::ManifestRejected { reason } => assert!(reason.contains("2 bytes")),
            other => panic!("expected a rejection, got {other:?}"),
        }

        assert!(Manifest::parse("client = Acme\n")
            .unwrap_err()
            .to_string()
            .contains("no signature line"));
    }

    #[test]
    fn an_empty_signing_key_is_rejected_rather_than_treated_as_a_key() {
        let manifest = Manifest::parse(&signed("client = Acme", b"")).unwrap();
        match manifest.verify(b"").unwrap_err() {
            Refusal::ManifestRejected { reason } => assert!(reason.contains("empty")),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_with_a_signature_but_no_text_is_rejected() {
        assert!(Manifest::parse("signature = 00\n")
            .unwrap_err()
            .to_string()
            .contains("nothing signed"));
    }

    #[test]
    fn two_signature_lines_are_rejected_rather_than_one_being_picked() {
        assert!(
            Manifest::parse("client = A\nsignature = 00\nsignature = 11\n")
                .unwrap_err()
                .to_string()
                .contains("more than one signature")
        );
    }

    #[test]
    fn a_trailing_newline_does_not_change_what_was_signed() {
        let key = b"k".to_vec();
        let body = "client = Acme";
        let with = Manifest::parse(&format!("{}\n\n", signed(body, &key).trim_end())).unwrap();
        assert!(with.verify(&key).is_ok());
    }

    #[test]
    fn a_misspelled_policy_key_is_an_error_rather_than_a_silent_default() {
        // The case this exists for: somebody meant to switch the capability off
        // and typed the name wrongly. Ignoring the line would leave it on.
        let err = Policy::parse("brute_force_enabledd = false\n").unwrap_err();
        assert!(err.to_string().contains("not a setting"));
    }

    #[test]
    fn a_malformed_policy_value_is_an_error() {
        assert!(Policy::parse("brute_force_enabled = flase\n")
            .unwrap_err()
            .to_string()
            .contains("not true or false"));
        assert!(Policy::parse("brute_force_enabled\n")
            .unwrap_err()
            .to_string()
            .contains("not a setting"));
        assert!(Policy::parse("reason = unquoted\n")
            .unwrap_err()
            .to_string()
            .contains("double quotes"));
    }

    #[test]
    fn a_policy_may_use_the_optional_section_header_and_comments() {
        let policy = Policy::parse(
            "# our policy\n[brute_force]\nbrute_force_enabled = true  # for now\n\
             require_signed_manifest = true\nreason = \"ask the lead\"\n",
        )
        .unwrap();
        assert!(policy.brute_force_enabled);
        assert!(policy.require_signed_manifest);
        assert_eq!(policy.reason.as_deref(), Some("ask the lead"));
    }

    #[test]
    fn an_unknown_section_is_rejected() {
        assert!(Policy::parse("[something_else]\n")
            .unwrap_err()
            .to_string()
            .contains("not a section"));
    }

    #[test]
    fn an_unreadable_policy_refuses_the_run_rather_than_allowing_it() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "carrier.bin", "data");
        write(dir.path(), POLICY_FILE, "this is not a policy at all\n");
        let request = Request {
            confirmed: true,
            ..Default::default()
        };
        let refusal = *authorise(&request, &input, dir.path()).unwrap_err();
        assert!(refusal.message().contains("refused"));
    }

    #[test]
    fn an_over_large_policy_file_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            POLICY_FILE,
            &"# padding\n".repeat((MAX_POLICY_BYTES as usize / 10) + 10),
        );
        assert!(Policy::discover(dir.path())
            .unwrap_err()
            .to_string()
            .contains("not been read"));
    }

    #[test]
    fn an_over_large_manifest_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "big.manifest",
            &"x".repeat(MAX_MANIFEST_BYTES as usize + 1),
        );
        assert!(Manifest::load(&path)
            .unwrap_err()
            .to_string()
            .contains("not been read"));
    }

    #[test]
    fn a_manifest_round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"k".to_vec();
        let path = write(dir.path(), "job.manifest", &signed("client = Acme", &key));
        let manifest = Manifest::load(&path).unwrap();
        assert!(manifest.verify(&key).is_ok());
        assert!(matches!(
            Manifest::load(Path::new("/nonexistent/job.manifest")).unwrap_err(),
            StegError::FileNotFound(_)
        ));
    }

    #[test]
    fn an_unreadable_input_file_refuses_rather_than_recording_a_wrong_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let request = Request {
            confirmed: true,
            ..Default::default()
        };
        let missing = dir.path().join("not-there.bin");
        let refusal = *authorise(&request, &missing, dir.path()).unwrap_err();
        assert!(refusal.message().contains("checksum"));
    }

    #[test]
    fn hashing_a_file_in_chunks_agrees_with_hashing_it_whole() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            hash_file(&path).unwrap(),
            hex(&crate::bruteforce::digest::sha256_bytes(&data))
        );
    }

    #[test]
    fn hex_decoding_rejects_odd_lengths_and_non_digits() {
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("00f"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex(""), None);
    }

    #[test]
    fn long_values_are_truncated_in_messages_rather_than_pasted_whole() {
        let long = "a".repeat(100);
        assert!(truncate(&long, 10).chars().count() <= 11);
        assert_eq!(truncate("short", 10), "short");
    }

    #[test]
    fn the_operator_and_host_are_never_empty() {
        assert!(!operator_name().is_empty());
        assert!(!host_name().is_empty());
    }

    #[test]
    fn a_policy_serialises_for_a_report() {
        let policy = Policy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), policy);
    }
}
