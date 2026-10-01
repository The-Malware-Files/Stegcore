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

//! The acceptable-use gate, tested as a gate rather than as a set of functions.
//!
//! Every test here asks the same question from a different angle: can key
//! recovery be reached without the authorisation it is supposed to require? The
//! unit tests in `bruteforce::authorisation` check that each piece works; these
//! check that the pieces cannot be stepped around.
//!
//! One thing deliberately **not** tested here, because the surface does not
//! exist: the gate has no public-key signature scheme. A manifest is
//! authenticated with a shared secret, which proves the holder of that secret
//! produced it and nothing more. `AUP.md` section 3.2 asks for "a key the
//! operator controls", which a shared secret satisfies, but a third party cannot
//! verify a manifest without being handed the secret, and handing it over lets
//! them forge the next one. That is an operator decision, recorded in the report
//! for this work rather than silently resolved.

use std::path::{Path, PathBuf};

use stegcore_engine::bruteforce::authorisation::{
    authorise, hash_file, Manifest, Policy, Refusal, Request, POLICY_FILE,
};
use stegcore_engine::bruteforce::digest::{hex, hmac_sha256};

fn case(dir: &Path) -> PathBuf {
    let path = dir.join("suspect.png");
    std::fs::write(&path, b"pretend this is a carrier").unwrap();
    path
}

fn confirmed() -> Request {
    Request {
        confirmed: true,
        manifest: None,
        invocation: "stegcore brute-force suspect.png --openstego --i-am-authorised".into(),
    }
}

fn signed_manifest(body: &str, key: &[u8]) -> Manifest {
    let tag = hmac_sha256(key, body.as_bytes());
    Manifest::parse(&format!("{body}\nsignature = {}\n", hex(&tag))).unwrap()
}

#[test]
fn the_gate_refuses_when_the_flag_is_absent_however_else_the_run_is_set_up() {
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());

    // A valid manifest, a permissive policy and a readable file. The only thing
    // missing is the operator's own confirmation, and that alone is enough.
    std::fs::write(dir.path().join(POLICY_FILE), "brute_force_enabled = true\n").unwrap();
    let key = b"engagement key".to_vec();
    let request = Request {
        confirmed: false,
        manifest: Some((signed_manifest("client = Acme", &key), key)),
        invocation: "stegcore brute-force suspect.png".into(),
    };
    assert_eq!(
        *authorise(&request, &input, dir.path()).unwrap_err(),
        Refusal::NotConfirmed,
        "a valid manifest must not stand in for the operator's own confirmation"
    );
}

#[test]
fn the_record_carries_every_field_the_policy_commits_to() {
    // AUP.md section 3.1 lists five things. All five, checked by name.
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    let request = confirmed();
    let record = authorise(&request, &input, dir.path()).unwrap();

    assert_eq!(record.invocation, request.invocation, "the invocation");
    assert!(!record.operator.is_empty(), "the operator");
    assert!(!record.hostname.is_empty(), "the hostname");
    assert!(record.timestamp_unix > 1_577_836_800, "a timestamp");
    assert_eq!(
        record.input_sha256,
        hash_file(&input).unwrap(),
        "a checksum of the input"
    );
    assert_eq!(record.outcome, "not recovered", "the outcome, either way");
}

#[test]
fn a_policy_disabling_the_capability_cannot_be_overridden_by_the_flag_or_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    std::fs::write(
        dir.path().join(POLICY_FILE),
        "brute_force_enabled = false\nreason = \"handle through the forensics team\"\n",
    )
    .unwrap();

    // Flag alone.
    assert!(matches!(
        *authorise(&confirmed(), &input, dir.path()).unwrap_err(),
        Refusal::DisabledByPolicy { .. }
    ));

    // Flag plus a perfectly valid manifest. A third party's authorisation does
    // not outrank the organisation's own policy on its own machines.
    let key = b"engagement key".to_vec();
    let with_manifest = Request {
        confirmed: true,
        manifest: Some((signed_manifest("client = Acme", &key), key)),
        invocation: "stegcore brute-force".into(),
    };
    assert!(matches!(
        *authorise(&with_manifest, &input, dir.path()).unwrap_err(),
        Refusal::DisabledByPolicy { .. }
    ));
}

#[test]
fn a_forged_manifest_is_rejected_and_a_valid_one_accepted_under_the_same_policy() {
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    std::fs::write(
        dir.path().join(POLICY_FILE),
        "require_signed_manifest = true\n",
    )
    .unwrap();
    let key = b"engagement key".to_vec();
    let body = "client = Acme\nscope = one laptop image\nuntil = 2026-12-31";

    let valid = Request {
        confirmed: true,
        manifest: Some((signed_manifest(body, &key), key.clone())),
        invocation: "stegcore brute-force".into(),
    };
    let record = authorise(&valid, &input, dir.path()).unwrap();
    assert!(record.manifest_verified);
    assert!(record.manifest_sha256.is_some());

    // The forgery that matters: widen the scope, keep the tag.
    let tag = hmac_sha256(&key, body.as_bytes());
    let forged = Manifest::parse(&format!(
        "client = Acme\nscope = the entire fleet\nuntil = 2026-12-31\nsignature = {}\n",
        hex(&tag)
    ))
    .unwrap();
    let request = Request {
        confirmed: true,
        manifest: Some((forged, key)),
        invocation: "stegcore brute-force".into(),
    };
    assert!(matches!(
        *authorise(&request, &input, dir.path()).unwrap_err(),
        Refusal::ManifestRejected { .. }
    ));
}

#[test]
fn a_manifest_requirement_cannot_be_met_by_an_unsigned_one() {
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    std::fs::write(
        dir.path().join(POLICY_FILE),
        "require_signed_manifest = true\n",
    )
    .unwrap();
    assert!(matches!(
        *authorise(&confirmed(), &input, dir.path()).unwrap_err(),
        Refusal::ManifestRequired { .. }
    ));
    // And an unsigned file does not even parse as a manifest, so there is no
    // route where one reaches the gate unchecked.
    assert!(Manifest::parse("client = Acme\n").is_err());
}

/// Both environment checks live in one test on purpose: they mutate process
/// environment, tests in a file share one process, and two of them setting
/// variables concurrently would be a race rather than a test.
#[test]
fn no_environment_variable_and_no_existing_consent_switches_the_gate_off() {
    // The bypass to rule out: a variable that an operator or a script could set
    // to make the gate pass without the flag. The names here are every plausible
    // candidate, including the ones this workspace really does honour elsewhere
    // (`STEGCORE_CONFIG_DIR` relocates the watermarking consent marker, and
    // `STEGCORE_PASSPHRASE` feeds the embed commands).
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    let unconfirmed = Request {
        confirmed: false,
        manifest: None,
        invocation: "stegcore brute-force suspect.png".into(),
    };

    for name in [
        "STEGCORE_I_AM_AUTHORISED",
        "STEGCORE_AUTHORISED",
        "STEGCORE_BRUTE_FORCE",
        "STEGCORE_FORCE",
        "STEGCORE_CONFIG_DIR",
        "STEGCORE_PASSPHRASE",
        "STEGCORE_SKIP_AUP",
        "SKIP_AUP",
        "I_AM_AUTHORISED",
    ] {
        // Safety: this test process sets and clears one variable at a time, and
        // the gate reads none of them, which is what is being established.
        std::env::set_var(name, "1");
        let refusal = *authorise(&unconfirmed, &input, dir.path()).unwrap_err();
        std::env::remove_var(name);
        assert_eq!(
            refusal,
            Refusal::NotConfirmed,
            "{name} changed the gate's answer, which makes it a bypass"
        );
    }

    // The most tempting shortcut in this codebase, and the reason it is wrong:
    // `watermark` records consent once per machine and never asks again. Reusing
    // that marker here would mean anybody who had ever watermarked a file on
    // this machine could recover keys with no further confirmation, and the
    // per-run record AUP.md section 3.1 asks for would not exist. The marker is
    // written by hand rather than through the core crate, which cannot be a
    // dependency here because core already depends on the engine.
    let config = dir.path().join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join(".watermarking_consent"),
        br#"{"granted":true,"surface":"cli","granted_at_unix":1700000000}"#,
    )
    .unwrap();
    std::env::set_var("STEGCORE_CONFIG_DIR", &config);
    let refusal = *authorise(&unconfirmed, &input, dir.path()).unwrap_err();
    std::env::remove_var("STEGCORE_CONFIG_DIR");
    assert_eq!(
        refusal,
        Refusal::NotConfirmed,
        "a recorded watermarking consent must not authorise key recovery"
    );
}

#[test]
fn a_policy_cannot_be_disarmed_by_a_misspelling_or_by_junk() {
    // An organisation that switches the capability off must not be able to fail
    // open. Both of these refuse the run rather than reverting to the default.
    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());

    for text in [
        "brute_force_enabledd = false\n",
        "brute_force_enabled = no\n",
        "brute_force_enabled: false\n",
        "<<<<<<< HEAD\nbrute_force_enabled = false\n",
    ] {
        std::fs::write(dir.path().join(POLICY_FILE), text).unwrap();
        let refusal = *authorise(&confirmed(), &input, dir.path()).unwrap_err();
        assert!(
            refusal.message().contains("refused"),
            "{text:?} did not refuse the run; it read as {refusal:?}"
        );
    }
}

#[test]
fn a_policy_above_the_case_directory_still_applies() {
    // Moving the file into a subdirectory must not escape the policy.
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("evidence").join("2026").join("case-12");
    std::fs::create_dir_all(&nested).unwrap();
    let input = case(&nested);
    std::fs::write(
        dir.path().join(POLICY_FILE),
        "brute_force_enabled = false\n",
    )
    .unwrap();
    assert!(matches!(
        *authorise(&confirmed(), &input, &nested).unwrap_err(),
        Refusal::DisabledByPolicy { .. }
    ));
}

#[test]
fn every_refusal_says_what_to_do_next_and_carries_no_hyphens_in_its_prose() {
    // Baseline section 8: no hyphens in user-facing strings. Flags are
    // identifiers and are exempt, so they are stripped before the check.
    let dir = tempfile::tempdir().unwrap();
    let refusals = [
        Refusal::NotConfirmed,
        Refusal::DisabledByPolicy {
            policy_path: PathBuf::from("/case/.stegcore-policy.toml"),
            reason: Some("ask the forensics team".into()),
        },
        Refusal::DisabledByPolicy {
            policy_path: dir.path().join(POLICY_FILE),
            reason: None,
        },
        Refusal::ManifestRequired {
            policy_path: PathBuf::from("/case/.stegcore-policy.toml"),
        },
        Refusal::ManifestRejected {
            reason: "the signature does not match".into(),
        },
    ];
    for refusal in refusals {
        let message = refusal.message();
        assert!(!message.is_empty());
        let prose: String = message
            .split_whitespace()
            .filter(|word| !word.starts_with("--") && !word.contains('/'))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            !prose.contains('-'),
            "a hyphen reached user-facing prose: {prose:?}"
        );
    }
}

#[test]
fn the_default_policy_is_permissive_and_that_is_deliberate() {
    // Recorded as a test so the choice is visible rather than incidental: with
    // no policy file, the capability is available. A tool that refused to work
    // until somebody wrote a policy file would be worked around, and a tool
    // nobody uses enforces nothing.
    let policy = Policy::default();
    assert!(policy.brute_force_enabled);
    assert!(!policy.require_signed_manifest);

    let dir = tempfile::tempdir().unwrap();
    let input = case(dir.path());
    assert!(Policy::discover(dir.path()).unwrap().is_none());
    assert!(authorise(&confirmed(), &input, dir.path()).is_ok());
}
