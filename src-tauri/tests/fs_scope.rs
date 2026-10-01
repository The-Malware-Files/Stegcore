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

//! Does the GUI's save button actually write a file?
//!
//! The question cannot be answered by reading `capabilities/default.json`,
//! because the answer depends on how the fs plugin combines that file with its
//! own runtime scope, and a careful reading of the plugin source is still a
//! reading. So this test stands the real thing up instead: a Tauri app on the
//! mock runtime, built from this crate's real `tauri.conf.json` and real
//! capability file, with the real `tauri_plugin_fs` mounted, and then drives the
//! same `plugin:fs|write_text_file` command the frontend's `writeTextFile` call
//! lands on. No webview, no window manager, no desktop; everything from the IPC
//! boundary inwards is production code.
//!
//! The mock runtime has no GTK or webkit dependency, which is what makes this
//! runnable on a headless machine and in CI.

use std::path::Path;

use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
use tauri::webview::InvokeRequest;

use stegcore_tauri_lib::save_scope::{grant_save_target, ScopeGrant};

/// The capability file declares `"windows": ["main"]`, so a webview under any
/// other label would be denied for the wrong reason and the test would prove
/// nothing.
const WINDOW_LABEL: &str = "main";

fn app() -> tauri::App<tauri::test::MockRuntime> {
    mock_builder()
        .plugin(tauri_plugin_fs::init())
        .build(tauri::generate_context!())
        .expect("failed to build the mock app")
}

/// Ask the fs plugin to write `contents` to `path`, exactly as the frontend's
/// `writeTextFile(path, contents)` does: the path rides in a header,
/// percent-encoded, and the bytes are the request body.
fn write_text_file(
    webview: &tauri::WebviewWindow<tauri::test::MockRuntime>,
    path: &Path,
    contents: &str,
) -> Result<(), String> {
    let encoded = percent_encode(&path.to_string_lossy());
    let mut headers = tauri::http::HeaderMap::new();
    headers.insert("path", encoded.parse().expect("header value"));

    get_ipc_response(
        webview,
        InvokeRequest {
            cmd: "plugin:fs|write_text_file".into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            // The webview's own URL, so the capability's local-origin rule
            // matches and the refusal under test is the scope one rather than an
            // origin mismatch of the test's own making.
            url: webview.url().expect("webview url"),
            body: InvokeBody::Raw(contents.as_bytes().to_vec()),
            headers,
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Percent-encode everything the plugin's decoder could otherwise misread. Not
/// a general-purpose encoder: it only has to survive a header round trip for the
/// paths these tests use.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b'~' | b':') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The bug, demonstrated rather than argued: with the capability file as it
/// stands and no runtime grant, the write is refused.
///
/// If this ever starts failing, the static capability has been widened (or the
/// plugin changed) and the runtime grant is no longer the only thing that lets a
/// save through. That is a decision, not a drive-by, so the test is left to
/// catch it.
#[test]
fn a_write_with_no_runtime_grant_is_refused() {
    let app = app();
    let webview = tauri::WebviewWindowBuilder::new(&app, WINDOW_LABEL, Default::default())
        .build()
        .expect("failed to build the mock webview");

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("report.json");

    let err = write_text_file(&webview, &target, "{}")
        .expect_err("the write was expected to be refused with no grant in place");
    assert!(
        err.to_lowercase().contains("forbidden"),
        "expected a forbidden-path refusal, got: {err}"
    );
    assert!(
        !target.exists(),
        "the plugin refused and yet a file appeared at {}",
        target.display()
    );
}

/// The fix, demonstrated the same way: grant that one path at runtime and the
/// identical write succeeds, with the bytes on disk to show for it.
#[test]
fn a_write_after_a_runtime_grant_succeeds() {
    let app = app();
    let webview = tauri::WebviewWindowBuilder::new(&app, WINDOW_LABEL, Default::default())
        .build()
        .expect("failed to build the mock webview");

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("report.json");

    let scope = stegcore_tauri_lib::PluginScope::for_app(&app).expect("fs scope");
    let granted = grant_save_target(&scope, &target).expect("the grant was expected to succeed");

    write_text_file(&webview, &granted, "{\"verdict\":\"clean\"}")
        .expect("the write was expected to succeed once the path was granted");
    assert_eq!(
        std::fs::read_to_string(&granted).expect("read back"),
        "{\"verdict\":\"clean\"}"
    );
}

/// Granting one file does not quietly grant its neighbours. This is the
/// property that makes the runtime grant narrower than the static capability it
/// replaces, so it is worth holding down.
#[test]
fn a_grant_for_one_file_does_not_cover_another_in_the_same_folder() {
    let app = app();
    let webview = tauri::WebviewWindowBuilder::new(&app, WINDOW_LABEL, Default::default())
        .build()
        .expect("failed to build the mock webview");

    let dir = tempfile::tempdir().expect("tempdir");
    let chosen = dir.path().join("chosen.json");
    let other = dir.path().join("not-chosen.json");

    let scope = stegcore_tauri_lib::PluginScope::for_app(&app).expect("fs scope");
    let granted = grant_save_target(&scope, &chosen).expect("grant");
    write_text_file(&webview, &granted, "{}").expect("the granted file must be writable");

    let err = write_text_file(&webview, &other, "{}")
        .expect_err("a file the user never chose must stay unwritable");
    assert!(
        err.to_lowercase().contains("forbidden"),
        "expected a forbidden-path refusal, got: {err}"
    );
    assert!(!other.exists());
}

/// The production `ScopeGrant` implementation forwards to the plugin's scope and
/// reports a failure rather than swallowing it. Checked here rather than in the
/// unit tests because only a live app has a scope to forward to.
#[test]
fn the_production_scope_grant_reaches_the_plugin() {
    let app = app();
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("x.bin");

    let scope = stegcore_tauri_lib::PluginScope::for_app(&app).expect("fs scope");
    assert!(ScopeGrant::allow_file(&scope, &target).is_ok());
}
