// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Tauri runtime glue: the thin `#[tauri::command]` wrappers, the AppHandle
//! settings resolution, and `run()`. Each wrapper resolves its String args
//! (or the AppHandle's config dir) and delegates to a path-explicit impl in
//! `lib.rs`. This file is intentionally logic-free; the impls behind it carry
//! the correctness story and are unit-tested in `tests/commands.rs`. Because
//! these wrappers can only be reached through a live Tauri runtime, this file
//! is the one surface excluded from the coverage gate (see CLAUDE.md A7).

use std::path::{Path, PathBuf};

use tauri::{Emitter, Manager};

use stegcore_core::{analysis, errors::StegError};

use crate::{
    analyse_batch_impl, analyse_file_impl, complete_setup_in, embed_impl, export_csv_impl,
    export_html_impl, export_json_impl, extract_impl, file_size_impl, folder_for_path,
    grant_watermark_consent_impl, is_first_run_for, load_settings_from, pixel_diff_impl,
    read_watermark_impl, save_settings_to, score_cover_impl, supported_formats_impl, verse_value,
    watermark_formats_impl, watermark_has_consent_impl, watermark_impl, Settings,
};

// ── AppHandle settings resolution ───────────────────────────────────────────

fn settings_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|d| d.join("settings.json"))
}

fn load_settings(app: &tauri::AppHandle) -> Settings {
    let Some(path) = settings_path(app) else {
        return Settings::default();
    };
    load_settings_from(&path)
}

fn save_settings(app: &tauri::AppHandle, s: &Settings) -> Result<(), StegError> {
    let Some(path) = settings_path(app) else {
        return Err(StegError::Io(std::io::Error::other(
            "Could not resolve app config directory",
        )));
    };
    save_settings_to(&path, s)
}

// ── Tauri IPC commands ───────────────────────────────────────────────────────

#[tauri::command]
fn get_supported_formats() -> Vec<String> {
    supported_formats_impl()
}

#[tauri::command]
async fn score_cover(path: String) -> Result<f64, StegError> {
    tauri::async_runtime::spawn_blocking(move || score_cover_impl(Path::new(&path)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command(rename_all = "camelCase")]
#[allow(clippy::too_many_arguments)]
async fn embed(
    cover: String,
    payload: String,
    passphrase: String,
    cipher: String,
    mode: String,
    deniable: bool,
    decoy_payload: Option<String>,
    decoy_passphrase: Option<String>,
    export_key: bool,
    output: String,
) -> Result<serde_json::Value, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        embed_impl(
            Path::new(&cover),
            Path::new(&payload),
            passphrase.as_bytes(),
            &cipher,
            &mode,
            deniable,
            decoy_payload.as_deref().map(Path::new),
            decoy_passphrase.as_deref(),
            export_key,
            Path::new(&output),
        )
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command(rename_all = "camelCase")]
async fn extract(
    stego: String,
    passphrase: String,
    key_file: Option<String>,
) -> Result<Vec<u8>, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        extract_impl(
            Path::new(&stego),
            passphrase.as_bytes(),
            key_file.as_deref().map(Path::new),
        )
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn analyse_file_progressive(
    app: tauri::AppHandle,
    path: String,
) -> Result<analysis::AnalysisReport, StegError> {
    // Phase 1: fast sampled analysis (returned to frontend immediately)
    let fast_path = path.clone();
    let fast_report =
        tauri::async_runtime::spawn_blocking(move || analysis::analyse_fast(Path::new(&fast_path)))
            .await
            .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))??;

    // Phase 2: full analysis in background; emits event when done
    let bg_path = path;
    tauri::async_runtime::spawn(async move {
        let result =
            tauri::async_runtime::spawn_blocking(move || analysis::analyse(Path::new(&bg_path)))
                .await;
        match result {
            Ok(Ok(report)) => {
                let json = serde_json::to_string(&report).unwrap_or_default();
                let _ = app.emit("analysis_complete", json);
            }
            Ok(Err(e)) => {
                log::warn!("Full analysis failed: {e}");
                // Emit error event so frontend knows analysis completed (with failure)
                let _ = app.emit("analysis_complete_error", e.to_string());
            }
            Err(e) => {
                log::warn!("Full analysis task panicked: {e}");
            }
        }
    });

    Ok(fast_report)
}

#[tauri::command]
async fn analyse_file(path: String) -> Result<analysis::AnalysisReport, StegError> {
    tauri::async_runtime::spawn_blocking(move || analyse_file_impl(Path::new(&path)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn analyse_batch_files(paths: Vec<String>) -> Vec<serde_json::Value> {
    tauri::async_runtime::spawn_blocking(move || analyse_batch_impl(&paths))
        .await
        .unwrap_or_default()
}

#[tauri::command]
async fn export_html_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || Ok(export_html_impl(&paths)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn export_csv_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || Ok(export_csv_impl(&paths)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn export_json_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || Ok(export_json_impl(&paths)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn pixel_diff(original: String, stego: String) -> Result<serde_json::Value, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        pixel_diff_impl(Path::new(&original), Path::new(&stego))
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn open_folder(path: String) -> Result<(), String> {
    let folder = folder_for_path(Path::new(&path));

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn file_size(path: String) -> Result<u64, StegError> {
    file_size_impl(Path::new(&path))
}

#[tauri::command]
fn watermark_formats() -> Vec<String> {
    watermark_formats_impl()
}

#[tauri::command]
fn watermark_has_consent() -> bool {
    watermark_has_consent_impl()
}

#[tauri::command]
fn grant_watermark_consent() -> Result<(), StegError> {
    grant_watermark_consent_impl()
}

#[tauri::command(rename_all = "camelCase")]
async fn watermark_file(
    cover: String,
    mark: String,
    passphrase: String,
    cipher: String,
    output: String,
) -> Result<String, StegError> {
    // Key derivation (Argon2) runs here, so do the work off the UI thread.
    tauri::async_runtime::spawn_blocking(move || {
        watermark_impl(
            Path::new(&cover),
            &mark,
            passphrase.as_bytes(),
            &cipher,
            Path::new(&output),
        )
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command(rename_all = "camelCase")]
async fn read_watermark_file(path: String, passphrase: String) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        read_watermark_impl(Path::new(&path), passphrase.as_bytes())
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
fn get_verse() -> serde_json::Value {
    verse_value()
}

#[tauri::command]
fn is_first_run(app: tauri::AppHandle) -> bool {
    let dir = app.path().app_config_dir().ok();
    is_first_run_for(dir.as_deref())
}

#[tauri::command(rename_all = "camelCase")]
fn complete_setup(
    app: tauri::AppHandle,
    theme: String,
    default_cipher: String,
) -> Result<(), StegError> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?;
    complete_setup_in(&config_dir, theme, default_cipher)
}

#[tauri::command]
fn get_settings(app: tauri::AppHandle) -> Settings {
    load_settings(&app)
}

#[tauri::command]
fn set_settings(app: tauri::AppHandle, settings: Settings) -> Result<(), StegError> {
    save_settings(&app, &settings)
}

// ── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Warm rayon thread pool during splash so first analysis has no cold-start
            std::thread::spawn(|| {
                rayon::scope(|_| {});
            });

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            get_supported_formats,
            score_cover,
            embed,
            extract,
            analyse_file,
            analyse_file_progressive,
            analyse_batch_files,
            export_html_report,
            export_csv_report,
            export_json_report,
            pixel_diff,
            open_folder,
            file_size,
            watermark_formats,
            watermark_has_consent,
            grant_watermark_consent,
            watermark_file,
            read_watermark_file,
            get_verse,
            is_first_run,
            complete_setup,
            get_settings,
            set_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Stegcore");
}
