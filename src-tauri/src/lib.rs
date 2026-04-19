// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

use stegcore_core::{analysis, errors::StegError, steg, utils, verses};

// ── Settings ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_font_size")]
    pub font_size: String,
    #[serde(default)]
    pub reduce_motion: bool,
    #[serde(default = "default_cipher")]
    pub default_cipher: String,
    #[serde(default = "default_mode")]
    pub default_mode: String,
    #[serde(default)]
    pub default_output_folder: Option<String>,
    #[serde(default)]
    pub auto_export_key: bool,
    #[serde(default = "default_true")]
    pub auto_score_on_drop: bool,
    #[serde(default = "default_passphrase_min_len")]
    pub passphrase_min_len: u32,
    #[serde(default = "default_clear_clipboard_secs")]
    pub clear_clipboard_secs: u32,
    #[serde(default)]
    pub session_timeout_mins: u32,
    #[serde(default)]
    pub show_technical_errors: bool,
    #[serde(default)]
    pub bible_verses: bool,
    #[serde(default = "default_report_format")]
    pub default_report_format: String,
    #[serde(default)]
    pub report_output_folder: Option<String>,
}

fn default_theme() -> String {
    "system".into()
}
fn default_font_size() -> String {
    "default".into()
}
fn default_cipher() -> String {
    "chacha20-poly1305".into()
}
fn default_mode() -> String {
    "adaptive".into()
}
fn default_true() -> bool {
    true
}
fn default_passphrase_min_len() -> u32 {
    12
}
fn default_clear_clipboard_secs() -> u32 {
    30
}
fn default_report_format() -> String {
    "pdf".into()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: default_theme(),
            font_size: default_font_size(),
            reduce_motion: false,
            default_cipher: default_cipher(),
            default_mode: default_mode(),
            default_output_folder: None,
            auto_export_key: false,
            auto_score_on_drop: true,
            passphrase_min_len: default_passphrase_min_len(),
            clear_clipboard_secs: default_clear_clipboard_secs(),
            session_timeout_mins: 0,
            show_technical_errors: false,
            bible_verses: false,
            default_report_format: default_report_format(),
            report_output_folder: None,
        }
    }
}

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
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(app: &tauri::AppHandle, s: &Settings) -> Result<(), StegError> {
    let Some(path) = settings_path(app) else {
        return Err(StegError::Io(std::io::Error::other(
            "Could not resolve app config directory",
        )));
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StegError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json = serde_json::to_string_pretty(s).map_err(StegError::Json)?;
    std::fs::write(&path, json).map_err(StegError::Io)
}

// ── Tauri IPC commands ────────────────────────────────────────────────────────

#[tauri::command]
fn get_supported_formats() -> Vec<String> {
    utils::supported_extensions()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

const MAX_COVER_BYTES: u64 = 2_000_000_000; // 2 GB
#[allow(dead_code)]
const MAX_PAYLOAD_BYTES: u64 = 500_000_000; // 500 MB — used in embed validation

#[tauri::command]
async fn score_cover(path: String) -> Result<f64, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = Path::new(&path);
        utils::validate_file(p, MAX_COVER_BYTES)?;
        steg::assess(p)
    })
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
        let cover_path = Path::new(&cover);
        let out_path = Path::new(&output);
        let pass_bytes = passphrase.as_bytes();
        let payload_bytes = std::fs::read(Path::new(&payload)).map_err(StegError::Io)?;

        if deniable {
            let decoy_path = decoy_payload.as_deref().ok_or(StegError::EmptyPayload)?;
            let decoy_pass_str = decoy_passphrase.as_deref().unwrap_or("");
            if decoy_pass_str.is_empty() {
                return Err(StegError::EmptyPayload);
            }
            let decoy_pass = decoy_pass_str.as_bytes().to_vec();
            let decoy_bytes = std::fs::read(Path::new(decoy_path)).map_err(StegError::Io)?;

            let (real_kf, decoy_kf) = steg::embed_deniable(
                cover_path,
                &payload_bytes,
                &decoy_bytes,
                pass_bytes,
                &decoy_pass,
                &cipher,
                out_path,
            )?;

            // Only write key files if user explicitly requested export
            let (real_kf_path, decoy_kf_path) = if export_key {
                let rkp = format!("{}.real.json", output);
                let dkp = format!("{}.decoy.json", output);
                stegcore_core::keyfile::write_key_file(Path::new(&rkp), &real_kf)?;
                stegcore_core::keyfile::write_key_file(Path::new(&dkp), &decoy_kf)?;
                (Some(rkp), Some(dkp))
            } else {
                (None, None)
            };

            return Ok(serde_json::json!({
                "outputPath":     output,
                "keyFilePath":    real_kf_path,
                "decoyKeyPath":   decoy_kf_path,
            }));
        }

        let maybe_kf = if mode == "sequential" {
            steg::embed_sequential(
                cover_path,
                &payload_bytes,
                pass_bytes,
                &cipher,
                out_path,
                export_key,
            )?
        } else {
            steg::embed_adaptive(
                cover_path,
                &payload_bytes,
                pass_bytes,
                &cipher,
                out_path,
                export_key,
            )?
        };

        let key_file_path = if export_key {
            if let Some(kf) = maybe_kf {
                let p = format!("{output}.json");
                stegcore_core::keyfile::write_key_file(Path::new(&p), &kf)?;
                Some(p)
            } else {
                None
            }
        } else {
            None
        };

        Ok(serde_json::json!({
            "outputPath":  output,
            "keyFilePath": key_file_path,
        }))
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
        let stego_path = Path::new(&stego);
        let pass_bytes = passphrase.as_bytes();

        if let Some(kf_path) = key_file.as_deref() {
            let kf = stegcore_core::keyfile::read_key_file(Path::new(kf_path))?;
            steg::extract_with_keyfile(stego_path, &kf, pass_bytes)
        } else {
            steg::extract(stego_path, pass_bytes)
        }
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

    // Phase 2: full analysis in background — emits event when done
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
    tauri::async_runtime::spawn_blocking(move || analysis::analyse(Path::new(&path)))
        .await
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn analyse_batch_files(paths: Vec<String>) -> Vec<serde_json::Value> {
    tauri::async_runtime::spawn_blocking(move || {
        let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
        analysis::analyse_batch(&path_refs)
            .into_iter()
            .map(|r| match r {
                Ok(report) => serde_json::to_value(report).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::Value::String(e.to_string()),
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
async fn export_html_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
        let results = analysis::analyse_batch(&path_refs);
        let reports: Vec<analysis::AnalysisReport> =
            results.into_iter().filter_map(|r| r.ok()).collect();
        Ok(analysis::generate_html_report(&reports))
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn export_csv_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
        let results = analysis::analyse_batch(&path_refs);
        let reports: Vec<analysis::AnalysisReport> =
            results.into_iter().filter_map(|r| r.ok()).collect();
        Ok(analysis::generate_csv_report(&reports))
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

#[tauri::command]
async fn export_json_report(paths: Vec<String>) -> Result<String, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
        let results = analysis::analyse_batch(&path_refs);
        let reports: Vec<analysis::AnalysisReport> =
            results.into_iter().filter_map(|r| r.ok()).collect();
        Ok(analysis::generate_json_report(&reports))
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

// ── Pixel diff ──────────────────────────────────────────────────────

#[tauri::command]
async fn pixel_diff(original: String, stego: String) -> Result<serde_json::Value, StegError> {
    tauri::async_runtime::spawn_blocking(move || {
        let orig = image::open(Path::new(&original))
            .map_err(|e| StegError::Image(e.to_string()))?
            .to_rgb8();
        let steg_img = image::open(Path::new(&stego))
            .map_err(|e| StegError::Image(e.to_string()))?
            .to_rgb8();

        if orig.dimensions() != steg_img.dimensions() {
            return Ok(serde_json::json!({ "error": "Different dimensions" }));
        }

        let (w, h) = orig.dimensions();
        let total = (w * h) as usize;
        let orig_raw = orig.as_raw();
        let steg_raw = steg_img.as_raw();

        let mut changed = 0usize;
        let mut max_delta: u8 = 0;
        let mut lsb_only = true;

        for p in 0..total {
            let i = p * 3;
            if orig_raw[i] != steg_raw[i]
                || orig_raw[i + 1] != steg_raw[i + 1]
                || orig_raw[i + 2] != steg_raw[i + 2]
            {
                changed += 1;
                for c in 0..3 {
                    let d = orig_raw[i + c].abs_diff(steg_raw[i + c]);
                    if d > max_delta {
                        max_delta = d;
                    }
                    if d > 1 {
                        lsb_only = false;
                    }
                }
            }
        }

        Ok(serde_json::json!({
            "totalPixels": total,
            "changedPixels": changed,
            "percentChanged": (changed as f64 / total as f64) * 100.0,
            "maxDelta": max_delta,
            "lsbOnly": lsb_only,
        }))
    })
    .await
    .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?
}

// ── Open folder (cross-platform) ─────────────────────────────────────────────

#[tauri::command]
async fn open_folder(path: String) -> Result<(), String> {
    let dir = Path::new(&path);
    // If it's a file, get its parent directory
    let folder = if dir.is_file() {
        dir.parent().unwrap_or(dir)
    } else {
        dir
    };

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── File info ───────────────────────────────────────────────────────

#[tauri::command]
fn file_size(path: String) -> Result<u64, StegError> {
    let meta = std::fs::metadata(Path::new(&path)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StegError::FileNotFound(path)
        } else {
            StegError::Io(e)
        }
    })?;
    Ok(meta.len())
}

// ── Bible verse ─────────────────────────────────────────────────────

#[tauri::command]
fn get_verse() -> serde_json::Value {
    let v = verses::current_verse();
    serde_json::json!({ "text": v.text, "reference": v.reference })
}

// ── First-run detection ──────────────────────────────────────────────────

#[tauri::command]
fn is_first_run(app: tauri::AppHandle) -> bool {
    let Some(config_dir) = app.path().app_config_dir().ok() else {
        return true;
    };
    !config_dir.join(".stegcore_configured").exists()
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
    std::fs::create_dir_all(&config_dir).map_err(StegError::Io)?;
    let marker = config_dir.join(".stegcore_configured");
    std::fs::write(&marker, "1").map_err(StegError::Io)?;

    // Apply initial preferences
    let mut settings = load_settings(&app);
    settings.theme = theme;
    settings.default_cipher = default_cipher;
    save_settings(&app, &settings)?;
    Ok(())
}

// ── Settings ─────────────────────────────────────────────────────────────

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
            get_verse,
            is_first_run,
            complete_setup,
            get_settings,
            set_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Stegcore");
}
