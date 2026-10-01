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

//! `stegcore detect-covert` — statistical covert-channel features from a capture.
//!
//! Ungated, per AUP Section 3.2: "The defensive companion (statistical detection
//! of covert-channel patterns from PCAP input) is ungated; that is the surface
//! defenders need." It opens no sockets and needs no privilege.
//!
//! # Why this prints what it prints
//!
//! The output is built around one hazard. Three of this detector's feature
//! families were measured and found wanting: the timing features point the wrong
//! way against legitimate constant-bitrate traffic, the unique-name ratios sit at
//! chance against realistic traffic, and most DNS features only work when the
//! tunnel dominates the capture. A screen that printed all of them in one list
//! would invite a reader to treat a number measured at chance as a finding.
//!
//! So the renderer follows the engine's own `FeatureRole` table rather than a
//! list of its own, and says three things separately: what was examined, what the
//! features that can actually discriminate say, and what is reported for
//! description only. A capture where nothing was found and a capture where
//! nothing that could discriminate was even present do not print the same
//! thing. That is the same defect that got `Clean` renamed to "Nothing found",
//! in a sharper form, because here the weak features are the loudest numbers.

use std::path::PathBuf;
use std::sync::Arc;

use crossterm::style::Color;
use stegcore_core::errors::StegError;
use stegcore_engine::covert::detect::{self, CovertReport, FeatureRole};

use crate::output::{self, JsonOut, Spinner};

#[derive(Debug, clap::Args)]
pub struct DetectCovertArgs {
    /// Packet capture to analyse (classic pcap; convert pcapng with `tshark -F pcap`)
    pub capture: PathBuf,

    /// Show every measured feature, including the ones measured at chance
    #[arg(long)]
    pub all_features: bool,
}

pub fn run(
    args: &DetectCovertArgs,
    verbose: bool,
    json: bool,
    quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    if !args.capture.exists() {
        let e = StegError::FileNotFound(args.capture.display().to_string());
        if json {
            output::emit_json(
                &JsonOut::<()>::failure(&e.to_string()),
                output::exit_code(&e),
            );
        }
        output::die(&e, verbose);
    }

    let spinner = Spinner::new("Reading capture…", Arc::clone(&interrupted));
    match detect::analyse_capture(&args.capture) {
        Ok(report) => {
            spinner.success(&headline(&report));
            if json {
                output::emit_json(&JsonOut::success(&report), 0);
            }
            if !quiet {
                print_report(&report, args.all_features);
            }
            std::process::exit(0);
        }
        Err(e) => {
            // Converted to the public error type and mapped by the shared table,
            // rather than by a mapping of this command's own, so a script sees
            // the same code for the same class of failure from every subcommand.
            let e: StegError = e.into();
            spinner.fail(&e.to_string());
            if json {
                output::emit_json(
                    &JsonOut::<()>::failure(&e.to_string()),
                    output::exit_code(&e),
                );
            }
            if verbose {
                output::print_error(&e.to_string(), Some(&format!("{e:#}")));
            } else {
                output::print_error(&e.to_string(), None);
            }
            std::process::exit(output::exit_code(&e));
        }
    }
}

/// One line that states what was examined rather than passing a verdict.
///
/// Deliberately never says "clean". The detector has no calibrated threshold, so
/// the strongest honest statement is what it looked at.
fn headline(report: &CovertReport) -> String {
    let packets = report.capture.packets;
    if packets == 0 {
        return "no packets in this capture".to_string();
    }
    if !report.had_discriminating_coverage() {
        return format!("{packets} packets examined, no DNS or ICMP to assess (see Coverage)");
    }
    let dns = report.dns.questions;
    let icmp = report.icmp.echo_requests + report.icmp.echo_replies;
    format!("{packets} packets examined, {dns} DNS questions, {icmp} ICMP echoes")
}

fn print_report(report: &CovertReport, all_features: bool) {
    // ── What was looked at ────────────────────────────────────────────────
    let mut coverage: Vec<(&str, String)> = Vec::new();
    coverage.push(("Packets read", report.capture.packets.to_string()));
    coverage.push((
        "DNS questions",
        if report.dns.questions == 0 {
            "none in this capture".to_string()
        } else {
            format!("{} across {} zones", report.dns.questions, report.dns.zones)
        },
    ));
    coverage.push((
        "ICMP echoes",
        if report.icmp.echo_requests + report.icmp.echo_replies == 0 {
            "none in this capture".to_string()
        } else {
            format!(
                "{} requests, {} replies",
                report.icmp.echo_requests, report.icmp.echo_replies
            )
        },
    ));
    coverage.push((
        "Flows timed",
        format!(
            "{} (busiest carried {} packets)",
            report.timing.flows, report.timing.busiest_flow_packets
        ),
    ));
    let rows: Vec<(&str, &str)> = coverage.iter().map(|(k, v)| (*k, v.as_str())).collect();
    output::print_summary("Coverage", Color::Cyan, &rows);

    if report.capture.malformed {
        output::print_warn(
            "This capture is truncated or malformed. The numbers below describe \
             only the part that could be read.",
        );
    }
    if report.limits_hit {
        output::print_warn(
            "A resource limit was reached, so some counts understate the capture. \
             Analyse a shorter capture for exact figures.",
        );
    }
    if !report.had_discriminating_coverage() {
        output::print_warn(
            "Nothing in this capture can be assessed for a covert channel. The \
             only features that ran are reported for description and cannot \
             distinguish a channel from ordinary traffic, so this is not a \
             statement that the traffic is clean.",
        );
    }

    // ── What the features that can discriminate say ───────────────────────
    let roles = &report.feature_roles;
    let values = feature_values(report);

    let mut decisive: Vec<(String, String)> = Vec::new();
    let mut narrow: Vec<(String, String)> = Vec::new();
    let mut descriptive: Vec<(String, String)> = Vec::new();
    for (name, rendered) in &values {
        let role = roles
            .get(name)
            .copied()
            .unwrap_or(FeatureRole::Inconclusive);
        let row = (pretty(name), rendered.clone());
        match role {
            FeatureRole::Discriminating => decisive.push(row),
            FeatureRole::DominantChannelOnly => narrow.push(row),
            FeatureRole::Inconclusive | FeatureRole::AntiSignal => descriptive.push(row),
        }
    }

    if !decisive.is_empty() {
        let rows: Vec<(&str, &str)> = decisive
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        output::print_summary(
            "Measured to discriminate (these are the ones to read)",
            Color::Yellow,
            &rows,
        );
    }
    if !narrow.is_empty() {
        let rows: Vec<(&str, &str)> = narrow
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        output::print_summary(
            "Only meaningful if a channel is most of this capture",
            Color::Yellow,
            &rows,
        );
    }
    if all_features && !descriptive.is_empty() {
        let rows: Vec<(&str, &str)> = descriptive
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        output::print_summary(
            "Description only, measured at or below chance",
            Color::Blue,
            &rows,
        );
    } else if !descriptive.is_empty() {
        output::print_info(&format!(
            "{} further statistics measured at or below chance are not shown; \
             pass --all-features to see them.",
            descriptive.len()
        ));
    }

    // ── What none of it means ─────────────────────────────────────────────
    output::print_info(
        "No threshold has been calibrated for these features, so none of the \
         numbers above is a verdict. The timing statistics in particular were \
         measured pointing the wrong way: ordinary voice and video traffic scores \
         as more suspicious than a real timing channel, so nothing should be \
         concluded from them.",
    );
}

/// Every feature, as a field key and a rendered value, in a stable order.
fn feature_values(report: &CovertReport) -> Vec<(String, String)> {
    let dns = &report.dns;
    let icmp = &report.icmp;
    let timing = &report.timing;
    let mut out: Vec<(String, String)> = vec![
        (
            "dns.max_query_name_length".into(),
            format!("{} characters", dns.max_query_name_length),
        ),
        (
            "dns.max_subdomain_entropy".into(),
            format!("{:.2} bits per byte", dns.max_subdomain_entropy),
        ),
        (
            "dns.mean_query_name_length".into(),
            format!("{:.1} characters", dns.mean_query_name_length),
        ),
        (
            "dns.mean_subdomain_entropy".into(),
            format!("{:.2} bits per byte", dns.mean_subdomain_entropy),
        ),
        (
            "dns.mean_subdomain_labels".into(),
            format!("{:.2}", dns.mean_subdomain_labels),
        ),
        (
            "dns.tunnelling_type_ratio".into(),
            format!(
                "{:.1}% TXT, NULL or CNAME",
                dns.tunnelling_type_ratio * 100.0
            ),
        ),
        (
            "dns.null_type_ratio".into(),
            format!("{:.1}% NULL", dns.null_type_ratio * 100.0),
        ),
        (
            "dns.unique_name_ratio_busiest_zone".into(),
            format!("{:.2}", dns.unique_name_ratio_busiest_zone),
        ),
        (
            "dns.max_zone_unique_name_ratio".into(),
            format!("{:.2}", dns.max_zone_unique_name_ratio),
        ),
        (
            "dns.max_names_per_zone".into(),
            dns.max_names_per_zone.to_string(),
        ),
        (
            "icmp.ping_pattern_ratio".into(),
            format!(
                "{:.1}% match an ordinary ping",
                icmp.ping_pattern_ratio * 100.0
            ),
        ),
        (
            "icmp.request_reply_mismatch_ratio".into(),
            format!(
                "{:.1}% of replies differed",
                icmp.request_reply_mismatch_ratio * 100.0
            ),
        ),
        (
            "icmp.sequence_discontinuity_ratio".into(),
            format!(
                "{:.1}% out of sequence",
                icmp.sequence_discontinuity_ratio * 100.0
            ),
        ),
        (
            "icmp.mean_body_entropy".into(),
            format!("{:.2} bits per byte", icmp.mean_body_entropy),
        ),
        (
            "icmp.mean_body_length".into(),
            format!("{:.1} bytes", icmp.mean_body_length),
        ),
        (
            "icmp.distinct_body_lengths".into(),
            icmp.distinct_body_lengths.to_string(),
        ),
        (
            "timing.coefficient_of_variation".into(),
            format!("{:.3}", timing.coefficient_of_variation),
        ),
        (
            "timing.interarrival_histogram_entropy".into(),
            format!("{:.2} bits", timing.interarrival_histogram_entropy),
        ),
        (
            "timing.top_two_bucket_mass".into(),
            format!("{:.2}", timing.top_two_bucket_mass),
        ),
        (
            "timing.mean_interarrival_micros".into(),
            format!("{:.0} microseconds", timing.mean_interarrival_micros),
        ),
    ];
    // Drop the rows for a channel that was not present at all, so a capture with
    // no ICMP does not print six zeroes that read like measurements.
    if icmp.echo_requests + icmp.echo_replies == 0 {
        out.retain(|(name, _)| !name.starts_with("icmp."));
    }
    if dns.questions == 0 {
        out.retain(|(name, _)| !name.starts_with("dns."));
    }
    if timing.busiest_flow_packets < 2 {
        out.retain(|(name, _)| !name.starts_with("timing."));
    }
    out
}

/// Turn a field key into something a person reads, with no underscores and no
/// channel prefix duplicated into the label.
fn pretty(key: &str) -> String {
    let (channel, field) = key.split_once('.').unwrap_or(("", key));
    let words = field.replace('_', " ");
    let channel = match channel {
        "dns" => "DNS",
        "icmp" => "ICMP",
        "timing" => "Timing",
        other => other,
    };
    let mut label = words;
    if let Some(first) = label.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    format!("{channel}: {label}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_use_the_shared_exit_code_table() {
        // Recorded because the brief asked for 3 on both FileNotFound and
        // UnsupportedFormat "as score.rs does", and score.rs does not: it calls
        // `output::exit_code`, which maps FileNotFound to 3 and UnsupportedFormat
        // to 4. This command uses the same table, so every subcommand agrees;
        // changing the table is the way to change this, not a local override.
        assert_eq!(output::exit_code(&StegError::FileNotFound("x".into())), 3);
        assert_eq!(
            output::exit_code(&StegError::UnsupportedFormat("x".into())),
            4
        );
        // A pcapng capture arrives as UnsupportedFormat, so it exits 4.
        let engine = stegcore_engine::errors::StegError::UnsupportedFormat("pcapng".into());
        let public: StegError = engine.into();
        assert_eq!(output::exit_code(&public), 4);
    }

    #[test]
    fn a_field_key_becomes_a_readable_label() {
        assert_eq!(
            pretty("dns.max_query_name_length"),
            "DNS: Max query name length"
        );
        assert_eq!(
            pretty("icmp.ping_pattern_ratio"),
            "ICMP: Ping pattern ratio"
        );
        assert_eq!(
            pretty("timing.coefficient_of_variation"),
            "Timing: Coefficient of variation"
        );
        for key in ["dns.a", "icmp.b", "timing.c"] {
            assert!(!pretty(key).contains('_'));
        }
    }
}
