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

//! Measure the covert-channel detector against generated matched arms.
//!
//! Reports, per channel and per feature, the ROC AUC and the true-positive rate
//! at a false-positive rate of 1% set on the negative arm. This is the
//! measurement that the detector's thresholds would be derived from, and it is
//! the number the detector is not allowed to ship without.
//!
//! Everything is generated in memory from seeded fixtures. No network, no files,
//! no privilege.
//!
//! ```text
//! cargo run --release -p stegcore-engine --example covert_measure
//! ```

use stegcore_engine::covert::detect::{analyse_reader, CovertReport};
use stegcore_engine::covert::fixtures;
use stegcore_engine::covert::pcap::PcapReader;

/// Captures per arm. Each is an independent seed, so each contributes one
/// observation of the per-capture feature vector.
const SAMPLES: usize = 120;

/// False-positive rate the true-positive rate is quoted at. One percent is the
/// figure a defender can actually live with on a busy link; a detector quoted at
/// 10% would fire constantly.
const TARGET_FPR: f64 = 0.01;

fn measure(bytes: &[u8]) -> CovertReport {
    let reader = PcapReader::new(std::io::Cursor::new(bytes.to_vec())).expect("fixture header");
    analyse_reader(reader).expect("fixture analysis")
}

/// ROC AUC by mean rank, the Mann-Whitney form. Ties take the average rank, so a
/// feature that is constant across both arms scores exactly 0.5 rather than 0 or
/// 1 depending on sort order.
fn auc(positive: &[f64], negative: &[f64]) -> f64 {
    if positive.is_empty() || negative.is_empty() {
        return f64::NAN;
    }
    let mut merged: Vec<(f64, u8)> = positive
        .iter()
        .map(|&value| (value, 1u8))
        .chain(negative.iter().map(|&value| (value, 0u8)))
        .collect();
    merged.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut rank_sum = 0.0;
    let mut index = 0;
    while index < merged.len() {
        let mut end = index;
        while end + 1 < merged.len() && merged[end + 1].0 == merged[index].0 {
            end += 1;
        }
        let mean_rank = (index + end) as f64 / 2.0 + 1.0;
        for item in &merged[index..=end] {
            if item.1 == 1 {
                rank_sum += mean_rank;
            }
        }
        index = end + 1;
    }
    let n_pos = positive.len() as f64;
    let n_neg = negative.len() as f64;
    (rank_sum - n_pos * (n_pos + 1.0) / 2.0) / (n_pos * n_neg)
}

/// True-positive rate at a threshold set so the negative arm's false-positive
/// rate is at most `TARGET_FPR`.
///
/// The threshold is the negative arm's own upper quantile, which is the honest
/// way round: it is chosen without looking at the positive arm, exactly as a
/// defender would have to choose it.
fn tpr_at_fpr(positive: &[f64], negative: &[f64], higher_is_positive: bool) -> f64 {
    if positive.is_empty() || negative.is_empty() {
        return f64::NAN;
    }
    let mut sorted = negative.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if higher_is_positive {
        // The threshold sits above all but TARGET_FPR of the negative arm.
        let index =
            (((1.0 - TARGET_FPR) * sorted.len() as f64).ceil() as usize).min(sorted.len() - 1);
        let threshold = sorted[index];
        positive.iter().filter(|&&v| v > threshold).count() as f64 / positive.len() as f64
    } else {
        let index = ((TARGET_FPR * sorted.len() as f64).floor() as usize).min(sorted.len() - 1);
        let threshold = sorted[index];
        positive.iter().filter(|&&v| v < threshold).count() as f64 / positive.len() as f64
    }
}

struct Feature {
    name: &'static str,
    extract: fn(&CovertReport) -> f64,
    /// Whether a higher value indicates a channel. Stated per feature rather
    /// than inferred, because inferring it from the data is how a measurement
    /// harness flatters itself.
    higher_is_positive: bool,
}

fn report(
    channel: &str,
    features: &[Feature],
    positive: &[CovertReport],
    negative: &[CovertReport],
) {
    println!("\n## {channel}");
    println!(
        "\n{:<36}{:>9}{:>14}",
        "feature",
        "AUC",
        format!("TPR@{:.0}%FPR", TARGET_FPR * 100.0)
    );
    println!("{}", "-".repeat(59));
    let mut rows: Vec<(String, f64, f64)> = Vec::new();
    for feature in features {
        let pos: Vec<f64> = positive.iter().map(feature.extract).collect();
        let neg: Vec<f64> = negative.iter().map(feature.extract).collect();
        let area = auc(&pos, &neg);
        // AUC is quoted in the direction the feature is declared to work in, so
        // a feature that separates downward does not read as 0.05.
        let oriented = if feature.higher_is_positive {
            area
        } else {
            1.0 - area
        };
        rows.push((
            feature.name.to_string(),
            oriented,
            tpr_at_fpr(&pos, &neg, feature.higher_is_positive),
        ));
    }
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (name, area, tpr) in rows {
        println!("{name:<36}{area:>9.4}{tpr:>14.4}");
    }
}

fn main() {
    println!("Covert-channel detector efficacy");
    println!("{SAMPLES} captures per arm, seeded fixtures, no network.");

    // ── DNS ───────────────────────────────────────────────────────────────
    let dns_features: &[Feature] = &[
        Feature {
            name: "mean_query_name_length",
            extract: |r| r.dns.mean_query_name_length,
            higher_is_positive: true,
        },
        Feature {
            name: "max_query_name_length",
            extract: |r| r.dns.max_query_name_length as f64,
            higher_is_positive: true,
        },
        Feature {
            name: "mean_subdomain_entropy",
            extract: |r| r.dns.mean_subdomain_entropy,
            higher_is_positive: true,
        },
        Feature {
            name: "mean_subdomain_labels",
            extract: |r| r.dns.mean_subdomain_labels,
            higher_is_positive: true,
        },
        Feature {
            name: "tunnelling_type_ratio",
            extract: |r| r.dns.tunnelling_type_ratio,
            higher_is_positive: true,
        },
        Feature {
            name: "null_type_ratio",
            extract: |r| r.dns.null_type_ratio,
            higher_is_positive: true,
        },
        Feature {
            name: "unique_name_ratio_busiest_zone",
            extract: |r| r.dns.unique_name_ratio_busiest_zone,
            higher_is_positive: true,
        },
        Feature {
            name: "max_names_per_zone",
            extract: |r| r.dns.max_names_per_zone as f64,
            higher_is_positive: true,
        },
        Feature {
            name: "max_zone_unique_name_ratio",
            extract: |r| r.dns.max_zone_unique_name_ratio,
            higher_is_positive: true,
        },
        Feature {
            name: "max_subdomain_entropy",
            extract: |r| r.dns.max_subdomain_entropy,
            higher_is_positive: true,
        },
    ];

    // Two negative arms, deliberately. `benign_dns` is ten repeating hostnames,
    // which is the easy arm and is reported so the hard arm has something to be
    // compared against. `realistic_dns` carries the long names, high-entropy CDN
    // keys, DKIM and ACME TXT lookups and unique tracing names that a real
    // resolver sees, every one of which is a legitimate occurrence of a property
    // that makes a tunnel conspicuous.
    let easy_negative: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::benign_dns(200, seed as u64)))
        .collect();
    let hard_negative: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::realistic_dns(200, seed as u64)))
        .collect();

    // Label length is the per-query payload axis: a shorter label carries less
    // and looks more like an ordinary hostname.
    for label_length in [40usize, 20, 10, 5] {
        let positive: Vec<CovertReport> = (0..SAMPLES)
            .map(|seed| measure(&fixtures::dns_tunnel(200, seed as u64, label_length)))
            .collect();
        report(
            &format!(
                "DNS tunnel, 100% of traffic, {label_length}-char labels, vs REALISTIC traffic"
            ),
            dns_features,
            &positive,
            &hard_negative,
        );
    }

    // Dilution is the axis that matters in the field: a tunnel is a small share
    // of a busy link, and a per-capture average sees it as a small perturbation.
    for tunnel_percent in [50u64, 20, 5, 1] {
        let positive: Vec<CovertReport> = (0..SAMPLES)
            .map(|seed| measure(&fixtures::mixed_dns(200, tunnel_percent, seed as u64, 40)))
            .collect();
        report(
            &format!(
                "DNS tunnel DILUTED to {tunnel_percent}% of traffic, 40-char labels, \
                 vs REALISTIC traffic"
            ),
            dns_features,
            &positive,
            &hard_negative,
        );
    }

    let null_positive: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::dns_tunnel_null(200, seed as u64, 40)))
        .collect();
    report(
        "DNS tunnel, NULL records, vs REALISTIC traffic",
        dns_features,
        &null_positive,
        &hard_negative,
    );
    report(
        "DNS tunnel, 40-char labels, vs the EASY arm (ten repeating hostnames)",
        dns_features,
        &(0..SAMPLES)
            .map(|seed| measure(&fixtures::dns_tunnel(200, seed as u64, 40)))
            .collect::<Vec<_>>(),
        &easy_negative,
    );

    // ── ICMP ──────────────────────────────────────────────────────────────
    let icmp_features: &[Feature] = &[
        Feature {
            name: "ping_pattern_ratio",
            extract: |r| r.icmp.ping_pattern_ratio,
            higher_is_positive: false,
        },
        Feature {
            name: "request_reply_mismatch_ratio",
            extract: |r| r.icmp.request_reply_mismatch_ratio,
            higher_is_positive: true,
        },
        Feature {
            name: "sequence_discontinuity_ratio",
            extract: |r| r.icmp.sequence_discontinuity_ratio,
            higher_is_positive: true,
        },
        Feature {
            name: "mean_body_entropy",
            extract: |r| r.icmp.mean_body_entropy,
            higher_is_positive: true,
        },
        Feature {
            name: "mean_body_length",
            extract: |r| r.icmp.mean_body_length,
            higher_is_positive: true,
        },
        Feature {
            name: "distinct_body_lengths",
            extract: |r| r.icmp.distinct_body_lengths as f64,
            higher_is_positive: true,
        },
    ];
    let icmp_negative: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::benign_ping(100, seed as u64)))
        .collect();
    let icmp_positive: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::icmp_tunnel(100, seed as u64)))
        .collect();
    report(
        "ICMP echo-body tunnel",
        icmp_features,
        &icmp_positive,
        &icmp_negative,
    );

    // ── Timing ────────────────────────────────────────────────────────────
    let timing_features: &[Feature] = &[
        Feature {
            name: "top_two_bucket_mass",
            extract: |r| r.timing.top_two_bucket_mass,
            higher_is_positive: true,
        },
        Feature {
            name: "interarrival_histogram_entropy",
            extract: |r| r.timing.interarrival_histogram_entropy,
            higher_is_positive: false,
        },
        Feature {
            name: "coefficient_of_variation",
            extract: |r| r.timing.coefficient_of_variation,
            higher_is_positive: false,
        },
        Feature {
            name: "stddev_interarrival_micros",
            extract: |r| r.timing.stddev_interarrival_micros,
            higher_is_positive: false,
        },
    ];
    let timing_negative: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::bursty_flow(400, seed as u64)))
        .collect();
    let timing_positive: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::timing_channel(400, seed as u64)))
        .collect();
    report(
        "Timing channel, two-level modulation, against bursty traffic",
        timing_features,
        &timing_positive,
        &timing_negative,
    );

    // The arm that matters. A legitimate constant-bitrate flow (VoIP, a
    // keepalive, a video stream) has the same near-zero jitter as a fixed-rate
    // covert channel, so this is the comparison a defender actually faces.
    let cbr_negative: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::constant_bitrate_flow(400, seed as u64)))
        .collect();
    report(
        "Timing, two-level channel vs LEGITIMATE CONSTANT-BITRATE traffic",
        timing_features,
        &timing_positive,
        &cbr_negative,
    );
    report(
        "Timing, FIXED-RATE channel vs LEGITIMATE CONSTANT-BITRATE traffic",
        timing_features,
        &(0..SAMPLES)
            .map(|seed| measure(&fixtures::steady_flow(400, 5_000_000 + seed as u64 * 1000)))
            .collect::<Vec<_>>(),
        &cbr_negative,
    );

    // The easy case, included so the hard case above is not mistaken for the
    // feature set being broken: a perfectly fixed-rate flow is trivial to see.
    let steady_positive: Vec<CovertReport> = (0..SAMPLES)
        .map(|seed| measure(&fixtures::steady_flow(400, 5_000_000 + seed as u64 * 1000)))
        .collect();
    report(
        "Timing, FIXED-RATE flow against bursty traffic (the easy case)",
        timing_features,
        &steady_positive,
        &timing_negative,
    );
}
