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

//! Statistical covert-channel features over a capture.
//!
//! Reports measurements per channel. It does not decide, because a threshold
//! that was not set against a corpus at a documented false-positive ceiling is a
//! guess, and a guess in a detector is worse than no detector because it gets
//! believed. See [`CALIBRATION_NOTE`] for what setting them needs.
//!
//! # Measured efficacy
//!
//! Measured on generated matched arms, TPR at a 1% false-positive rate set on
//! the negative arm, reported by `covert_measure`. Numbers and the corpus they
//! came from live with the calibration harness.
//!
//! The honest summary, stated before the detail:
//!
//! - **DNS tunnelling that dominates a capture is trivial to see** (AUC 1.0000),
//!   and a tunnel diluted to 1% of ordinary traffic is seen by exactly one
//!   feature, `max_query_name_length`, at AUC 0.9542 and a true-positive rate of
//!   0.9083. Every averaged feature falls to near chance at that dilution.
//! - **ICMP payload abuse is easy to see structurally** (AUC 1.0000 on the fill
//!   pattern, the request-reply mismatch and sequence continuity).
//! - **The timing features do not work and should not raise a verdict.** Against
//!   legitimate constant-bitrate traffic they score AUC 0.0000, meaning they
//!   point the wrong way. See [`TimingFeatures`].
//! - **The unique-name-ratio family does not discriminate against realistic
//!   traffic** (AUC 0.5000), because real CDN and request-tracing traffic already
//!   never repeats a name. See [`DnsFeatures::max_zone_unique_name_ratio`].
//!
//! # Bounded accumulation
//!
//! A capture is untrusted and arbitrarily large, so nothing here grows with it.
//! Per-zone and per-flow state is capped, and the timing analysis uses
//! fixed-width histograms and running moments rather than storing arrival times.
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_ZONES`] | 4096 | Distinct DNS zones tracked |
//! | [`MAX_NAMES_PER_ZONE`] | 4096 | Distinct names remembered per zone |
//! | [`MAX_FLOWS`] | 8192 | Distinct flows tracked for timing |
//! | [`INTERARRIVAL_BUCKETS`] | 64 | Log-spaced inter-arrival histogram width |
//!
//! Reaching any of them sets [`CovertReport::limits_hit`], because a capped
//! count read as a true count would understate a tunnel.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::dns::{self, RecordType};
use super::packet::{dissect, Dissection};
use super::pcap::{CaptureStats, PcapReader};
use crate::errors::StegError;

/// Distinct DNS zones tracked before new ones are ignored.
pub const MAX_ZONES: usize = 4096;

/// Distinct names remembered per zone, which bounds the unique-name count.
pub const MAX_NAMES_PER_ZONE: usize = 4096;

/// Distinct flows tracked for timing analysis.
pub const MAX_FLOWS: usize = 8192;

/// Width of the log-spaced inter-arrival histogram.
pub const INTERARRIVAL_BUCKETS: usize = 64;

/// Fewest queries a zone must carry before its unique-name ratio is reported.
///
/// A reporting floor, not a detection threshold: a ratio over three queries is
/// 1.0 whenever the three names differ, which is true of a great deal of
/// ordinary traffic, so including thin zones would fill the maximum with noise.
pub const MIN_ZONE_QUERIES_FOR_RATIO: usize = 8;

/// What a measured feature is good for, so a consumer cannot render a
/// descriptive statistic as though it were a finding.
///
/// Every value here was set by the measurement in `covert_measure`, not by
/// judgement. The hazard this exists to prevent is the same one that got the
/// `Clean` verdict renamed to "Nothing found": a label that claims a conclusion
/// the engine has not earned. A capture where nothing was found and a capture
/// where the only features that ran cannot discriminate must not read alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureRole {
    /// Measured to separate a channel from realistic traffic. May contribute to
    /// a verdict once a threshold has been calibrated against a real corpus.
    Discriminating,
    /// Measured to separate only when the channel dominates the capture, and to
    /// fail or inverst once it is diluted. Read it on a capture of one suspect
    /// host; do not threshold it on a busy link.
    DominantChannelOnly,
    /// Measured at or near an AUC of 0.5 against realistic traffic. It answers a
    /// narrow question (and may be decisive for that question alone), but it
    /// carries no general signal.
    Inconclusive,
    /// Measured to point the WRONG way: an AUC at or below 0.5 where higher was
    /// expected to mean a channel. **Nothing may raise a verdict from this.**
    /// Reported so a defender can read the distribution, and for no other
    /// purpose.
    AntiSignal,
}

impl FeatureRole {
    /// Whether a verdict may ever be raised from this feature. False for
    /// anything the measurement did not support.
    pub fn may_inform_a_verdict(self) -> bool {
        matches!(self, Self::Discriminating | Self::DominantChannelOnly)
    }

    /// One plain sentence for a human reading the report.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Discriminating => "separates a channel from ordinary traffic in measurement",
            Self::DominantChannelOnly => "only separates when the channel is most of the traffic",
            Self::Inconclusive => "measured at chance against ordinary traffic",
            Self::AntiSignal => {
                "measured pointing the wrong way; ordinary traffic scores as more \
                 suspicious than a real channel, so no verdict may rest on it"
            }
        }
    }
}

/// The measured role of every feature this module reports, keyed by field name.
///
/// A table rather than a method on each feature, so the whole set can be
/// serialised beside the numbers and a consumer has no way to receive a value
/// without receiving what it is worth. The AUCs behind each entry are in the
/// measurement record.
pub fn feature_roles() -> BTreeMap<String, FeatureRole> {
    use FeatureRole::{AntiSignal, Discriminating, DominantChannelOnly, Inconclusive};
    [
        // DNS. `max_query_name_length` is the only one that survived dilution to
        // 1% of traffic (AUC 0.9542, TPR 0.9083 at 1% FPR).
        ("dns.max_query_name_length", Discriminating),
        ("dns.max_subdomain_entropy", Discriminating),
        ("dns.mean_query_name_length", DominantChannelOnly),
        ("dns.mean_subdomain_entropy", DominantChannelOnly),
        ("dns.mean_subdomain_labels", DominantChannelOnly),
        ("dns.tunnelling_type_ratio", DominantChannelOnly),
        // Decisive for NULL tunnels (AUC 1.0000) and silent otherwise (0.5000).
        ("dns.null_type_ratio", Inconclusive),
        // Inverts to 0.0000 once the tunnel stops being the busiest zone.
        ("dns.unique_name_ratio_busiest_zone", DominantChannelOnly),
        ("dns.max_names_per_zone", DominantChannelOnly),
        // 0.5000 at every dilution: real CDN and tracing traffic never repeats a
        // name either.
        ("dns.max_zone_unique_name_ratio", Inconclusive),
        // ICMP. The structural checks separate completely; the body statistics do
        // not (see the entropy finding).
        ("icmp.ping_pattern_ratio", Discriminating),
        ("icmp.request_reply_mismatch_ratio", Discriminating),
        ("icmp.sequence_discontinuity_ratio", Discriminating),
        ("icmp.mean_body_entropy", DominantChannelOnly),
        ("icmp.mean_body_length", Inconclusive),
        ("icmp.distinct_body_lengths", Inconclusive),
        // Timing. Every one of these measured AUC 0.0000 against legitimate
        // constant-bitrate traffic, which is why they are all anti-signals.
        ("timing.coefficient_of_variation", AntiSignal),
        ("timing.interarrival_histogram_entropy", AntiSignal),
        ("timing.top_two_bucket_mass", AntiSignal),
        ("timing.stddev_interarrival_micros", AntiSignal),
        ("timing.mean_interarrival_micros", AntiSignal),
    ]
    .into_iter()
    .map(|(name, role)| (name.to_string(), role))
    .collect()
}

/// What a defender needs in order to turn these measurements into a threshold.
pub const CALIBRATION_NOTE: &str = "\
These are measurements, not a verdict. Setting a threshold needs a negative arm \
of ordinary traffic from the network being monitored, a stated false-positive \
ceiling chosen in advance, and the payload rate range the threshold must hold \
over. A threshold carried over from another network is a guess.";

// ── Report types ──────────────────────────────────────────────────────────────

/// DNS features over a whole capture.
///
/// The discriminating ones in measurement were `mean_query_name_length`,
/// `mean_subdomain_entropy` and `tunnelling_type_ratio`; `max_names_per_zone`
/// separates hardest but needs a window long enough to accumulate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsFeatures {
    /// DNS messages parsed, queries and responses together.
    pub messages: usize,
    /// Messages whose question section could not be fully read.
    pub malformed_messages: usize,
    /// Questions seen across all messages.
    pub questions: usize,

    /// Mean total length of the queried name in characters.
    pub mean_query_name_length: f64,
    /// Longest queried name seen.
    pub max_query_name_length: usize,
    /// Mean Shannon entropy, in bits per byte, of the labels below the zone.
    /// Encoded payload sits high; English hostnames sit low.
    pub mean_subdomain_entropy: f64,
    /// Mean number of labels below the zone.
    pub mean_subdomain_labels: f64,

    /// Fraction of questions whose type is TXT, NULL or CNAME.
    pub tunnelling_type_ratio: f64,
    /// Fraction that are specifically NULL, which is the strongest single tell
    /// because ordinary traffic effectively never queries it.
    pub null_type_ratio: f64,
    /// Per-type question counts, in a sorted map so serialised output is stable.
    pub type_counts: BTreeMap<String, usize>,

    /// Distinct zones seen.
    pub zones: usize,
    /// Largest number of distinct names under any one zone. A resolver cache
    /// miss pattern revisits names; a tunnel almost never repeats one.
    pub max_names_per_zone: usize,
    /// Across the busiest zone, distinct names divided by total queries. A
    /// tunnel approaches 1.0; ordinary traffic sits well below it.
    ///
    /// **Only informative when the tunnel dominates the capture.** Measured, this
    /// collapses to an AUC of 0.0000 once a tunnel is diluted to 20% of traffic,
    /// because "busiest" then selects a background zone and the feature stops
    /// describing the tunnel at all. Kept because it is the right thing to read
    /// on a capture of a single suspect host, and paired with
    /// [`Self::max_zone_unique_name_ratio`], which does not have the flaw.
    pub unique_name_ratio_busiest_zone: f64,
    /// Queries to the busiest zone.
    pub busiest_zone_queries: usize,
    /// The largest unique-name ratio over every zone carrying at least
    /// [`MIN_ZONE_QUERIES_FOR_RATIO`] queries.
    ///
    /// A maximum rather than an average, which is the point: a tunnel is one zone
    /// among many and an average over zones dilutes it away, while a maximum
    /// finds it however much ordinary traffic surrounds it.
    pub max_zone_unique_name_ratio: f64,
    /// Highest subdomain entropy of any single query, as against the mean.
    ///
    /// Measured, maximum-based features survive dilution and mean-based ones do
    /// not: at a tunnel occupying 1% of traffic every mean feature here falls to
    /// near chance while [`Self::max_query_name_length`] still reaches an AUC of
    /// 0.95. This exists because of that result.
    pub max_subdomain_entropy: f64,
}

/// ICMP features over a whole capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IcmpFeatures {
    pub echo_requests: usize,
    pub echo_replies: usize,
    /// Mean echo body length in bytes. The ordinary ping is 56 bytes on Unix and
    /// 32 on Windows.
    pub mean_body_length: f64,
    /// Distinct body lengths seen, which is small for real ping traffic.
    pub distinct_body_lengths: usize,
    /// Mean Shannon entropy of echo bodies in bits per byte. A ping's ramp or
    /// alphabet fill is near zero; encrypted payload approaches 8.
    pub mean_body_entropy: f64,
    /// Fraction of bodies that match the ordinary ping fill pattern, meaning a
    /// monotonic byte ramp or a repeating short alphabet.
    pub ping_pattern_ratio: f64,
    /// Fraction of request bodies whose matching reply body differed. A real
    /// ping is echoed verbatim, so any asymmetry at all is notable.
    pub request_reply_mismatch_ratio: f64,
    /// Echo requests whose sequence number did not follow the previous one for
    /// the same identifier, as a fraction. Tunnels reuse the field for framing.
    pub sequence_discontinuity_ratio: f64,
}

/// Timing features over the busiest flow.
///
/// # These do not work as a detector, measured
///
/// **Against a legitimate constant-bitrate flow, every feature here scores an
/// AUC of 0.0000.** Not 0.5, which would be useless; 0.0, which means they point
/// the wrong way. Voice, video, keepalives and NTP all send on a timer, so their
/// jitter is near zero, which is the headline property a timing channel was
/// supposed to be caught by. A two-level channel alternating between a short and
/// a long gap has *more* variation than a VoIP stream, so "low variation is
/// suspicious" flags every call on the network and misses the channel.
///
/// The one number that looks good, a coefficient of variation separating a
/// fixed-rate channel from constant-bitrate traffic at AUC 1.0000, is an artefact
/// of the fixture rather than a result: the generated channel has mathematically
/// exact gaps, and nothing that crosses a real network does.
///
/// For completeness, against a bursty negative arm every feature scores 1.0000.
/// That arm is the easy one and it is reported only so the 0.0000 above is not
/// mistaken for the code being broken.
///
/// **So these are descriptive statistics and not a signal.** They are reported
/// because a defender looking at one suspect flow can read a histogram usefully,
/// and the recommendation is that nothing downstream raise a verdict from them.
/// Growing the feature set until something crossed a line was the alternative and
/// it was not taken.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimingFeatures {
    /// Flows observed, capped at [`MAX_FLOWS`].
    pub flows: usize,
    /// Packets in the busiest flow, which is the one analysed.
    pub busiest_flow_packets: usize,
    /// Mean inter-arrival gap in the busiest flow, in microseconds.
    pub mean_interarrival_micros: f64,
    /// Standard deviation of the gap, in microseconds.
    pub stddev_interarrival_micros: f64,
    /// Standard deviation over mean. Ordinary traffic is bursty and sits above
    /// 1.0; a fixed-rate channel sits near 0.
    pub coefficient_of_variation: f64,
    /// Shannon entropy of the log-spaced inter-arrival histogram, in bits. A
    /// channel that modulates between two gaps concentrates into few buckets.
    pub interarrival_histogram_entropy: f64,
    /// Fraction of gaps falling in the two most populated buckets. A binary
    /// timing channel pushes this toward 1.0.
    pub top_two_bucket_mass: f64,
    /// The log-spaced histogram itself, so a defender can look rather than trust
    /// a summary.
    pub interarrival_histogram: Vec<u64>,
}

/// Everything measured over one capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CovertReport {
    pub capture: CaptureStats,
    /// Packets that produced no transport payload, by reason, in a sorted map.
    pub unhandled: BTreeMap<String, usize>,
    pub dns: DnsFeatures,
    pub icmp: IcmpFeatures,
    pub timing: TimingFeatures,
    /// An accumulation cap was reached, so a count may understate the capture.
    pub limits_hit: bool,
    /// Carried in the report so a JSON consumer cannot render these numbers as a
    /// verdict without also receiving the sentence that says they are not one.
    pub calibration_note: String,
    /// What each reported feature is worth, measured. Serialised beside the
    /// numbers so no consumer can receive a value without receiving its role.
    pub feature_roles: BTreeMap<String, FeatureRole>,
}

impl CovertReport {
    /// Features that measurement supports raising a verdict from, sorted.
    ///
    /// The intended way for a renderer to decide what to put under a heading and
    /// what to put under "also measured", rather than each surface keeping its
    /// own list and drifting.
    pub fn verdict_bearing_features(&self) -> Vec<&str> {
        self.feature_roles
            .iter()
            .filter(|(_, role)| role.may_inform_a_verdict())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Whether any feature that could bear a verdict was able to run at all.
    ///
    /// False means the capture held nothing those features could read, so
    /// "nothing found" would be a claim about the capture rather than about the
    /// traffic. A renderer must say so.
    pub fn had_discriminating_coverage(&self) -> bool {
        self.dns.questions > 0 || (self.icmp.echo_requests + self.icmp.echo_replies) > 0
    }
}

// ── Accumulators ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct ZoneState {
    queries: usize,
    names: std::collections::BTreeSet<String>,
    names_capped: bool,
}

#[derive(Default)]
struct DnsAccumulator {
    messages: usize,
    malformed: usize,
    questions: usize,
    name_length_total: u64,
    max_name_length: usize,
    subdomain_entropy_total: f64,
    subdomain_entropy_samples: usize,
    max_subdomain_entropy: f64,
    subdomain_label_total: u64,
    tunnelling_types: usize,
    null_types: usize,
    type_counts: BTreeMap<String, usize>,
    zones: BTreeMap<String, ZoneState>,
    zones_capped: bool,
}

#[derive(Default)]
struct IcmpAccumulator {
    requests: usize,
    replies: usize,
    body_length_total: u64,
    body_lengths: std::collections::BTreeSet<usize>,
    entropy_total: f64,
    ping_pattern: usize,
    bodies: usize,
    /// Last sequence number per identifier, for continuity. Bounded by
    /// `MAX_FLOWS` because an identifier is effectively a flow key here.
    last_sequence: BTreeMap<u16, u16>,
    sequence_breaks: usize,
    sequence_samples: usize,
    /// Request bodies awaiting their reply, keyed by identifier and sequence.
    /// Bounded, and a hash of the body rather than the body itself so a capture
    /// full of large pings cannot grow this without limit.
    pending_requests: BTreeMap<(u16, u16), u64>,
    matched_pairs: usize,
    mismatched_pairs: usize,
}

struct FlowState {
    last_nanos: u64,
    count: usize,
    gap_count: u64,
    gap_sum: f64,
    gap_sum_squares: f64,
    histogram: Vec<u64>,
}

impl FlowState {
    fn new(first_nanos: u64) -> Self {
        Self {
            last_nanos: first_nanos,
            count: 1,
            gap_count: 0,
            gap_sum: 0.0,
            gap_sum_squares: 0.0,
            histogram: vec![0; INTERARRIVAL_BUCKETS],
        }
    }

    /// Record one arrival. Running moments and a fixed histogram rather than a
    /// list of timestamps, so a flow of any length costs the same memory.
    fn observe(&mut self, nanos: u64) {
        self.count += 1;
        let gap_nanos = nanos.saturating_sub(self.last_nanos);
        self.last_nanos = nanos;
        let micros = gap_nanos as f64 / 1000.0;
        self.gap_count += 1;
        self.gap_sum += micros;
        self.gap_sum_squares += micros * micros;
        let bucket = log_bucket(gap_nanos);
        if let Some(slot) = self.histogram.get_mut(bucket) {
            *slot += 1;
        }
    }
}

/// Bucket a gap by its magnitude: bucket `n` holds gaps from `2^n` to
/// `2^(n+1)` nanoseconds. Log spacing because inter-arrival times span
/// microseconds to minutes and a linear histogram would put everything in one
/// bucket.
fn log_bucket(gap_nanos: u64) -> usize {
    if gap_nanos == 0 {
        return 0;
    }
    let bits = 64 - gap_nanos.leading_zeros() as usize;
    bits.min(INTERARRIVAL_BUCKETS - 1)
}

/// FNV-1a over a byte string. A non-cryptographic 64-bit digest is all the
/// request-and-reply comparison needs, and it keeps the accumulator from holding
/// packet bodies.
fn body_digest(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// Does this echo body look like an ordinary ping's filler?
///
/// Two shapes cover the common tools: a monotonic byte ramp, which is what
/// Linux `ping` writes after its timestamp, and a short repeating alphabet,
/// which is what Windows `ping` writes. Both are checked structurally rather
/// than by entropy, so a short body is judged on its shape and not on a
/// statistic that short samples cannot support.
fn looks_like_ping_fill(body: &[u8]) -> bool {
    if body.len() < 8 {
        // Too short to tell. Not counted as a ping pattern, and not counted
        // against one either; the caller tracks the sample count.
        return false;
    }
    // Linux ping puts an 8 or 16 byte timestamp first, then 0x10, 0x11, 0x12...
    // Look for a monotonic +1 ramp over the tail, allowing the first 16 bytes to
    // be anything.
    let tail_start = 16.min(body.len().saturating_sub(1));
    let tail = &body[tail_start..];
    if tail.len() >= 8 {
        let ramp = tail
            .windows(2)
            .all(|pair| pair[1] == pair[0].wrapping_add(1));
        if ramp {
            return true;
        }
    }
    // Windows ping repeats "abcdefghijklmnopqrstuvwabcdefghi".
    let alphabet = body.windows(2).all(|pair| {
        pair[0].is_ascii_lowercase()
            && pair[1].is_ascii_lowercase()
            && (pair[1] == pair[0] + 1 || pair[1] == b'a')
    });
    if alphabet {
        return true;
    }
    // A single repeated byte, which several tools use.
    body.iter().all(|&byte| byte == body[0])
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Measure covert-channel features over a capture file.
///
/// Opens no sockets and needs no privilege. The only input is the file.
///
/// # Errors
///
/// [`StegError::FileNotFound`] when the path does not exist,
/// [`StegError::UnsupportedFormat`] when the file is not a classic PCAP, and
/// [`StegError::Io`] on a read failure. A malformed capture is data: it comes
/// back with [`CaptureStats::malformed`] set.
pub fn analyse_capture(path: &std::path::Path) -> Result<CovertReport, StegError> {
    let reader = PcapReader::open(path)?;
    analyse_reader(reader)
}

/// Measure features from an already-opened capture, which is how the tests drive
/// this from memory without touching a filesystem or a network.
///
/// # Errors
///
/// As [`analyse_capture`].
pub fn analyse_reader<R: std::io::Read>(
    mut reader: PcapReader<R>,
) -> Result<CovertReport, StegError> {
    let link = reader.link_type();
    let mut dns_acc = DnsAccumulator::default();
    let mut icmp_acc = IcmpAccumulator::default();
    let mut flows: BTreeMap<(IpAddr, IpAddr, u16, u16, u8), FlowState> = BTreeMap::new();
    let mut flows_capped = false;
    let mut unhandled: BTreeMap<String, usize> = BTreeMap::new();

    while let Some((meta, frame)) = reader.next_packet()? {
        if frame.is_empty() {
            *unhandled.entry("empty_or_capped".to_string()).or_insert(0) += 1;
            continue;
        }
        match dissect(link, frame) {
            Dissection::Udp {
                source,
                destination,
                source_port,
                destination_port,
                payload,
            } => {
                observe_flow(
                    &mut flows,
                    &mut flows_capped,
                    (source, destination, source_port, destination_port, 17),
                    meta.timestamp_nanos,
                );
                if source_port == 53 || destination_port == 53 || destination_port == 5353 {
                    observe_dns(&mut dns_acc, payload);
                }
            }
            Dissection::Tcp {
                source,
                destination,
                source_port,
                destination_port,
                payload,
            } => {
                observe_flow(
                    &mut flows,
                    &mut flows_capped,
                    (source, destination, source_port, destination_port, 6),
                    meta.timestamp_nanos,
                );
                // DNS over TCP is length-prefixed with two bytes. No stream
                // reassembly, so only a message wholly inside one segment is
                // read; a split message is missed and that is a stated limit.
                if (source_port == 53 || destination_port == 53) && payload.len() > 2 {
                    observe_dns(&mut dns_acc, &payload[2..]);
                }
            }
            Dissection::Icmp {
                source,
                destination,
                message_type,
                identifier,
                sequence,
                body,
                ..
            } => {
                observe_flow(
                    &mut flows,
                    &mut flows_capped,
                    (source, destination, 0, 0, 1),
                    meta.timestamp_nanos,
                );
                observe_icmp(&mut icmp_acc, message_type, identifier, sequence, body);
            }
            Dissection::Unhandled { reason } => {
                *unhandled.entry(format!("{reason:?}")).or_insert(0) += 1;
            }
        }
    }

    let capture = reader.stats();
    let limits_hit = flows_capped
        || dns_acc.zones_capped
        || dns_acc.zones.values().any(|zone| zone.names_capped)
        || capture.packet_cap_reached
        || capture.byte_cap_reached;

    Ok(CovertReport {
        capture,
        unhandled,
        dns: finish_dns(dns_acc),
        icmp: finish_icmp(icmp_acc),
        timing: finish_timing(flows),
        limits_hit,
        calibration_note: CALIBRATION_NOTE.to_string(),
        feature_roles: feature_roles(),
    })
}

fn observe_flow(
    flows: &mut BTreeMap<(IpAddr, IpAddr, u16, u16, u8), FlowState>,
    capped: &mut bool,
    key: (IpAddr, IpAddr, u16, u16, u8),
    nanos: u64,
) {
    if let Some(state) = flows.get_mut(&key) {
        state.observe(nanos);
        return;
    }
    if flows.len() >= MAX_FLOWS {
        *capped = true;
        return;
    }
    flows.insert(key, FlowState::new(nanos));
}

fn observe_dns(acc: &mut DnsAccumulator, payload: &[u8]) {
    let Some(message) = dns::parse(payload) else {
        return;
    };
    acc.messages += 1;
    if message.malformed {
        acc.malformed += 1;
    }
    for question in &message.questions {
        acc.questions += 1;
        acc.name_length_total += question.name.len() as u64;
        acc.max_name_length = acc.max_name_length.max(question.name.len());

        let subdomain = question.subdomain_labels();
        acc.subdomain_label_total += subdomain.len() as u64;
        if !subdomain.is_empty() {
            let joined = subdomain.join(".");
            let entropy = dns::entropy_bits_per_byte(joined.as_bytes());
            acc.subdomain_entropy_total += entropy;
            acc.subdomain_entropy_samples += 1;
            if entropy > acc.max_subdomain_entropy {
                acc.max_subdomain_entropy = entropy;
            }
        }

        if question.record_type.is_tunnelling_favourite() {
            acc.tunnelling_types += 1;
        }
        if question.record_type == RecordType::Null {
            acc.null_types += 1;
        }
        *acc.type_counts
            .entry(type_label(question.record_type))
            .or_insert(0) += 1;

        // Only queries are counted per zone. Counting responses too would double
        // every name and halve the unique-name ratio for all traffic equally,
        // which adds noise without adding signal.
        if message.is_response {
            continue;
        }
        let zone = question.zone();
        if let Some(state) = acc.zones.get_mut(&zone) {
            state.queries += 1;
            if state.names.len() < MAX_NAMES_PER_ZONE {
                state.names.insert(question.name.clone());
            } else {
                state.names_capped = true;
            }
        } else if acc.zones.len() < MAX_ZONES {
            let mut state = ZoneState {
                queries: 1,
                ..ZoneState::default()
            };
            state.names.insert(question.name.clone());
            acc.zones.insert(zone, state);
        } else {
            acc.zones_capped = true;
        }
    }
}

fn type_label(record_type: RecordType) -> String {
    match record_type {
        RecordType::Other(code) => format!("type{code}"),
        named => format!("{named:?}").to_lowercase(),
    }
}

fn observe_icmp(
    acc: &mut IcmpAccumulator,
    message_type: u8,
    identifier: u16,
    sequence: u16,
    body: &[u8],
) {
    // 8 and 0 are IPv4 echo request and reply; 128 and 129 are the IPv6 pair.
    let is_request = message_type == 8 || message_type == 128;
    let is_reply = message_type == 0 || message_type == 129;
    if !is_request && !is_reply {
        return;
    }
    if is_request {
        acc.requests += 1;
    } else {
        acc.replies += 1;
    }

    acc.bodies += 1;
    acc.body_length_total += body.len() as u64;
    if acc.body_lengths.len() < MAX_FLOWS {
        acc.body_lengths.insert(body.len());
    }
    acc.entropy_total += dns::entropy_bits_per_byte(body);
    if looks_like_ping_fill(body) {
        acc.ping_pattern += 1;
    }

    if is_request {
        if let Some(previous) = acc.last_sequence.get(&identifier).copied() {
            acc.sequence_samples += 1;
            if sequence != previous.wrapping_add(1) {
                acc.sequence_breaks += 1;
            }
        }
        // Bounded by the identifier space: a 16-bit key cannot produce more
        // than 65536 entries, so this cannot grow with the capture and needs no
        // cap of its own.
        acc.last_sequence.insert(identifier, sequence);
        if acc.pending_requests.len() < MAX_FLOWS {
            acc.pending_requests
                .insert((identifier, sequence), body_digest(body));
        }
    } else if let Some(expected) = acc.pending_requests.remove(&(identifier, sequence)) {
        acc.matched_pairs += 1;
        if expected != body_digest(body) {
            acc.mismatched_pairs += 1;
        }
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

fn finish_dns(acc: DnsAccumulator) -> DnsFeatures {
    let (busiest_names, busiest_queries) = acc
        .zones
        .values()
        .map(|zone| (zone.names.len(), zone.queries))
        .max_by_key(|(_, queries)| *queries)
        .unwrap_or((0, 0));
    let max_names_per_zone = acc
        .zones
        .values()
        .map(|zone| zone.names.len())
        .max()
        .unwrap_or(0);
    // Maximum over zones rather than the busiest zone, so a tunnel sitting
    // beside heavier ordinary traffic is still found.
    let max_zone_unique_name_ratio = acc
        .zones
        .values()
        .filter(|zone| zone.queries >= MIN_ZONE_QUERIES_FOR_RATIO)
        .map(|zone| zone.names.len() as f64 / zone.queries as f64)
        .fold(0.0f64, f64::max);

    DnsFeatures {
        messages: acc.messages,
        malformed_messages: acc.malformed,
        questions: acc.questions,
        mean_query_name_length: if acc.questions == 0 {
            0.0
        } else {
            acc.name_length_total as f64 / acc.questions as f64
        },
        max_query_name_length: acc.max_name_length,
        mean_subdomain_entropy: if acc.subdomain_entropy_samples == 0 {
            0.0
        } else {
            acc.subdomain_entropy_total / acc.subdomain_entropy_samples as f64
        },
        mean_subdomain_labels: if acc.questions == 0 {
            0.0
        } else {
            acc.subdomain_label_total as f64 / acc.questions as f64
        },
        tunnelling_type_ratio: ratio(acc.tunnelling_types, acc.questions),
        null_type_ratio: ratio(acc.null_types, acc.questions),
        type_counts: acc.type_counts,
        zones: acc.zones.len(),
        max_names_per_zone,
        unique_name_ratio_busiest_zone: ratio(busiest_names, busiest_queries),
        busiest_zone_queries: busiest_queries,
        max_zone_unique_name_ratio,
        max_subdomain_entropy: acc.max_subdomain_entropy,
    }
}

fn finish_icmp(acc: IcmpAccumulator) -> IcmpFeatures {
    IcmpFeatures {
        echo_requests: acc.requests,
        echo_replies: acc.replies,
        mean_body_length: if acc.bodies == 0 {
            0.0
        } else {
            acc.body_length_total as f64 / acc.bodies as f64
        },
        distinct_body_lengths: acc.body_lengths.len(),
        mean_body_entropy: if acc.bodies == 0 {
            0.0
        } else {
            acc.entropy_total / acc.bodies as f64
        },
        ping_pattern_ratio: ratio(acc.ping_pattern, acc.bodies),
        request_reply_mismatch_ratio: ratio(acc.mismatched_pairs, acc.matched_pairs),
        sequence_discontinuity_ratio: ratio(acc.sequence_breaks, acc.sequence_samples),
    }
}

fn finish_timing(flows: BTreeMap<(IpAddr, IpAddr, u16, u16, u8), FlowState>) -> TimingFeatures {
    let flow_count = flows.len();
    let Some(busiest) = flows.into_values().max_by_key(|flow| flow.count) else {
        return TimingFeatures {
            flows: 0,
            busiest_flow_packets: 0,
            mean_interarrival_micros: 0.0,
            stddev_interarrival_micros: 0.0,
            coefficient_of_variation: 0.0,
            interarrival_histogram_entropy: 0.0,
            top_two_bucket_mass: 0.0,
            interarrival_histogram: vec![0; INTERARRIVAL_BUCKETS],
        };
    };

    let gaps = busiest.gap_count;
    let (mean, stddev) = if gaps == 0 {
        (0.0, 0.0)
    } else {
        let mean = busiest.gap_sum / gaps as f64;
        // Population variance from running moments, floored at zero because
        // catastrophic cancellation on a near-constant series can otherwise
        // produce a tiny negative and a NaN square root.
        let variance = (busiest.gap_sum_squares / gaps as f64 - mean * mean).max(0.0);
        (mean, variance.sqrt())
    };

    let total: u64 = busiest.histogram.iter().sum();
    let mut entropy = 0.0;
    if total > 0 {
        for &count in busiest.histogram.iter() {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }
    }
    let mut sorted = busiest.histogram.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let top_two: u64 = sorted.iter().take(2).sum();

    TimingFeatures {
        flows: flow_count,
        busiest_flow_packets: busiest.count,
        mean_interarrival_micros: mean,
        stddev_interarrival_micros: stddev,
        coefficient_of_variation: if mean > 0.0 { stddev / mean } else { 0.0 },
        interarrival_histogram_entropy: entropy,
        top_two_bucket_mass: if total > 0 {
            top_two as f64 / total as f64
        } else {
            0.0
        },
        interarrival_histogram: busiest.histogram,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covert::fixtures;
    use crate::covert::pcap::LinkType;
    use std::io::Cursor;

    fn analyse_bytes(bytes: &[u8]) -> CovertReport {
        let reader = PcapReader::new(Cursor::new(bytes.to_vec())).expect("header");
        analyse_reader(reader).expect("analyse")
    }

    // ── DNS ───────────────────────────────────────────────────────────────

    #[test]
    fn benign_dns_and_tunnelled_dns_separate_on_the_named_features() {
        let benign = fixtures::benign_dns(200, 1);
        let tunnel = fixtures::dns_tunnel(200, 1, 40);
        let b = analyse_bytes(&benign).dns;
        let t = analyse_bytes(&tunnel).dns;

        assert!(
            t.mean_query_name_length > b.mean_query_name_length * 2.0,
            "names: {} against {}",
            t.mean_query_name_length,
            b.mean_query_name_length
        );
        assert!(
            t.mean_subdomain_entropy > b.mean_subdomain_entropy,
            "entropy: {} against {}",
            t.mean_subdomain_entropy,
            b.mean_subdomain_entropy
        );
        assert!(
            t.tunnelling_type_ratio > b.tunnelling_type_ratio,
            "types: {} against {}",
            t.tunnelling_type_ratio,
            b.tunnelling_type_ratio
        );
        assert!(
            t.unique_name_ratio_busiest_zone > b.unique_name_ratio_busiest_zone,
            "unique ratio: {} against {}",
            t.unique_name_ratio_busiest_zone,
            b.unique_name_ratio_busiest_zone
        );
    }

    #[test]
    fn a_tunnel_almost_never_repeats_a_name_and_benign_traffic_does() {
        let tunnel = analyse_bytes(&fixtures::dns_tunnel(150, 7, 40)).dns;
        assert!(
            tunnel.unique_name_ratio_busiest_zone > 0.95,
            "got {}",
            tunnel.unique_name_ratio_busiest_zone
        );
        let benign = analyse_bytes(&fixtures::benign_dns(150, 7)).dns;
        assert!(
            benign.unique_name_ratio_busiest_zone < 0.9,
            "got {}",
            benign.unique_name_ratio_busiest_zone
        );
    }

    #[test]
    fn null_record_queries_are_counted_separately_because_they_are_the_strongest_tell() {
        let report = analyse_bytes(&fixtures::dns_tunnel_null(100, 3, 40)).dns;
        assert!(
            report.null_type_ratio > 0.9,
            "got {}",
            report.null_type_ratio
        );
        let benign = analyse_bytes(&fixtures::benign_dns(100, 3)).dns;
        assert_eq!(benign.null_type_ratio, 0.0);
    }

    #[test]
    fn the_type_counts_are_a_sorted_map_so_output_is_stable() {
        let a = analyse_bytes(&fixtures::benign_dns(60, 2)).dns.type_counts;
        let b = analyse_bytes(&fixtures::benign_dns(60, 2)).dns.type_counts;
        assert_eq!(a, b);
        assert!(a.contains_key("a"));
        let json_a = serde_json::to_string(&a).expect("serialisable");
        let json_b = serde_json::to_string(&b).expect("serialisable");
        assert_eq!(json_a, json_b);
    }

    #[test]
    fn a_capture_with_no_dns_reports_zeroes_rather_than_dividing_by_zero() {
        let report = analyse_bytes(&fixtures::benign_ping(20, 1)).dns;
        assert_eq!(report.questions, 0);
        assert_eq!(report.mean_query_name_length, 0.0);
        assert_eq!(report.mean_subdomain_entropy, 0.0);
        assert_eq!(report.tunnelling_type_ratio, 0.0);
        assert_eq!(report.unique_name_ratio_busiest_zone, 0.0);
        assert_eq!(report.max_zone_unique_name_ratio, 0.0);
        assert_eq!(report.max_subdomain_entropy, 0.0);
    }

    // ── ICMP ──────────────────────────────────────────────────────────────

    #[test]
    fn a_ping_and_an_icmp_tunnel_separate_on_body_entropy_and_fill_pattern() {
        let ping = analyse_bytes(&fixtures::benign_ping(100, 1)).icmp;
        let tunnel = analyse_bytes(&fixtures::icmp_tunnel(100, 1)).icmp;

        assert!(
            ping.ping_pattern_ratio > 0.9,
            "ordinary ping should match its own fill pattern, got {}",
            ping.ping_pattern_ratio
        );
        assert!(
            tunnel.ping_pattern_ratio < 0.1,
            "a tunnel body should not match the fill pattern, got {}",
            tunnel.ping_pattern_ratio
        );
        // Entropy is reported but is NOT the discriminator here, and the gap
        // is small enough to be worth stating rather than implying: see
        // `entropy_cannot_discriminate_an_icmp_body_because_the_sample_is_too_short`.
        assert!(
            tunnel.mean_body_entropy > ping.mean_body_entropy,
            "entropy: {} against {}",
            tunnel.mean_body_entropy,
            ping.mean_body_entropy
        );
    }

    #[test]
    fn entropy_cannot_discriminate_an_icmp_body_because_the_sample_is_too_short() {
        // A finding, recorded as a test so it cannot quietly stop being true.
        //
        // Shannon entropy over n samples is bounded by log2(n). An ordinary ping
        // body is 56 bytes, so the ceiling is 5.81 bits per byte, and the Linux
        // fill is a monotonic ramp whose 56 bytes hold 44 DISTINCT values, which
        // scores 5.11. A 48-byte encrypted body scores about 5.40 against its own
        // ceiling of 5.59. The two are a quarter of a bit apart, and the ramp is
        // near-maximal entropy despite being the most predictable sequence
        // imaginable, because entropy reads the histogram and not the order.
        //
        // So the structural fill-pattern check is what separates ICMP, and
        // `mean_body_entropy` is kept as a reported measurement rather than as a
        // signal. Anyone tempted to threshold on it should read this first.
        let ping = analyse_bytes(&fixtures::benign_ping(100, 1)).icmp;
        let tunnel = analyse_bytes(&fixtures::icmp_tunnel(100, 1)).icmp;
        let gap = tunnel.mean_body_entropy - ping.mean_body_entropy;
        assert!(
            gap < 1.0,
            "if entropy ever separates ICMP bodies by a whole bit, this finding \
             has changed and the module documentation needs revisiting: gap {gap}"
        );
        // The structural check, by contrast, separates completely.
        assert!(ping.ping_pattern_ratio > 0.9);
        assert!(tunnel.ping_pattern_ratio < 0.1);
    }

    #[test]
    fn a_real_ping_is_echoed_verbatim_and_a_tunnel_reply_is_not() {
        let ping = analyse_bytes(&fixtures::benign_ping(80, 5)).icmp;
        assert!(ping.echo_requests > 0 && ping.echo_replies > 0);
        assert_eq!(
            ping.request_reply_mismatch_ratio, 0.0,
            "a ping reply must echo the request body"
        );
        let tunnel = analyse_bytes(&fixtures::icmp_tunnel(80, 5)).icmp;
        assert!(
            tunnel.request_reply_mismatch_ratio > 0.9,
            "got {}",
            tunnel.request_reply_mismatch_ratio
        );
    }

    #[test]
    fn ordinary_ping_sequence_numbers_are_continuous() {
        let ping = analyse_bytes(&fixtures::benign_ping(50, 1)).icmp;
        assert_eq!(ping.sequence_discontinuity_ratio, 0.0);
    }

    #[test]
    fn a_capture_with_no_icmp_reports_zeroes() {
        let report = analyse_bytes(&fixtures::benign_dns(30, 1)).icmp;
        assert_eq!(report.echo_requests, 0);
        assert_eq!(report.mean_body_entropy, 0.0);
        assert_eq!(report.ping_pattern_ratio, 0.0);
        assert_eq!(report.request_reply_mismatch_ratio, 0.0);
        assert_eq!(report.sequence_discontinuity_ratio, 0.0);
    }

    #[test]
    fn the_ping_fill_pattern_recogniser_knows_the_shapes_it_claims() {
        // Linux: 16 bytes of timestamp then a ramp.
        let mut linux = vec![0xAAu8; 16];
        linux.extend((0x10u8..0x38).collect::<Vec<u8>>());
        assert!(looks_like_ping_fill(&linux));
        // Windows: a repeating lowercase alphabet.
        let windows: Vec<u8> = b"abcdefghijklmnopqrstuvwabcdefghi".to_vec();
        assert!(looks_like_ping_fill(&windows));
        // A single repeated byte.
        assert!(looks_like_ping_fill(&[0x5A; 32]));
        // High-entropy payload must not match.
        let payload: Vec<u8> = (0..56u32).map(|i| (i * 167 % 251) as u8).collect();
        assert!(!looks_like_ping_fill(&payload));
        // Too short to judge.
        assert!(!looks_like_ping_fill(&[1, 2, 3]));
        assert!(!looks_like_ping_fill(&[]));
    }

    // ── Timing ────────────────────────────────────────────────────────────

    #[test]
    fn a_fixed_rate_flow_has_a_low_coefficient_of_variation() {
        let steady = analyse_bytes(&fixtures::steady_flow(200, 10_000_000)).timing;
        assert!(
            steady.coefficient_of_variation < 0.1,
            "got {}",
            steady.coefficient_of_variation
        );
        assert!(steady.busiest_flow_packets > 150);
    }

    #[test]
    fn a_bursty_flow_has_a_higher_coefficient_of_variation_than_a_steady_one() {
        let steady = analyse_bytes(&fixtures::steady_flow(200, 10_000_000)).timing;
        let bursty = analyse_bytes(&fixtures::bursty_flow(200, 1)).timing;
        assert!(
            bursty.coefficient_of_variation > steady.coefficient_of_variation,
            "bursty {} should exceed steady {}",
            bursty.coefficient_of_variation,
            steady.coefficient_of_variation
        );
    }

    #[test]
    fn a_two_level_timing_channel_concentrates_its_histogram() {
        let modulated = analyse_bytes(&fixtures::timing_channel(400, 1)).timing;
        let bursty = analyse_bytes(&fixtures::bursty_flow(400, 1)).timing;
        // The honest expectation: a two-level channel puts most of its mass in
        // two buckets. Whether that beats ordinary jitter is the measurement
        // question, answered by the harness rather than asserted here.
        // 0.86, not above 0.9, and the reason is the bucketing rather than the
        // channel: a gap of 1.0 to 1.2 ms spans buckets 20 and 21, and a gap of
        // 8.0 to 8.4 ms spans 23 and 24, so a two-level channel lands in four
        // power-of-two buckets whenever a level straddles a boundary. A finer or
        // offset bucketing would concentrate it further; log2 was chosen because
        // gaps span microseconds to minutes, and this is the cost of that choice.
        assert!(
            modulated.top_two_bucket_mass > 0.85,
            "got {}",
            modulated.top_two_bucket_mass
        );
        assert!(modulated.interarrival_histogram.len() == INTERARRIVAL_BUCKETS);
        assert!(bursty.interarrival_histogram.iter().sum::<u64>() > 0);
    }

    #[test]
    fn the_timing_features_are_beaten_by_legitimate_constant_bitrate_traffic() {
        // The finding, pinned so it cannot quietly stop being true. A VoIP-shaped
        // flow has LOWER variation than a two-level covert channel, so every
        // "low variation is suspicious" reading is inverted: the legitimate flow
        // scores as more suspicious than the channel.
        let channel = analyse_bytes(&fixtures::timing_channel(400, 1)).timing;
        let voip = analyse_bytes(&fixtures::constant_bitrate_flow(400, 1)).timing;
        assert!(
            voip.coefficient_of_variation < channel.coefficient_of_variation,
            "legitimate CBR {} should sit BELOW the channel {}; if this ever \
             reverses, the timing finding has changed and the module \
             documentation needs revisiting",
            voip.coefficient_of_variation,
            channel.coefficient_of_variation
        );
        assert!(
            voip.interarrival_histogram_entropy < channel.interarrival_histogram_entropy,
            "CBR entropy {} against channel {}",
            voip.interarrival_histogram_entropy,
            channel.interarrival_histogram_entropy
        );
    }

    #[test]
    fn a_capture_with_one_packet_per_flow_has_no_gaps_and_does_not_divide_by_zero() {
        let report = analyse_bytes(&fixtures::one_packet_per_flow(20)).timing;
        assert_eq!(report.mean_interarrival_micros, 0.0);
        assert_eq!(report.stddev_interarrival_micros, 0.0);
        assert_eq!(report.coefficient_of_variation, 0.0);
        assert_eq!(report.interarrival_histogram_entropy, 0.0);
        assert_eq!(report.top_two_bucket_mass, 0.0);
    }

    #[test]
    fn an_empty_capture_produces_a_report_of_zeroes_rather_than_an_error() {
        let mut bytes = Vec::new();
        let writer =
            crate::covert::pcap::PcapWriter::new(&mut bytes, LinkType::Ethernet).expect("header");
        writer.finish().expect("flush");
        let report = analyse_bytes(&bytes);
        assert_eq!(report.capture.packets, 0);
        assert_eq!(report.timing.flows, 0);
        assert_eq!(report.dns.messages, 0);
        assert_eq!(report.icmp.echo_requests, 0);
        assert!(!report.limits_hit);
    }

    #[test]
    fn the_log_bucket_is_monotonic_and_bounded() {
        assert_eq!(log_bucket(0), 0);
        assert!(log_bucket(1_000) < log_bucket(1_000_000));
        assert!(log_bucket(u64::MAX) < INTERARRIVAL_BUCKETS);
        let mut previous = 0;
        for power in 0..63 {
            let bucket = log_bucket(1u64 << power);
            assert!(bucket >= previous);
            previous = bucket;
        }
    }

    // ── Robustness ────────────────────────────────────────────────────────

    #[test]
    fn a_malformed_capture_is_measured_as_far_as_it_reads() {
        let mut bytes = fixtures::dns_tunnel(50, 1, 40);
        bytes.truncate(bytes.len() / 2);
        let report = analyse_bytes(&bytes);
        assert!(report.capture.malformed);
        assert!(
            report.dns.questions > 0,
            "what was readable must be measured"
        );
    }

    #[test]
    fn a_capture_of_random_bytes_in_valid_records_does_not_panic() {
        // Records whose bodies are noise: every parser below has to decline
        // rather than crash, and the report has to come back.
        let mut state = 0x9E37_79B9u32;
        let mut packets = Vec::new();
        for index in 0..200u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let length = 1 + (state as usize % 300);
            let body: Vec<u8> = (0..length)
                .map(|i| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> ((i % 4) * 8)) as u8
                })
                .collect();
            packets.push((index * 1_000_000, body));
        }
        let mut bytes = Vec::new();
        let mut writer =
            crate::covert::pcap::PcapWriter::new(&mut bytes, LinkType::Ethernet).expect("header");
        for (timestamp, body) in &packets {
            writer.write_packet(*timestamp, body).expect("write");
        }
        writer.finish().expect("flush");
        let report = analyse_bytes(&bytes);
        // The point is that it returned at all; the unhandled map records why.
        assert_eq!(report.capture.packets, 200);
        assert!(!report.unhandled.is_empty());
    }

    #[test]
    fn unhandled_packets_are_counted_by_reason_rather_than_lumped_together() {
        let report = analyse_bytes(&fixtures::mixed_unhandled());
        assert!(report.unhandled.len() >= 2, "got {:?}", report.unhandled);
        assert!(report.unhandled.values().all(|&count| count > 0));
    }

    #[test]
    fn the_zone_cap_is_reported_rather_than_silently_truncating_the_count() {
        let report = analyse_bytes(&fixtures::many_zones(MAX_ZONES + 50));
        assert_eq!(report.dns.zones, MAX_ZONES);
        assert!(report.limits_hit);
    }

    #[test]
    fn the_flow_cap_is_reported() {
        let report = analyse_bytes(&fixtures::many_flows(MAX_FLOWS + 20));
        assert_eq!(report.timing.flows, MAX_FLOWS);
        assert!(report.limits_hit);
    }

    #[test]
    fn the_same_capture_measures_identically_twice_and_serialises_stably() {
        let bytes = fixtures::dns_tunnel(100, 11, 40);
        let first = analyse_bytes(&bytes);
        let second = analyse_bytes(&bytes);
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).expect("serialisable"),
            serde_json::to_string(&second).expect("serialisable")
        );
    }

    #[test]
    fn no_timing_feature_may_ever_bear_a_verdict() {
        // The operator's decision, pinned. Timing measured AUC 0.0000 against
        // legitimate constant-bitrate traffic, which is an anti-signal rather
        // than a weak signal, and there is no false-positive ceiling at which it
        // becomes useful. If a future change lets one of these inform a verdict,
        // this test is where that has to be argued.
        let roles = feature_roles();
        for (name, role) in &roles {
            if name.starts_with("timing.") {
                assert_eq!(
                    *role,
                    FeatureRole::AntiSignal,
                    "{name} must stay an anti-signal"
                );
                assert!(!role.may_inform_a_verdict(), "{name}");
            }
        }
        let report = analyse_bytes(&fixtures::timing_channel(50, 1));
        assert!(
            report
                .verdict_bearing_features()
                .iter()
                .all(|name| !name.starts_with("timing.")),
            "a timing feature reached the verdict-bearing set"
        );
    }

    #[test]
    fn every_reported_feature_has_a_measured_role() {
        // A field added without a role would be rendered with no indication of
        // what it is worth, which is the hazard the roles exist to close. Checked
        // against the serialised field names so adding a field to the struct
        // without adding a role fails here.
        let report = analyse_bytes(&fixtures::benign_dns(20, 1));
        let json = serde_json::to_value(&report).expect("serialisable");
        let roles = feature_roles();
        for channel in ["dns", "icmp", "timing"] {
            let object = json[channel].as_object().expect("a channel object");
            for field in object.keys() {
                // Counts and maps describe the capture rather than scoring it.
                let descriptive = [
                    "messages",
                    "malformed_messages",
                    "questions",
                    "type_counts",
                    "zones",
                    "busiest_zone_queries",
                    "echo_requests",
                    "echo_replies",
                    "flows",
                    "busiest_flow_packets",
                    "interarrival_histogram",
                ];
                if descriptive.contains(&field.as_str()) {
                    continue;
                }
                let key = format!("{channel}.{field}");
                assert!(
                    roles.contains_key(&key),
                    "{key} is reported with no measured role"
                );
            }
        }
    }

    #[test]
    fn coverage_distinguishes_nothing_found_from_nothing_examined() {
        // A capture of traffic the discriminating features can read.
        let with_dns = analyse_bytes(&fixtures::benign_dns(20, 1));
        assert!(with_dns.had_discriminating_coverage());
        // A capture of nothing but TCP timing: the only features that ran are
        // anti-signals, so "nothing found" would be a claim about the capture.
        let timing_only = analyse_bytes(&fixtures::bursty_flow(50, 1));
        assert!(!timing_only.had_discriminating_coverage());
        assert!(timing_only.timing.busiest_flow_packets > 0);
    }

    #[test]
    fn a_role_explains_itself_in_plain_language() {
        for role in [
            FeatureRole::Discriminating,
            FeatureRole::DominantChannelOnly,
            FeatureRole::Inconclusive,
            FeatureRole::AntiSignal,
        ] {
            let text = role.explanation();
            assert!(!text.is_empty());
            assert!(!text.contains('_'), "{text} reads like an identifier");
        }
        assert!(FeatureRole::Discriminating.may_inform_a_verdict());
        assert!(FeatureRole::DominantChannelOnly.may_inform_a_verdict());
        assert!(!FeatureRole::Inconclusive.may_inform_a_verdict());
        assert!(!FeatureRole::AntiSignal.may_inform_a_verdict());
    }

    #[test]
    fn the_report_carries_the_calibration_note_so_it_cannot_be_read_as_a_verdict() {
        let report = analyse_bytes(&fixtures::benign_dns(10, 1));
        assert!(report.calibration_note.contains("not a verdict"));
        assert!(report.calibration_note.contains("false-positive"));
    }

    #[test]
    fn analysing_a_capture_on_disk_agrees_with_the_in_memory_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("fixture.pcap");
        let bytes = fixtures::dns_tunnel(40, 2, 40);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(
            analyse_capture(&path).expect("analyse"),
            analyse_bytes(&bytes)
        );
    }

    #[test]
    fn a_missing_capture_is_a_loud_file_not_found() {
        let err = analyse_capture(std::path::Path::new("/nonexistent/stegcore/x.pcap"))
            .expect_err("must fail");
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn the_body_digest_separates_different_bodies_and_matches_equal_ones() {
        assert_eq!(body_digest(b"same"), body_digest(b"same"));
        assert_ne!(body_digest(b"same"), body_digest(b"different"));
        assert_eq!(body_digest(b""), body_digest(b""));
    }

    #[test]
    fn dns_over_tcp_inside_one_segment_is_read() {
        let report = analyse_bytes(&fixtures::dns_over_tcp_tunnel(40, 1)).dns;
        assert!(
            report.questions > 0,
            "a single-segment TCP query was missed"
        );
    }
}
