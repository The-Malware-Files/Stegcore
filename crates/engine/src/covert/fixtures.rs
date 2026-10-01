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

//! Capture fixtures for measuring the detector, and deliberately nothing more.
//!
//! # This is a test instrument, not a tunnel
//!
//! The detector needs matched arms to be measured against, which means something
//! has to produce traffic that looks like a covert channel. The difference
//! between that and an exfiltration tool is not a matter of intent, so it is
//! built into what this module can do:
//!
//! - **It writes capture files. It has no socket, no address to connect to and
//!   no transmit path.** Every function here returns a `Vec<u8>` holding PCAP
//!   bytes. There is nothing to point at a network.
//! - **It carries no caller payload.** Every generator fills its channel from a
//!   seeded pseudorandom stream. There is no parameter that takes a file, a
//!   buffer or a string to encode, so it cannot move anyone's data anywhere.
//! - **It has no evasion controls.** No jitter, no padding, no rate shaping, no
//!   label-length tuning, no record-type rotation to blend in. The generators
//!   are shaped to be *recognisable*, which is what a ground-truth fixture needs
//!   and the opposite of what an evasive channel needs.
//! - **It has no receiving side.** Nothing here decodes a fixture back, so even
//!   the encoding is one-way and useless as a transport.
//!
//! Those four absences are the whole design. A generator with a payload
//! parameter and a jitter knob would be a tunnel with a PCAP backend; this is
//! not that, and the measurement does not need it to be.
//!
//! # Determinism
//!
//! Every generator takes a seed and derives all content and all timestamps from
//! it. Nothing reads the clock. The same arguments give byte-identical output,
//! which is what lets the measured numbers be reproduced.

use super::pcap::{LinkType, PcapWriter};

/// SplitMix64, so fixtures are reproducible without pulling the `rand`
/// machinery into a path that only needs repeatable bytes.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            // Mixed so that small seeds like 1 and 2 do not produce correlated
            // streams, which would make two arms look more alike than they are.
            state: seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0x1234_5678_9ABC_DEF0),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

/// Base32 alphabet without padding, which is what DNS tunnels use because a
/// label must be letters, digits and hyphens.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_label(rng: &mut Rng, length: usize) -> String {
    (0..length)
        .map(|_| char::from(BASE32[(rng.next_u64() % 32) as usize]))
        .collect()
}

/// Hostnames an ordinary network asks for. A small, repeating set, because that
/// is the property that distinguishes benign resolution from a tunnel: real
/// clients revisit names and a tunnel does not.
const COMMON_HOSTS: &[&str] = &[
    "www.example.com",
    "api.example.com",
    "cdn.example.com",
    "mail.example.net",
    "login.example.net",
    "static.example.org",
    "updates.example.org",
    "ntp.pool.example",
    "docs.example.com",
    "search.example.net",
];

// ── Frame builders ────────────────────────────────────────────────────────────

fn ethernet_ipv4(protocol: u8, source: [u8; 4], destination: [u8; 4], transport: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 14];
    // Locally administered MAC addresses, so a fixture cannot be mistaken for a
    // capture of real hardware.
    frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let total = 20 + transport.len();
    let mut header = vec![0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    header[8] = 64;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(transport);
    frame
}

fn udp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn tcp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 20];
    out[0..2].copy_from_slice(&source_port.to_be_bytes());
    out[2..4].copy_from_slice(&destination_port.to_be_bytes());
    out[12] = 5 << 4;
    out[13] = 0x18; // PSH and ACK
    out.extend_from_slice(body);
    out
}

fn icmp(message_type: u8, identifier: u16, sequence: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![message_type, 0, 0, 0];
    out.extend_from_slice(&identifier.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn dns_query(transaction_id: u16, name: &str, record_type: u16, response: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&(if response { 0x8180u16 } else { 0x0100u16 }).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(if response { 1u16 } else { 0u16 }).to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&record_type.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// Assemble a capture from timestamped frames.
fn capture(frames: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer =
        PcapWriter::new(&mut bytes, LinkType::Ethernet).expect("writing to a Vec cannot fail");
    for (timestamp, frame) in frames {
        writer
            .write_packet(timestamp, &frame)
            .expect("fixture frames are well under the record cap");
    }
    writer.finish().expect("flushing a Vec cannot fail");
    bytes
}

/// Fixed epoch for every fixture, so no generator reads the clock.
const EPOCH_NANOS: u64 = 1_700_000_000_000_000_000;

// ── DNS fixtures ──────────────────────────────────────────────────────────────

/// Ordinary DNS resolution: a small set of repeating hostnames, A and AAAA
/// records, with a reply to each query.
pub fn benign_dns(queries: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..queries {
        let host = COMMON_HOSTS[(rng.next_u64() as usize) % COMMON_HOSTS.len()];
        let record_type = if rng.next_u64() % 4 == 0 { 28 } else { 1 };
        let transaction = (rng.next_u64() & 0xFFFF) as u16;
        let query = dns_query(transaction, host, record_type, false);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 5],
                [10, 0, 0, 53],
                &udp(40000 + (index as u16 % 1000), 53, &query),
            ),
        ));
        // A reply a few milliseconds later, which is what a resolver does.
        now += 2_000_000 + rng.below(8_000_000);
        let reply = dns_query(transaction, host, record_type, true);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 53],
                [10, 0, 0, 5],
                &udp(53, 40000 + (index as u16 % 1000), &reply),
            ),
        ));
        // Ordinary spacing between lookups, bursty rather than regular.
        now += 20_000_000 + rng.below(400_000_000);
    }
    capture(frames)
}

/// A DNS tunnel's shape: long high-entropy subdomains under one zone, TXT
/// records, every name distinct.
///
/// `label_length` is the per-label size in characters and exists because the
/// detector's efficacy depends on it, so the measurement has to vary it. It is a
/// measurement axis, not an evasion control: shortening the label makes the
/// fixture less detectable and also carries less, which is the trade-off the
/// harness is there to quantify.
pub fn dns_tunnel(queries: usize, seed: u64, label_length: usize) -> Vec<u8> {
    dns_tunnel_typed(queries, seed, label_length, 16)
}

/// As [`dns_tunnel`] but using NULL records, which is the strongest single tell.
pub fn dns_tunnel_null(queries: usize, seed: u64, label_length: usize) -> Vec<u8> {
    dns_tunnel_typed(queries, seed, label_length, 10)
}

fn dns_tunnel_typed(queries: usize, seed: u64, label_length: usize, record_type: u16) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    // Labels are capped at the protocol's 63 bytes; a longer request is clamped
    // rather than producing an invalid name.
    let label_length = label_length.clamp(1, 63);
    for index in 0..queries {
        // Two payload labels under a single zone, which is the common shape.
        let name = format!(
            "{}.{}.tunnel.example.com",
            base32_label(&mut rng, label_length),
            base32_label(&mut rng, label_length / 2 + 1)
        );
        let transaction = (rng.next_u64() & 0xFFFF) as u16;
        let query = dns_query(transaction, &name, record_type, false);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 5],
                [10, 0, 0, 53],
                &udp(40000 + (index as u16 % 1000), 53, &query),
            ),
        ));
        now += 1_000_000 + rng.below(3_000_000);
        let reply = dns_query(transaction, &name, record_type, true);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 53],
                [10, 0, 0, 5],
                &udp(53, 40000 + (index as u16 % 1000), &reply),
            ),
        ));
        now += 5_000_000 + rng.below(20_000_000);
    }
    capture(frames)
}

/// A DNS tunnel over TCP, each message wholly inside one segment, to exercise
/// that path.
pub fn dns_over_tcp_tunnel(queries: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for _ in 0..queries {
        let name = format!("{}.tunnel.example.com", base32_label(&mut rng, 40));
        let message = dns_query((rng.next_u64() & 0xFFFF) as u16, &name, 16, false);
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&message);
        frames.push((
            now,
            ethernet_ipv4(6, [10, 0, 0, 5], [10, 0, 0, 53], &tcp(40000, 53, &framed)),
        ));
        now += 5_000_000 + rng.below(10_000_000);
    }
    capture(frames)
}

/// One ordinary query as a real resolver sees it: a name and a record type.
///
/// The single source of truth for background traffic, used by both
/// [`realistic_dns`] and [`mixed_dns`]. That sharing is not tidiness, it is the
/// thing that makes a dilution measurement valid: when the two arms draw their
/// background from different code, any difference between the code shows up as
/// detector performance, and a measurement comparing two backgrounds while
/// claiming to compare tunnel against no-tunnel reads as a perfect detector. It
/// did, before this was factored out, reporting AUC 1.0000 for a tunnel at 1% of
/// traffic, which is arithmetically impossible for a per-capture mean.
fn background_query(rng: &mut Rng) -> (String, u16) {
    // A mixture that roughly matches what a busy office resolver sees. Every
    // branch is a legitimate occurrence of a property that also makes a tunnel
    // conspicuous: long names, high-entropy labels, TXT lookups, unique names.
    match rng.below(100) {
        // Repeated common hostnames, still the bulk of real traffic.
        0..=44 => (
            COMMON_HOSTS[(rng.next_u64() as usize) % COMMON_HOSTS.len()].to_string(),
            if rng.below(4) == 0 { 28 } else { 1 },
        ),
        // CDN cache keys: a long high-entropy label under a shared zone.
        45..=64 => {
            let key_length = 16 + rng.below(24) as usize;
            (
                format!(
                    "{}.{}.cdn.example.net",
                    base32_label(rng, key_length),
                    base32_label(rng, 8)
                ),
                1,
            )
        }
        // Cloud instance names: long and structured.
        65..=74 => (
            format!(
                "ec2-{}-{}-{}-{}.compute-{}.amazonaws.example",
                rng.below(256),
                rng.below(256),
                rng.below(256),
                rng.below(256),
                rng.below(9) + 1
            ),
            1,
        ),
        // DKIM selectors: TXT, long, random-looking.
        75..=84 => {
            let selector_length = 12 + rng.below(20) as usize;
            (
                format!(
                    "{}._domainkey.mail.example.org",
                    base32_label(rng, selector_length)
                ),
                16,
            )
        }
        // ACME challenges: TXT under a per-certificate label.
        85..=89 => (
            format!("_acme-challenge.{}.example.com", base32_label(rng, 10)),
            16,
        ),
        // SPF and DMARC lookups on the apex: TXT and short.
        90..=94 => ("example.com".to_string(), 16),
        // Per-request tracing names: unique, never repeated, under one zone.
        95..=97 => (
            format!(
                "{}.{}.trace.example.net",
                base32_label(rng, 32),
                base32_label(rng, 12)
            ),
            1,
        ),
        // Reverse lookups.
        _ => (
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                rng.below(256),
                rng.below(256),
                rng.below(256),
                rng.below(256)
            ),
            12,
        ),
    }
}

/// Ordinary DNS as a real network actually produces it, which is a far harder
/// negative arm than [`benign_dns`].
///
/// [`benign_dns`] asks for ten hostnames over and over, so anything with a long
/// random label beats it trivially. Real resolution is not like that, and every
/// property that makes a tunnel conspicuous also occurs legitimately: long cloud
/// and CDN names, high-entropy cache keys and DKIM selectors, TXT lookups for
/// SPF, DKIM, DMARC and ACME, and unique per-request tracing names a resolver
/// will never see again. This arm has all four, and it is the arm the measured
/// numbers should be read from.
///
/// Defined as [`mixed_dns`] with no tunnel, so the two cannot drift apart.
pub fn realistic_dns(queries: usize, seed: u64) -> Vec<u8> {
    mixed_dns(queries, 0, seed, 40)
}

/// A tunnel diluted into realistic background traffic.
///
/// `tunnel_percent` is the share of queries belonging to the tunnel, and it is
/// the axis the field cares about: a detector reading per-capture averages sees a
/// tunnel at 1% of traffic as a 1% perturbation of the mean, which is a
/// completely different problem from a capture that is nothing but tunnel.
///
/// At `tunnel_percent == 0` this is byte-identical to [`realistic_dns`], which is
/// asserted by a test. That identity is what makes the dilution axis mean
/// something.
pub fn mixed_dns(queries: usize, tunnel_percent: u64, seed: u64, label_length: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let label_length = label_length.clamp(1, 63);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..queries {
        // Drawn for every slot whatever the percentage, so the decision itself
        // does not shift the stream between one dilution and another.
        let is_tunnel = rng.below(100) < tunnel_percent;
        let (name, record_type) = if is_tunnel {
            let first = base32_label(&mut rng, label_length);
            let second = base32_label(&mut rng, label_length / 2 + 1);
            (format!("{first}.{second}.tunnel.example.com"), 16)
        } else {
            background_query(&mut rng)
        };
        let transaction = (rng.next_u64() & 0xFFFF) as u16;
        let port = 40000 + (index as u16 % 1000);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 5],
                [10, 0, 0, 53],
                &udp(port, 53, &dns_query(transaction, &name, record_type, false)),
            ),
        ));
        now += 2_000_000 + rng.below(8_000_000);
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 53],
                [10, 0, 0, 5],
                &udp(53, port, &dns_query(transaction, &name, record_type, true)),
            ),
        ));
        now += 5_000_000 + rng.below(300_000_000);
    }
    capture(frames)
}

/// Many distinct zones, to drive the zone cap.
pub fn many_zones(count: usize) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..count {
        let name = format!("host.zone{index}.example");
        let query = dns_query(index as u16, &name, 1, false);
        frames.push((
            now,
            ethernet_ipv4(17, [10, 0, 0, 5], [10, 0, 0, 53], &udp(40000, 53, &query)),
        ));
        now += 1_000_000;
    }
    capture(frames)
}

// ── ICMP fixtures ─────────────────────────────────────────────────────────────

/// Ordinary ping traffic: 56-byte bodies with the Linux timestamp-then-ramp
/// fill, one reply echoing each request verbatim, one second apart.
pub fn benign_ping(pings: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let identifier = (rng.next_u64() & 0xFFFF) as u16;
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for sequence in 0..pings {
        let mut body = Vec::with_capacity(56);
        // Eight bytes that stand in for ping's timestamp, then the ramp.
        body.extend_from_slice(&(now / 1000).to_be_bytes());
        body.extend_from_slice(&[0u8; 8]);
        for offset in 0..40u8 {
            body.push(0x10u8.wrapping_add(offset));
        }
        let request = icmp(8, identifier, sequence as u16, &body);
        frames.push((
            now,
            ethernet_ipv4(1, [10, 0, 0, 5], [10, 0, 0, 9], &request),
        ));
        // The reply echoes the body, which is what a real ping does.
        now += 1_000_000 + rng.below(4_000_000);
        let reply = icmp(0, identifier, sequence as u16, &body);
        frames.push((now, ethernet_ipv4(1, [10, 0, 0, 9], [10, 0, 0, 5], &reply)));
        now += 1_000_000_000;
    }
    capture(frames)
}

/// An ICMP tunnel's shape: high-entropy bodies, a reply body that differs from
/// the request, sequence numbers used as framing rather than as a counter.
pub fn icmp_tunnel(messages: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let identifier = (rng.next_u64() & 0xFFFF) as u16;
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..messages {
        let body = rng.bytes(48);
        // Sequence jumps rather than incrementing, which is what framing a
        // payload into the field looks like.
        let sequence = (index as u16).wrapping_mul(7).wrapping_add(13);
        frames.push((
            now,
            ethernet_ipv4(
                1,
                [10, 0, 0, 5],
                [10, 0, 0, 9],
                &icmp(8, identifier, sequence, &body),
            ),
        ));
        now += 2_000_000 + rng.below(3_000_000);
        // The reply carries different bytes, because it is the return channel.
        let reply_body = rng.bytes(48);
        frames.push((
            now,
            ethernet_ipv4(
                1,
                [10, 0, 0, 9],
                [10, 0, 0, 5],
                &icmp(0, identifier, sequence, &reply_body),
            ),
        ));
        now += 10_000_000 + rng.below(20_000_000);
    }
    capture(frames)
}

// ── Timing fixtures ───────────────────────────────────────────────────────────

/// A flow at an exactly fixed rate, which is the easy end of timing detection.
pub fn steady_flow(packets: usize, gap_nanos: u64) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..packets {
        frames.push((
            now,
            ethernet_ipv4(
                6,
                [10, 0, 0, 5],
                [10, 0, 0, 80],
                &tcp(44000, 443, &[(index & 0xFF) as u8; 16]),
            ),
        ));
        now += gap_nanos;
    }
    capture(frames)
}

/// Ordinary bursty traffic: heavy-tailed gaps, which is what a real link looks
/// like and the negative arm the timing features have to beat.
pub fn bursty_flow(packets: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..packets {
        frames.push((
            now,
            ethernet_ipv4(
                6,
                [10, 0, 0, 5],
                [10, 0, 0, 80],
                &tcp(44000, 443, &[(index & 0xFF) as u8; 16]),
            ),
        ));
        // A crude heavy tail: mostly short gaps with occasional long ones, which
        // is the shape that makes timing detection hard.
        now += if rng.next_u64() % 8 == 0 {
            50_000_000 + rng.below(500_000_000)
        } else {
            200_000 + rng.below(3_000_000)
        };
    }
    capture(frames)
}

/// A legitimate constant-bitrate flow: VoIP-shaped, a packet every 20 ms with
/// the small jitter a real network adds.
///
/// This is the timing detector's real negative arm and the reason the easier one
/// is not enough. Voice and video carry constant-bitrate streams, keepalives and
/// heartbeats fire on a timer, and NTP polls on a schedule. All of them have a
/// near-zero coefficient of variation, which is the headline property of a
/// fixed-rate covert channel. A feature set that calls low jitter suspicious
/// calls every VoIP call on the network suspicious.
pub fn constant_bitrate_flow(packets: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..packets {
        frames.push((
            now,
            ethernet_ipv4(
                17,
                [10, 0, 0, 5],
                [10, 0, 0, 90],
                &udp(16384, 16386, &[(index & 0xFF) as u8; 172]),
            ),
        ));
        // 20 ms nominal with a couple of hundred microseconds of network jitter,
        // which is what a real codec stream looks like on a healthy link.
        now += 20_000_000 - 200_000 + rng.below(400_000);
    }
    capture(frames)
}

/// A two-level timing channel: one of two gaps per packet, which is the textbook
/// binary modulation.
pub fn timing_channel(packets: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..packets {
        frames.push((
            now,
            ethernet_ipv4(
                6,
                [10, 0, 0, 5],
                [10, 0, 0, 80],
                &tcp(44000, 443, &[(index & 0xFF) as u8; 16]),
            ),
        ));
        // A zero is a short gap and a one is a long one, with a little spread so
        // the fixture is not a single histogram spike.
        now += if rng.next_u64() % 2 == 0 {
            1_000_000 + rng.below(200_000)
        } else {
            8_000_000 + rng.below(400_000)
        };
    }
    capture(frames)
}

/// One packet in each of many flows, so no flow has an inter-arrival gap.
pub fn one_packet_per_flow(flows: usize) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..flows {
        let port = 40000u16.wrapping_add(index as u16);
        frames.push((
            now,
            ethernet_ipv4(6, [10, 0, 0, 5], [10, 0, 0, 80], &tcp(port, 443, &[0u8; 8])),
        ));
        now += 1_000_000;
    }
    capture(frames)
}

/// Many distinct flows, to drive the flow cap.
pub fn many_flows(count: usize) -> Vec<u8> {
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;
    for index in 0..count {
        // Vary the destination address so the flow key differs even past the
        // 16-bit port space.
        let octet = ((index >> 8) & 0xFF) as u8;
        let port = 40000u16.wrapping_add((index & 0xFF) as u16);
        frames.push((
            now,
            ethernet_ipv4(
                6,
                [10, 0, 0, 5],
                [10, 0, octet, 80],
                &tcp(port, 443, &[0u8; 8]),
            ),
        ));
        now += 1_000_000;
    }
    capture(frames)
}

/// A capture of frames the dissector declines for several different reasons, so
/// the unhandled breakdown has something to break down.
pub fn mixed_unhandled() -> Vec<u8> {
    let mut frames = Vec::new();
    let mut now = EPOCH_NANOS;

    // ARP: recognised Ethernet, not IP.
    let mut arp = vec![0u8; 14];
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    arp.extend_from_slice(&[0u8; 28]);
    frames.push((now, arp));
    now += 1_000_000;

    // SCTP: IP, but a transport the dissector does not read.
    frames.push((
        now,
        ethernet_ipv4(132, [10, 0, 0, 5], [10, 0, 0, 6], &[0u8; 20]),
    ));
    now += 1_000_000;

    // A non-initial fragment.
    let mut fragment = ethernet_ipv4(17, [10, 0, 0, 5], [10, 0, 0, 6], &udp(1000, 53, &[0u8; 20]));
    fragment[14 + 6..14 + 8].copy_from_slice(&8u16.to_be_bytes());
    frames.push((now, fragment));

    capture(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covert::pcap::PcapReader;
    use std::io::Cursor;

    fn count_packets(bytes: &[u8]) -> usize {
        let mut reader = PcapReader::new(Cursor::new(bytes.to_vec())).expect("header");
        let mut count = 0;
        while reader.next_packet().expect("read").is_some() {
            count += 1;
        }
        count
    }

    #[test]
    fn every_generator_is_deterministic() {
        assert_eq!(benign_dns(30, 1), benign_dns(30, 1));
        assert_eq!(dns_tunnel(30, 1, 40), dns_tunnel(30, 1, 40));
        assert_eq!(dns_tunnel_null(30, 1, 40), dns_tunnel_null(30, 1, 40));
        assert_eq!(dns_over_tcp_tunnel(30, 1), dns_over_tcp_tunnel(30, 1));
        assert_eq!(benign_ping(30, 1), benign_ping(30, 1));
        assert_eq!(icmp_tunnel(30, 1), icmp_tunnel(30, 1));
        assert_eq!(steady_flow(30, 1_000_000), steady_flow(30, 1_000_000));
        assert_eq!(bursty_flow(30, 1), bursty_flow(30, 1));
        assert_eq!(timing_channel(30, 1), timing_channel(30, 1));
        assert_eq!(many_zones(10), many_zones(10));
        assert_eq!(many_flows(10), many_flows(10));
        assert_eq!(mixed_unhandled(), mixed_unhandled());
        assert_eq!(realistic_dns(30, 1), realistic_dns(30, 1));
        assert_eq!(mixed_dns(30, 5, 1, 40), mixed_dns(30, 5, 1, 40));
        assert_eq!(constant_bitrate_flow(30, 1), constant_bitrate_flow(30, 1));
        assert_eq!(one_packet_per_flow(10), one_packet_per_flow(10));
    }

    #[test]
    fn a_zero_percent_tunnel_is_exactly_the_negative_arm() {
        // The invariant that makes the dilution axis valid. Without it, the two
        // arms of a dilution measurement differ in their background as well as
        // in the tunnel, and the detector gets credit for telling two background
        // generators apart. That is precisely the bug this test was written
        // after finding: AUC 1.0000 for a tunnel at 1% of traffic.
        for seed in 0..8u64 {
            assert_eq!(
                mixed_dns(50, 0, seed, 40),
                realistic_dns(50, seed),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn a_higher_dilution_really_does_put_more_tunnel_names_in() {
        let count = |percent| {
            queried_names(&mixed_dns(400, percent, 1, 40))
                .iter()
                .filter(|name| name.ends_with("tunnel.example.com"))
                .count()
        };
        let (none, low, high) = (count(0), count(10), count(50));
        assert_eq!(none, 0);
        assert!(low > 0 && low < high, "{none}, {low}, {high}");
    }

    #[test]
    fn different_seeds_give_different_captures() {
        assert_ne!(dns_tunnel(30, 1, 40), dns_tunnel(30, 2, 40));
        assert_ne!(benign_dns(30, 1), benign_dns(30, 2));
        assert_ne!(icmp_tunnel(30, 1), icmp_tunnel(30, 2));
    }

    /// Collect every DNS name a capture queries, which is the seeded content of
    /// a DNS fixture with all the fixed framing stripped away.
    fn queried_names(bytes: &[u8]) -> std::collections::BTreeSet<String> {
        let mut reader = PcapReader::new(Cursor::new(bytes.to_vec())).expect("header");
        let mut names = std::collections::BTreeSet::new();
        while let Some((_, frame)) = reader.next_packet().expect("read") {
            if let crate::covert::packet::Dissection::Udp { payload, .. } =
                crate::covert::packet::dissect(LinkType::Ethernet, frame)
            {
                if let Some(message) = crate::covert::dns::parse(payload) {
                    for question in message.questions {
                        names.insert(question.name);
                    }
                }
            }
        }
        names
    }

    #[test]
    fn adjacent_seeds_are_not_correlated() {
        // The seed is mixed before use, so seed 1 and seed 2 must not produce
        // similar content.
        //
        // Compared on the generated names rather than on raw bytes, because most
        // of a fixture is framing that is identical by construction and says
        // nothing about the seed. Measured, only 40% of bytes differ between
        // adjacent seeds, and that figure is dominated by the 58 bytes per packet
        // of Ethernet, IP, UDP and record headers plus the fixed
        // `.tunnel.example.com` suffix, not by any correlation in the stream. The
        // names are the part the seed controls, so the names are what to check.
        let one = queried_names(&dns_tunnel(40, 1, 40));
        let two = queried_names(&dns_tunnel(40, 2, 40));
        assert_eq!(one.len(), 40, "each query should have a distinct name");
        assert_eq!(two.len(), 40);
        assert!(
            one.intersection(&two).next().is_none(),
            "adjacent seeds produced an overlapping name"
        );
    }

    #[test]
    fn every_fixture_reads_back_as_a_valid_capture() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("benign_dns", benign_dns(20, 1)),
            ("dns_tunnel", dns_tunnel(20, 1, 40)),
            ("dns_tunnel_null", dns_tunnel_null(20, 1, 40)),
            ("dns_over_tcp", dns_over_tcp_tunnel(20, 1)),
            ("benign_ping", benign_ping(20, 1)),
            ("icmp_tunnel", icmp_tunnel(20, 1)),
            ("steady", steady_flow(20, 1_000_000)),
            ("bursty", bursty_flow(20, 1)),
            ("timing", timing_channel(20, 1)),
            ("unhandled", mixed_unhandled()),
            ("realistic_dns", realistic_dns(20, 1)),
            ("mixed_dns", mixed_dns(20, 10, 1, 40)),
            ("cbr", constant_bitrate_flow(20, 1)),
        ];
        for (name, bytes) in cases {
            let mut reader = PcapReader::new(Cursor::new(bytes)).expect(name);
            while reader.next_packet().expect(name).is_some() {}
            assert!(
                !reader.stats().malformed,
                "{name} produced a malformed capture"
            );
            assert!(reader.stats().packets > 0, "{name} produced no packets");
        }
    }

    #[test]
    fn the_query_and_reply_pair_means_two_packets_per_exchange() {
        assert_eq!(count_packets(&benign_dns(25, 1)), 50);
        assert_eq!(count_packets(&dns_tunnel(25, 1, 40)), 50);
        assert_eq!(count_packets(&benign_ping(25, 1)), 50);
        assert_eq!(count_packets(&icmp_tunnel(25, 1)), 50);
        // One-way generators emit one packet each.
        assert_eq!(count_packets(&dns_over_tcp_tunnel(25, 1)), 25);
        assert_eq!(count_packets(&steady_flow(25, 1_000_000)), 25);
    }

    #[test]
    fn an_over_long_label_request_is_clamped_to_the_protocol_limit() {
        // 200 characters is not a legal label; the generator must clamp rather
        // than emit a name no parser would accept.
        let bytes = dns_tunnel(5, 1, 200);
        let mut reader = PcapReader::new(Cursor::new(bytes)).expect("header");
        let mut seen = 0;
        while let Some((_, frame)) = reader.next_packet().expect("read") {
            if let crate::covert::packet::Dissection::Udp { payload, .. } =
                crate::covert::packet::dissect(LinkType::Ethernet, frame)
            {
                if let Some(message) = crate::covert::dns::parse(payload) {
                    assert!(!message.malformed, "clamping produced an unparseable name");
                    seen += 1;
                }
            }
        }
        assert!(seen > 0);
    }

    #[test]
    fn a_zero_length_request_produces_an_empty_capture_rather_than_a_panic() {
        for bytes in [
            benign_dns(0, 1),
            dns_tunnel(0, 1, 40),
            benign_ping(0, 1),
            icmp_tunnel(0, 1),
            steady_flow(0, 1_000_000),
            bursty_flow(0, 1),
            timing_channel(0, 1),
            many_zones(0),
            realistic_dns(0, 1),
            mixed_dns(0, 10, 1, 40),
            constant_bitrate_flow(0, 1),
            many_flows(0),
            one_packet_per_flow(0),
        ] {
            assert_eq!(count_packets(&bytes), 0);
        }
    }

    #[test]
    fn the_rng_bound_helper_handles_a_zero_bound() {
        let mut rng = Rng::new(1);
        assert_eq!(rng.below(0), 0);
        assert!(rng.below(10) < 10);
        assert_eq!(rng.bytes(0), Vec::<u8>::new());
        assert_eq!(rng.bytes(5).len(), 5);
    }

    #[test]
    fn base32_labels_use_only_characters_a_dns_label_may_hold() {
        let mut rng = Rng::new(42);
        let label = base32_label(&mut rng, 63);
        assert_eq!(label.len(), 63);
        assert!(label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
    }

    #[test]
    fn no_generator_takes_a_caller_payload() {
        // Not a behavioural test but a structural one, and the reason it exists
        // is the module's whole premise: if a `&[u8]` payload parameter ever
        // appears on one of these, this module has become a tunnel with a PCAP
        // backend. The signatures below are the contract; changing one should
        // mean deleting this test deliberately rather than by accident.
        let _: fn(usize, u64) -> Vec<u8> = benign_dns;
        let _: fn(usize, u64) -> Vec<u8> = realistic_dns;
        let _: fn(usize, u64, u64, usize) -> Vec<u8> = mixed_dns;
        let _: fn(usize, u64, usize) -> Vec<u8> = dns_tunnel;
        let _: fn(usize, u64, usize) -> Vec<u8> = dns_tunnel_null;
        let _: fn(usize, u64) -> Vec<u8> = dns_over_tcp_tunnel;
        let _: fn(usize, u64) -> Vec<u8> = benign_ping;
        let _: fn(usize, u64) -> Vec<u8> = icmp_tunnel;
        let _: fn(usize, u64) -> Vec<u8> = timing_channel;
        let _: fn(usize, u64) -> Vec<u8> = bursty_flow;
        let _: fn(usize, u64) -> Vec<u8> = steady_flow;
        let _: fn(usize, u64) -> Vec<u8> = constant_bitrate_flow;
    }
}
