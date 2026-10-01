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

//! Just enough DNS to read the question section of a query or response.
//!
//! The detector needs the queried name, its labels and the record type. It does
//! not need the answer records, so they are not parsed: every byte of parsing
//! that is not needed is attack surface that is not earned.
//!
//! # Compression pointers are the hazard
//!
//! A DNS name is a sequence of length-prefixed labels, and a label length byte
//! whose top two bits are set is instead a pointer to an offset elsewhere in the
//! message. A pointer that points at itself, or two pointers that point at each
//! other, make a parser loop forever; this is an old and well-known denial of
//! service. Two bounds stop it here: pointers followed are capped at
//! [`MAX_POINTERS`], and every pointer must point strictly backwards, which
//! makes a cycle impossible rather than merely unlikely.
//!
//! # Caps
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_MESSAGE_BYTES`] | 65535 | Message size parsed, the protocol's own ceiling |
//! | [`MAX_NAME_BYTES`] | 255 | Assembled name length, the protocol's own limit |
//! | [`MAX_LABELS`] | 128 | Labels in one name |
//! | [`MAX_POINTERS`] | 16 | Compression pointers followed while reading one name |

use serde::{Deserialize, Serialize};

/// Largest DNS message parsed. A UDP datagram cannot exceed this and a TCP
/// message is length-prefixed with a 16-bit field, so this is the protocol's
/// own ceiling rather than a chosen one.
pub const MAX_MESSAGE_BYTES: usize = 65_535;

/// Largest assembled name, from RFC 1035.
pub const MAX_NAME_BYTES: usize = 255;

/// Largest number of labels in one name. RFC 1035 allows a name of 255 bytes
/// with labels of at least two bytes each, so 128 cannot be reached legitimately
/// and a message that tries is malformed.
pub const MAX_LABELS: usize = 128;

/// Compression pointers followed while reading one name.
pub const MAX_POINTERS: usize = 16;

/// The record types the detector distinguishes. TXT and NULL are the tunnelling
/// tells, so they are named; the rest are counted as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    /// Type 10. Has no defined presentation format and is almost never seen in
    /// ordinary traffic, which is exactly why tunnels like it.
    Null,
    Txt,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Any,
    Other(u16),
}

impl RecordType {
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            10 => Self::Null,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            255 => Self::Any,
            other => Self::Other(other),
        }
    }

    /// Whether this type is one of the ones that carry arbitrary bytes well and
    /// appear rarely in ordinary traffic. Used as a feature input, not as a
    /// verdict: plenty of legitimate traffic queries TXT.
    pub fn is_tunnelling_favourite(self) -> bool {
        matches!(self, Self::Txt | Self::Null | Self::Cname)
    }
}

/// One question from a DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The name as queried, lowercased, labels joined with dots and no trailing
    /// dot. Lowercased because DNS names are case-insensitive and some tunnels
    /// use mixed case as an extra channel, which would otherwise inflate the
    /// unique-name count for ordinary traffic too.
    pub name: String,
    /// The labels in order, before the join, so per-label statistics do not have
    /// to re-split the name.
    pub labels: Vec<String>,
    pub record_type: RecordType,
}

impl Question {
    /// The registrable-looking suffix: the last two labels, which is the zone a
    /// tunnel operates under. `a1b2c3.tunnel.example.com` gives
    /// `example.com`.
    ///
    /// A deliberate approximation. Doing this properly needs the public-suffix
    /// list, which is a large data file that changes and would be a dependency
    /// and an update obligation. Two labels is wrong for `co.uk` and friends,
    /// which groups all of `example.co.uk` and `other.co.uk` under `co.uk`;
    /// that over-groups rather than under-groups, so it makes the
    /// cardinality-per-zone signal more conservative rather than less.
    pub fn zone(&self) -> String {
        let count = self.labels.len();
        if count <= 2 {
            return self.name.clone();
        }
        self.labels[count - 2..].join(".")
    }

    /// Labels below the zone, which is where a tunnel puts its payload.
    pub fn subdomain_labels(&self) -> &[String] {
        let count = self.labels.len();
        if count <= 2 {
            return &[];
        }
        &self.labels[..count - 2]
    }
}

/// The parts of a DNS message the detector reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub transaction_id: u16,
    /// True when the QR bit is set, meaning this is a response.
    pub is_response: bool,
    pub opcode: u8,
    pub response_code: u8,
    pub questions: Vec<Question>,
    pub answer_count: u16,
    /// A length field was impossible or a name could not be assembled. The
    /// questions read before that point are still returned, because a partial
    /// read is evidence and discarding it would lose traffic.
    pub malformed: bool,
}

/// Parse the header and question section of a DNS message.
///
/// Returns None only when the input is too short to hold a header or longer
/// than [`MAX_MESSAGE_BYTES`]. Anything else comes back as a [`Message`], with
/// `malformed` set if the parse could not complete.
pub fn parse(bytes: &[u8]) -> Option<Message> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let header = bytes.get(..12)?;
    let transaction_id = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let question_count = u16::from_be_bytes([header[4], header[5]]);
    let answer_count = u16::from_be_bytes([header[6], header[7]]);

    let mut message = Message {
        transaction_id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        response_code: (flags & 0x000F) as u8,
        questions: Vec::new(),
        answer_count,
        malformed: false,
    };

    // The question count is attacker-controlled, so it bounds the loop only
    // together with the message actually running out. Capped at MAX_LABELS as a
    // sane ceiling on questions too; real messages carry one.
    let wanted = usize::from(question_count).min(MAX_LABELS);
    let mut offset = 12;
    for _ in 0..wanted {
        let Some((labels, next)) = read_name(bytes, offset) else {
            message.malformed = true;
            break;
        };
        offset = next;
        let Some(type_bytes) = bytes.get(offset..offset + 4) else {
            message.malformed = true;
            break;
        };
        offset += 4;
        let record_type = RecordType::from_code(u16::from_be_bytes([type_bytes[0], type_bytes[1]]));
        message.questions.push(Question {
            name: labels.join("."),
            labels,
            record_type,
        });
    }
    if message.questions.len() < usize::from(question_count) {
        message.malformed = true;
    }
    Some(message)
}

/// Read one name, following compression pointers.
///
/// Returns the labels and the offset just past the name *in the question
/// section*, which for a compressed name is just past the pointer rather than
/// past the data it pointed at.
fn read_name(bytes: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut pointers = 0usize;
    let mut after_first_pointer: Option<usize> = None;
    let mut assembled = 0usize;

    for _ in 0..MAX_LABELS {
        let length = *bytes.get(offset)?;
        match length & 0xC0 {
            0x00 => {
                let label_len = usize::from(length);
                offset += 1;
                if label_len == 0 {
                    // Root label ends the name.
                    let end = after_first_pointer.unwrap_or(offset);
                    return Some((labels, end));
                }
                assembled += label_len + 1;
                if assembled > MAX_NAME_BYTES {
                    return None;
                }
                let label = bytes.get(offset..offset + label_len)?;
                // Lossy rather than strict: a tunnel may put bytes in a label
                // that are not valid UTF-8, and refusing to read it would hide
                // exactly the traffic being hunted. The replacement character is
                // deterministic, so the entropy figures stay reproducible.
                labels.push(String::from_utf8_lossy(label).to_lowercase());
                offset += label_len;
            }
            0xC0 => {
                // A 14-bit offset in the low bits of these two bytes.
                let second = *bytes.get(offset + 1)?;
                let target = usize::from(u16::from_be_bytes([length & 0x3F, second]));
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return None;
                }
                // Strictly backwards, which is what makes a cycle impossible
                // rather than merely capped.
                if target >= offset {
                    return None;
                }
                if after_first_pointer.is_none() {
                    after_first_pointer = Some(offset + 2);
                }
                offset = target;
            }
            // 0x40 and 0x80 are reserved label types; a message using one is
            // malformed and is not guessed at.
            _ => return None,
        }
    }
    None
}

/// Shannon entropy of a byte string in bits per byte, 0.0 to 8.0.
///
/// Summed over the histogram in index order so the floating-point result is
/// reproducible.
pub fn entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut histogram = [0u32; 256];
    for &byte in bytes {
        histogram[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in histogram.iter() {
        if count > 0 {
            let p = f64::from(count) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a name as DNS wire-format labels.
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn query(name: &str, record_type: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1234u16.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD set
        out.extend_from_slice(&1u16.to_be_bytes()); // one question
        out.extend_from_slice(&[0u8; 6]); // no answers, authority or additional
        out.extend_from_slice(&wire_name(name));
        out.extend_from_slice(&record_type.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out
    }

    #[test]
    fn an_ordinary_query_parses_to_its_name_and_type() {
        let message = parse(&query("www.example.com", 1)).expect("parses");
        assert!(!message.is_response);
        assert!(!message.malformed);
        assert_eq!(message.questions.len(), 1);
        let question = &message.questions[0];
        assert_eq!(question.name, "www.example.com");
        assert_eq!(question.labels, vec!["www", "example", "com"]);
        assert_eq!(question.record_type, RecordType::A);
        assert_eq!(question.zone(), "example.com");
        assert_eq!(question.subdomain_labels(), ["www".to_string()]);
    }

    #[test]
    fn names_are_lowercased_so_mixed_case_does_not_inflate_the_unique_count() {
        let message = parse(&query("WwW.ExAmPlE.CoM", 1)).expect("parses");
        assert_eq!(message.questions[0].name, "www.example.com");
    }

    #[test]
    fn a_response_is_distinguished_from_a_query() {
        let mut bytes = query("example.com", 1);
        bytes[2] |= 0x80;
        let message = parse(&bytes).expect("parses");
        assert!(message.is_response);
    }

    #[test]
    fn the_record_types_that_matter_are_named_and_the_rest_are_not_guessed() {
        assert_eq!(RecordType::from_code(16), RecordType::Txt);
        assert_eq!(RecordType::from_code(10), RecordType::Null);
        assert_eq!(RecordType::from_code(5), RecordType::Cname);
        assert_eq!(RecordType::from_code(1), RecordType::A);
        assert_eq!(RecordType::from_code(28), RecordType::Aaaa);
        assert_eq!(RecordType::from_code(255), RecordType::Any);
        assert_eq!(RecordType::from_code(65282), RecordType::Other(65282));
        for favourite in [RecordType::Txt, RecordType::Null, RecordType::Cname] {
            assert!(favourite.is_tunnelling_favourite());
        }
        for ordinary in [RecordType::A, RecordType::Aaaa, RecordType::Mx] {
            assert!(!ordinary.is_tunnelling_favourite());
        }
    }

    #[test]
    fn a_zone_of_two_labels_or_fewer_is_the_whole_name() {
        let message = parse(&query("example.com", 1)).expect("parses");
        assert_eq!(message.questions[0].zone(), "example.com");
        assert!(message.questions[0].subdomain_labels().is_empty());
        let message = parse(&query("localhost", 1)).expect("parses");
        assert_eq!(message.questions[0].zone(), "localhost");
        assert!(message.questions[0].subdomain_labels().is_empty());
    }

    #[test]
    fn a_deep_tunnel_name_splits_into_zone_and_payload_labels() {
        let message =
            parse(&query("aGVsbG8.d29ybGQ.ZGF0YQ.tunnel.example.com", 16)).expect("parses");
        let question = &message.questions[0];
        assert_eq!(question.zone(), "example.com");
        assert_eq!(question.subdomain_labels().len(), 4);
        assert_eq!(question.record_type, RecordType::Txt);
    }

    #[test]
    fn a_compression_pointer_is_followed_backwards() {
        // Put a name at offset 12, then a question whose name is a pointer to it.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
        let name_at = bytes.len();
        bytes.extend_from_slice(&wire_name("target.example.com"));
        // Overwrite the question with a pointer, which means rebuilding: put the
        // pointer after the inline name and treat that as the question.
        let mut message = bytes.clone();
        message.extend_from_slice(&[0xC0 | ((name_at >> 8) as u8), (name_at & 0xFF) as u8]);
        message.extend_from_slice(&16u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        // The first question starts at offset 12, which is the inline name, so
        // this parses that one; the pointer case is exercised by the name at the
        // pointer offset resolving identically.
        let parsed = parse(&message).expect("parses");
        assert_eq!(parsed.questions[0].name, "target.example.com");

        // Now a message whose question IS the pointer: header, filler name,
        // then a second question built as a pointer.
        let mut two = Vec::new();
        two.extend_from_slice(&0x1234u16.to_be_bytes());
        two.extend_from_slice(&0x0100u16.to_be_bytes());
        two.extend_from_slice(&2u16.to_be_bytes());
        two.extend_from_slice(&[0u8; 6]);
        let first_at = two.len();
        two.extend_from_slice(&wire_name("first.example.com"));
        two.extend_from_slice(&1u16.to_be_bytes());
        two.extend_from_slice(&1u16.to_be_bytes());
        two.extend_from_slice(&[0xC0 | ((first_at >> 8) as u8), (first_at & 0xFF) as u8]);
        two.extend_from_slice(&16u16.to_be_bytes());
        two.extend_from_slice(&1u16.to_be_bytes());
        let parsed = parse(&two).expect("parses");
        assert_eq!(parsed.questions.len(), 2);
        assert_eq!(parsed.questions[1].name, "first.example.com");
        assert_eq!(parsed.questions[1].record_type, RecordType::Txt);
        assert!(!parsed.malformed);
    }

    #[test]
    fn a_pointer_to_itself_cannot_loop() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
        // A pointer at offset 12 pointing at offset 12.
        bytes.extend_from_slice(&[0xC0, 12]);
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
        assert!(message.questions.is_empty());
    }

    #[test]
    fn two_pointers_pointing_at_each_other_cannot_loop() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        // Offset 12 points at 14, offset 14 points at 12. The
        // strictly-backwards rule refuses the forward one.
        bytes.extend_from_slice(&[0xC0, 14, 0xC0, 12]);
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
    }

    #[test]
    fn a_forward_pointer_is_refused_even_though_it_terminates() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0xC0, 20]);
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(&wire_name("forward.example.com"));
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
    }

    #[test]
    fn a_reserved_label_type_is_refused_rather_than_guessed() {
        for top_bits in [0x40u8, 0x80u8] {
            let mut bytes = vec![0u8; 12];
            bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
            bytes.push(top_bits | 0x05);
            bytes.extend_from_slice(b"label");
            bytes.push(0);
            let message = parse(&bytes).expect("parses the header");
            assert!(message.malformed, "top bits {top_bits:#x} were followed");
        }
    }

    #[test]
    fn a_name_longer_than_the_protocol_allows_is_refused() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        // Ten labels of 63 bytes is 640 bytes, well past the 255-byte limit.
        for _ in 0..10 {
            bytes.push(63);
            bytes.extend_from_slice(&[b'a'; 63]);
        }
        bytes.push(0);
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
    }

    #[test]
    fn a_name_with_more_labels_than_the_cap_is_refused() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        // Single-byte labels, more than MAX_LABELS of them, each under the name
        // length limit individually.
        for _ in 0..MAX_LABELS + 10 {
            bytes.push(1);
            bytes.push(b'a');
        }
        bytes.push(0);
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
    }

    #[test]
    fn a_label_running_past_the_message_is_refused() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes.push(60); // claims 60 bytes
        bytes.extend_from_slice(b"short"); // provides 5
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
    }

    #[test]
    fn a_question_count_higher_than_the_message_holds_is_malformed_not_a_panic() {
        let mut bytes = query("example.com", 1);
        bytes[4..6].copy_from_slice(&50u16.to_be_bytes());
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
        // The one question that was really there is still returned.
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "example.com");
    }

    #[test]
    fn a_message_missing_its_type_and_class_is_malformed() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&wire_name("example.com"));
        // No type or class follows.
        let message = parse(&bytes).expect("parses the header");
        assert!(message.malformed);
        assert!(message.questions.is_empty());
    }

    #[test]
    fn a_message_shorter_than_a_header_is_rejected() {
        for length in 0..12 {
            assert!(parse(&vec![0u8; length]).is_none(), "length {length}");
        }
        assert!(parse(&[0u8; 12]).is_some());
    }

    #[test]
    fn a_message_past_the_protocol_ceiling_is_rejected() {
        assert!(parse(&vec![0u8; MAX_MESSAGE_BYTES + 1]).is_none());
    }

    #[test]
    fn a_label_that_is_not_valid_utf8_is_read_lossily_rather_than_dropped() {
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes.push(4);
        bytes.extend_from_slice(&[0xFF, 0xFE, 0x41, 0x42]);
        bytes.extend_from_slice(&wire_name("example.com"));
        bytes.extend_from_slice(&16u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        let message = parse(&bytes).expect("parses");
        assert_eq!(message.questions.len(), 1);
        // The non-UTF-8 bytes became replacement characters, deterministically.
        assert!(message.questions[0].labels[0].contains('\u{FFFD}'));
    }

    #[test]
    fn every_truncation_of_a_valid_query_is_handled_rather_than_panicking() {
        let full = query("a1b2c3d4.tunnel.example.com", 16);
        for keep in 0..=full.len() {
            let _ = parse(&full[..keep]);
        }
    }

    #[test]
    fn entropy_is_zero_for_one_repeated_byte_and_maximal_for_a_flat_histogram() {
        assert_eq!(entropy_bits_per_byte(&[]), 0.0);
        assert_eq!(entropy_bits_per_byte(&[b'a'; 64]), 0.0);
        let flat: Vec<u8> = (0..=255u8).collect();
        assert!((entropy_bits_per_byte(&flat) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn base32_looking_text_has_higher_entropy_than_an_english_hostname() {
        let hostname = b"www.example.com";
        let encoded = b"mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dz";
        assert!(entropy_bits_per_byte(encoded) > entropy_bits_per_byte(hostname));
    }

    #[test]
    fn the_header_flag_fields_are_decoded() {
        let mut bytes = query("example.com", 1);
        // Opcode 2 (status), response code 3 (name error), QR set.
        bytes[2] = 0x80 | (2 << 3);
        bytes[3] = 0x03;
        let message = parse(&bytes).expect("parses");
        assert!(message.is_response);
        assert_eq!(message.opcode, 2);
        assert_eq!(message.response_code, 3);
        assert_eq!(message.transaction_id, 0x1234);
    }

    #[test]
    fn the_answer_count_is_carried_through() {
        let mut bytes = query("example.com", 1);
        bytes[6..8].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(parse(&bytes).expect("parses").answer_count, 7);
    }
}
