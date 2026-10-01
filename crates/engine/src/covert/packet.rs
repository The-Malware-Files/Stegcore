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

//! Enough packet dissection to reach a DNS message or an ICMP echo body.
//!
//! Deliberately shallow. This is not a protocol stack: it strips link, network
//! and transport framing to find the payload the detector cares about, and
//! declines anything it does not recognise rather than guessing. Nothing here
//! reassembles IP fragments or TCP streams, both of which are stated
//! limitations rather than oversights (see [`Dissection::Unhandled`]).
//!
//! Every length comes out of the packet, so every length is untrusted. Each is
//! bounds-checked against the slice actually in hand rather than against what
//! the header claims, and the module indexes nothing it has not first checked.
//!
//! # Caps
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_IP_OPTION_BYTES`] | 40 | IPv4 options walked past, the format's own maximum |
//! | [`MAX_EXTENSION_HEADERS`] | 8 | IPv6 extension headers followed before giving up |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::pcap::LinkType;

/// Largest IPv4 option area, which the 4-bit header-length field caps at 60
/// bytes total minus the 20-byte fixed header.
pub const MAX_IP_OPTION_BYTES: usize = 40;

/// IPv6 extension headers followed before the chain is treated as hostile. A
/// legitimate packet has at most two or three; an unbounded chain is an attack
/// on the parser.
pub const MAX_EXTENSION_HEADERS: usize = 8;

/// Transport protocol numbers this module recognises.
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// IPv6 extension header numbers that carry a `(next, len)` pair in the shape
/// the walker below understands.
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_DEST_OPTIONS: u8 = 60;

/// What a packet turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dissection<'a> {
    /// A UDP datagram, with the ports and the payload.
    Udp {
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        payload: &'a [u8],
    },
    /// An ICMP or ICMPv6 message, with its type, code and body after the
    /// 8-byte header. `identifier` and `sequence` are only meaningful for echo
    /// request and reply, where the detector uses them.
    Icmp {
        source: IpAddr,
        destination: IpAddr,
        message_type: u8,
        code: u8,
        identifier: u16,
        sequence: u16,
        body: &'a [u8],
    },
    /// A TCP segment. The payload is whatever this one segment carried, with no
    /// stream reassembly, so a DNS message split across segments is not seen.
    /// Recorded rather than silently dropped because the timing signals use TCP
    /// arrival times and do not need the payload.
    Tcp {
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        payload: &'a [u8],
    },
    /// Recognised as IP but not a transport this module handles, or an IP
    /// fragment that is not the first fragment.
    Unhandled { reason: UnhandledReason },
}

/// Why a packet produced no transport payload. Carried rather than collapsed to
/// a single "skipped" count, because a capture that is mostly truncated frames
/// and a capture that is mostly IP fragments are different situations and a
/// defender should be able to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnhandledReason {
    /// The capture's link type is not one this module strips.
    UnknownLinkType,
    /// The frame ended before a complete header could be read.
    Truncated,
    /// Not IPv4 or IPv6.
    NotIp,
    /// A non-initial IP fragment, so the transport header is not present. No
    /// reassembly is attempted.
    NonInitialFragment,
    /// IPv6 extension header chain longer than [`MAX_EXTENSION_HEADERS`].
    ExtensionChainTooLong,
    /// A transport protocol this module does not dissect.
    OtherProtocol(u8),
}

/// Dissect one captured frame.
///
/// Returns [`Dissection::Unhandled`] rather than an error for anything it
/// cannot read: a capture is a mixed bag by nature and one odd frame is not a
/// failure of the analysis.
pub fn dissect(link: LinkType, frame: &[u8]) -> Dissection<'_> {
    let Some(link_len) = link.header_len() else {
        return unhandled(UnhandledReason::UnknownLinkType);
    };
    let Some(rest) = frame.get(link_len..) else {
        return unhandled(UnhandledReason::Truncated);
    };

    // Ethernet and Linux SLL both name the network protocol in a 2-byte field;
    // for the others the IP version nibble is the only evidence, which is what
    // `RAW` means.
    let ethertype = match link {
        LinkType::Ethernet => frame.get(12..14).map(|b| u16::from_be_bytes([b[0], b[1]])),
        // SLL's protocol field is the last two bytes of its 16-byte header.
        LinkType::LinuxSll => frame.get(14..16).map(|b| u16::from_be_bytes([b[0], b[1]])),
        _ => None,
    };
    match ethertype {
        Some(0x0800) => dissect_ipv4(rest),
        Some(0x86DD) => dissect_ipv6(rest),
        Some(_) => unhandled(UnhandledReason::NotIp),
        None => match rest.first().map(|first| first >> 4) {
            Some(4) => dissect_ipv4(rest),
            Some(6) => dissect_ipv6(rest),
            Some(_) => unhandled(UnhandledReason::NotIp),
            None => unhandled(UnhandledReason::Truncated),
        },
    }
}

fn unhandled(reason: UnhandledReason) -> Dissection<'static> {
    Dissection::Unhandled { reason }
}

fn dissect_ipv4(bytes: &[u8]) -> Dissection<'_> {
    // The fixed header is 20 bytes; anything shorter cannot be read.
    let Some(header) = bytes.get(..20) else {
        return unhandled(UnhandledReason::Truncated);
    };
    let header_len = usize::from(header[0] & 0x0F) * 4;
    // A header length below the fixed 20, or an option area past the format's
    // own maximum, is a malformed packet rather than something to follow.
    if !(20..=20 + MAX_IP_OPTION_BYTES).contains(&header_len) {
        return unhandled(UnhandledReason::Truncated);
    }
    let protocol = header[9];
    let source = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));

    // Fragment offset is the low 13 bits of the flags-and-offset field. A
    // non-zero offset means the transport header is in an earlier fragment.
    let flags_and_offset = u16::from_be_bytes([header[6], header[7]]);
    if flags_and_offset & 0x1FFF != 0 {
        return unhandled(UnhandledReason::NonInitialFragment);
    }

    // The total-length field is trusted only as an upper bound: a capture taken
    // with a short snaplen has fewer bytes than the field claims, and offload
    // can make the field smaller than the frame.
    let declared_total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let available = bytes.len();
    let end = if declared_total >= header_len && declared_total <= available {
        declared_total
    } else {
        available
    };
    let Some(payload) = bytes.get(header_len..end) else {
        return unhandled(UnhandledReason::Truncated);
    };
    dissect_transport(protocol, source, destination, payload)
}

fn dissect_ipv6(bytes: &[u8]) -> Dissection<'_> {
    let Some(header) = bytes.get(..40) else {
        return unhandled(UnhandledReason::Truncated);
    };
    let mut source_octets = [0u8; 16];
    let mut destination_octets = [0u8; 16];
    source_octets.copy_from_slice(&header[8..24]);
    destination_octets.copy_from_slice(&header[24..40]);
    let source = IpAddr::V6(Ipv6Addr::from(source_octets));
    let destination = IpAddr::V6(Ipv6Addr::from(destination_octets));

    let declared_payload = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let available = bytes.len() - 40;
    let end = 40 + declared_payload.min(available);
    let mut next_header = header[6];
    let mut offset = 40;

    // Walk the extension-header chain. Bounded, because the chain is
    // attacker-controlled and a loop here is the parser's own denial of service.
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next_header {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTIONS => {
                let Some(ext) = bytes.get(offset..offset + 2) else {
                    return unhandled(UnhandledReason::Truncated);
                };
                // Length is in 8-byte units, not counting the first 8 bytes.
                let ext_len = (usize::from(ext[1]) + 1) * 8;
                next_header = ext[0];
                offset += ext_len;
                if offset > end {
                    return unhandled(UnhandledReason::Truncated);
                }
            }
            // The fragment header is 8 bytes and its offset field says whether
            // the transport header is here at all.
            44 => {
                let Some(ext) = bytes.get(offset..offset + 8) else {
                    return unhandled(UnhandledReason::Truncated);
                };
                let fragment_offset = u16::from_be_bytes([ext[2], ext[3]]) >> 3;
                if fragment_offset != 0 {
                    return unhandled(UnhandledReason::NonInitialFragment);
                }
                next_header = ext[0];
                offset += 8;
                if offset > end {
                    return unhandled(UnhandledReason::Truncated);
                }
            }
            protocol => {
                let Some(payload) = bytes.get(offset..end) else {
                    return unhandled(UnhandledReason::Truncated);
                };
                return dissect_transport(protocol, source, destination, payload);
            }
        }
    }
    unhandled(UnhandledReason::ExtensionChainTooLong)
}

fn dissect_transport(
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    payload: &[u8],
) -> Dissection<'_> {
    match protocol {
        PROTO_UDP => {
            let Some(header) = payload.get(..8) else {
                return unhandled(UnhandledReason::Truncated);
            };
            let declared = usize::from(u16::from_be_bytes([header[4], header[5]]));
            let available = payload.len();
            // The UDP length field counts its own 8-byte header. Below 8 it is
            // malformed; above what is present the capture was snapped short.
            let end = if declared >= 8 && declared <= available {
                declared
            } else {
                available
            };
            let Some(body) = payload.get(8..end) else {
                return unhandled(UnhandledReason::Truncated);
            };
            Dissection::Udp {
                source,
                destination,
                source_port: u16::from_be_bytes([header[0], header[1]]),
                destination_port: u16::from_be_bytes([header[2], header[3]]),
                payload: body,
            }
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let Some(header) = payload.get(..8) else {
                return unhandled(UnhandledReason::Truncated);
            };
            let Some(body) = payload.get(8..) else {
                return unhandled(UnhandledReason::Truncated);
            };
            Dissection::Icmp {
                source,
                destination,
                message_type: header[0],
                code: header[1],
                // Bytes 4 to 8 are the identifier and sequence for echo
                // messages and mean other things for other types; the caller
                // checks the type before using them.
                identifier: u16::from_be_bytes([header[4], header[5]]),
                sequence: u16::from_be_bytes([header[6], header[7]]),
                body,
            }
        }
        PROTO_TCP => {
            let Some(header) = payload.get(..20) else {
                return unhandled(UnhandledReason::Truncated);
            };
            let data_offset = usize::from(header[12] >> 4) * 4;
            if data_offset < 20 {
                return unhandled(UnhandledReason::Truncated);
            }
            let body = payload.get(data_offset..).unwrap_or(&[]);
            Dissection::Tcp {
                source,
                destination,
                source_port: u16::from_be_bytes([header[0], header[1]]),
                destination_port: u16::from_be_bytes([header[2], header[3]]),
                payload: body,
            }
        }
        other => unhandled(UnhandledReason::OtherProtocol(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Ethernet + IPv4 frame around a transport payload. Hand-built so
    /// each test names the bytes it parses.
    fn ipv4_frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let total = 20 + transport.len();
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        header[8] = 64;
        header[9] = protocol;
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(transport);
        frame
    }

    fn udp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&source_port.to_be_bytes());
        out.extend_from_slice(&destination_port.to_be_bytes());
        out.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn icmp_echo(message_type: u8, identifier: u16, sequence: u16, body: &[u8]) -> Vec<u8> {
        let mut out = vec![message_type, 0, 0, 0];
        out.extend_from_slice(&identifier.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_udp_datagram_is_dissected_to_its_payload() {
        let frame = ipv4_frame(PROTO_UDP, &udp(5353, 53, b"query bytes"));
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Udp {
                source_port,
                destination_port,
                payload,
                source,
                destination,
            } => {
                assert_eq!(source_port, 5353);
                assert_eq!(destination_port, 53);
                assert_eq!(payload, b"query bytes");
                assert_eq!(source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
            }
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn an_icmp_echo_is_dissected_to_its_body_with_identifier_and_sequence() {
        let frame = ipv4_frame(PROTO_ICMP, &icmp_echo(8, 0x1234, 7, b"ping body"));
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Icmp {
                message_type,
                identifier,
                sequence,
                body,
                ..
            } => {
                assert_eq!(message_type, 8);
                assert_eq!(identifier, 0x1234);
                assert_eq!(sequence, 7);
                assert_eq!(body, b"ping body");
            }
            other => panic!("expected ICMP, got {other:?}"),
        }
    }

    #[test]
    fn a_tcp_segment_is_dissected_past_its_options() {
        let mut tcp = vec![0u8; 24];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&44300u16.to_be_bytes());
        // Data offset of 6 words: 20 fixed bytes plus 4 bytes of options.
        tcp[12] = 6 << 4;
        tcp.extend_from_slice(b"body");
        let frame = ipv4_frame(PROTO_TCP, &tcp);
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Tcp {
                source_port,
                payload,
                ..
            } => {
                assert_eq!(source_port, 443);
                assert_eq!(payload, b"body");
            }
            other => panic!("expected TCP, got {other:?}"),
        }
    }

    #[test]
    fn raw_and_null_and_sll_link_types_all_reach_the_same_payload() {
        let transport = udp(1000, 53, b"same");
        let mut ip = ipv4_frame(PROTO_UDP, &transport);
        ip.drain(..14); // strip the Ethernet header

        let raw = dissect(LinkType::Raw, &ip);
        let mut null_frame = vec![2u8, 0, 0, 0];
        null_frame.extend_from_slice(&ip);
        let null = dissect(LinkType::Null, &null_frame);
        let mut sll_frame = vec![0u8; 16];
        sll_frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        sll_frame.extend_from_slice(&ip);
        let sll = dissect(LinkType::LinuxSll, &sll_frame);

        for result in [raw, null, sll] {
            match result {
                Dissection::Udp { payload, .. } => assert_eq!(payload, b"same"),
                other => panic!("expected UDP, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_ipv6_udp_datagram_is_dissected() {
        let transport = udp(40000, 53, b"v6 query");
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        let mut header = vec![0u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        header[6] = PROTO_UDP;
        header[8] = 0x20;
        header[24] = 0x20;
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&transport);
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Udp {
                payload, source, ..
            } => {
                assert_eq!(payload, b"v6 query");
                assert!(matches!(source, IpAddr::V6(_)));
            }
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn an_ipv6_extension_header_is_walked_past() {
        let transport = udp(40000, 53, b"after ext");
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        // One 8-byte destination-options header before the UDP header.
        let mut extension = vec![PROTO_UDP, 0];
        extension.extend_from_slice(&[0u8; 6]);
        let mut header = vec![0u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&((extension.len() + transport.len()) as u16).to_be_bytes());
        header[6] = EXT_DEST_OPTIONS;
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&extension);
        frame.extend_from_slice(&transport);
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Udp { payload, .. } => assert_eq!(payload, b"after ext"),
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn an_unbounded_ipv6_extension_chain_is_refused_rather_than_followed() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        // A chain of destination-options headers each pointing at another one,
        // far longer than the cap.
        let count = MAX_EXTENSION_HEADERS + 4;
        let mut chain = Vec::new();
        for _ in 0..count {
            chain.push(EXT_DEST_OPTIONS);
            chain.push(0);
            chain.extend_from_slice(&[0u8; 6]);
        }
        let mut header = vec![0u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(chain.len() as u16).to_be_bytes());
        header[6] = EXT_DEST_OPTIONS;
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&chain);
        assert_eq!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled {
                reason: UnhandledReason::ExtensionChainTooLong
            }
        );
    }

    #[test]
    fn a_non_initial_ipv4_fragment_is_reported_rather_than_misparsed() {
        let mut frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"fragment"));
        // Fragment offset of 1 (eight bytes in), inside the IP header at 14+6.
        frame[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled {
                reason: UnhandledReason::NonInitialFragment
            }
        );
    }

    #[test]
    fn a_non_initial_ipv6_fragment_is_reported() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        let mut fragment = vec![PROTO_UDP, 0];
        // Fragment offset of 1 lives in the top 13 bits of bytes 2 and 3.
        fragment.extend_from_slice(&(1u16 << 3).to_be_bytes());
        fragment.extend_from_slice(&[0u8; 4]);
        let mut header = vec![0u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(fragment.len() as u16).to_be_bytes());
        header[6] = 44;
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&fragment);
        assert_eq!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled {
                reason: UnhandledReason::NonInitialFragment
            }
        );
    }

    #[test]
    fn an_ipv4_header_length_below_the_fixed_minimum_is_refused() {
        let mut frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"x"));
        frame[14] = 0x43; // version 4, header length 3 words (12 bytes)
        assert!(matches!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled { .. }
        ));
    }

    #[test]
    fn an_ipv4_option_area_past_the_formats_maximum_is_refused() {
        let mut frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"x"));
        frame[14] = 0x4F; // 15 words = 60 bytes, the legal maximum
                          // Legal, so it must not be refused for the length alone; it fails later
                          // for want of bytes, which is the honest reason.
        assert!(matches!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled { .. }
        ));
    }

    #[test]
    fn a_declared_length_longer_than_the_capture_falls_back_to_what_is_present() {
        // A short snaplen is ordinary, so an IP total-length past the frame must
        // not lose the payload that is there.
        let mut frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"present"));
        frame[14 + 2..14 + 4].copy_from_slice(&9000u16.to_be_bytes());
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Udp { payload, .. } => assert_eq!(payload, b"present"),
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn a_udp_length_field_below_its_own_header_falls_back_safely() {
        let mut frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"body here"));
        let udp_at = 14 + 20;
        frame[udp_at + 4..udp_at + 6].copy_from_slice(&3u16.to_be_bytes());
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Udp { payload, .. } => assert_eq!(payload, b"body here"),
            other => panic!("expected UDP, got {other:?}"),
        }
    }

    #[test]
    fn a_tcp_data_offset_below_the_fixed_header_is_refused() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 2 << 4; // 8 bytes, below the 20-byte minimum
        let frame = ipv4_frame(PROTO_TCP, &tcp);
        assert!(matches!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled { .. }
        ));
    }

    #[test]
    fn a_tcp_data_offset_past_the_segment_yields_an_empty_payload_not_a_panic() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 15 << 4; // 60 bytes of header in a 20-byte segment
        let frame = ipv4_frame(PROTO_TCP, &tcp);
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Tcp { payload, .. } => assert!(payload.is_empty()),
            other => panic!("expected TCP, got {other:?}"),
        }
    }

    #[test]
    fn every_truncation_point_is_handled_rather_than_indexed() {
        // Cut a valid frame at every length and require no panic at any of them.
        let frame = ipv4_frame(PROTO_UDP, &udp(1000, 53, b"a reasonable query payload"));
        for keep in 0..=frame.len() {
            let _ = dissect(LinkType::Ethernet, &frame[..keep]);
            let _ = dissect(LinkType::Raw, &frame[..keep]);
            let _ = dissect(LinkType::LinuxSll, &frame[..keep]);
            let _ = dissect(LinkType::Null, &frame[..keep]);
        }
    }

    #[test]
    fn a_non_ip_ethertype_is_reported_as_not_ip() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
        frame.extend_from_slice(&[0u8; 28]);
        assert_eq!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled {
                reason: UnhandledReason::NotIp
            }
        );
    }

    #[test]
    fn an_unknown_link_type_is_reported_rather_than_guessed() {
        assert_eq!(
            dissect(LinkType::Other(276), &[0u8; 64]),
            Dissection::Unhandled {
                reason: UnhandledReason::UnknownLinkType
            }
        );
    }

    #[test]
    fn an_unhandled_transport_names_its_protocol_number() {
        // 132 is SCTP, which this module does not dissect.
        let frame = ipv4_frame(132, &[0u8; 20]);
        assert_eq!(
            dissect(LinkType::Ethernet, &frame),
            Dissection::Unhandled {
                reason: UnhandledReason::OtherProtocol(132)
            }
        );
    }

    #[test]
    fn a_raw_link_type_with_a_nonsense_version_nibble_is_not_ip() {
        assert_eq!(
            dissect(LinkType::Raw, &[0x90, 0, 0, 0]),
            Dissection::Unhandled {
                reason: UnhandledReason::NotIp
            }
        );
    }

    #[test]
    fn an_empty_frame_is_truncated_rather_than_a_panic() {
        assert_eq!(
            dissect(LinkType::Raw, &[]),
            Dissection::Unhandled {
                reason: UnhandledReason::Truncated
            }
        );
        assert_eq!(
            dissect(LinkType::Ethernet, &[]),
            Dissection::Unhandled {
                reason: UnhandledReason::Truncated
            }
        );
    }

    #[test]
    fn icmpv6_is_dissected_the_same_way_as_icmp() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        let message = icmp_echo(128, 9, 1, b"v6 ping");
        let mut header = vec![0u8; 40];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(message.len() as u16).to_be_bytes());
        header[6] = PROTO_ICMPV6;
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&message);
        match dissect(LinkType::Ethernet, &frame) {
            Dissection::Icmp {
                message_type, body, ..
            } => {
                assert_eq!(message_type, 128);
                assert_eq!(body, b"v6 ping");
            }
            other => panic!("expected ICMP, got {other:?}"),
        }
    }
}
