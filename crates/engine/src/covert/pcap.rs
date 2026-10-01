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

//! Classic PCAP file reading and writing, in pure Rust and under hard caps.
//!
//! # Why this is ours rather than a dependency
//!
//! The obvious crates split two ways. `pcap` and `pnet` bind libpcap or
//! platform capture libraries, which is C on the build path of three OS
//! runners for a feature that never captures anything live. The pure-Rust
//! readers (`pcap-file`, `pcap-parser`) would work, but this module needs its
//! resource caps enforced *during* the parse rather than checked after it, so a
//! third-party iterator would be wrapped in exactly this code anyway.
//!
//! What is left to own is small: a 24-byte file header and a 16-byte record
//! header, in four endianness-and-precision variants. That is the case
//! CLAUDE.md §5 describes, where a few lines of our own beat a dependency.
//! PCAPNG is deliberately not supported; it is a different and much larger
//! format, and a capture can be converted.
//!
//! # Caps
//!
//! A capture file is untrusted input and a hostile one is an expected input,
//! not a crash. Every cap is a documented constant.
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_PACKETS`] | 2000000 | Records read from one capture |
//! | [`MAX_PACKET_BYTES`] | 262144 | Bytes read from any one record, and the largest buffer allocated |
//! | [`MAX_CAPTURE_BYTES`] | 2147483648 | Total bytes read from one capture |
//!
//! A record whose declared length exceeds [`MAX_PACKET_BYTES`] is truncated to
//! it rather than refused, because a capture with one oversized frame is still
//! worth analysing and silently stopping would understate the traffic. Reaching
//! any cap is reported on [`CaptureStats`] rather than hidden.
//!
//! # Determinism
//!
//! The writer takes every timestamp from its caller. Nothing here reads the
//! clock, so a generated capture is byte-identical across runs and machines.

use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::StegError;

/// Maximum records read from one capture.
pub const MAX_PACKETS: usize = 2_000_000;

/// Maximum bytes read from any one record. Also the largest single allocation
/// this module makes, because the reader reuses one buffer of this size.
pub const MAX_PACKET_BYTES: usize = 256 * 1024;

/// Maximum total bytes read from one capture.
pub const MAX_CAPTURE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;

/// Microsecond-precision magic, written little-endian by most tools.
const MAGIC_USEC: u32 = 0xa1b2_c3d4;
/// Nanosecond-precision magic, as `tcpdump` writes with `--time-stamp-precision`.
const MAGIC_NSEC: u32 = 0xa1b2_3c4d;

/// Link-layer type of a capture, limited to the ones whose framing this crate
/// can strip. Anything else is read but its packets are not dissected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    /// `LINKTYPE_NULL` (0): a 4-byte host-endian address family, BSD loopback.
    Null,
    /// `LINKTYPE_ETHERNET` (1): a 14-byte Ethernet II header.
    Ethernet,
    /// `LINKTYPE_RAW` (101): the IP header starts at byte zero.
    Raw,
    /// `LINKTYPE_LINUX_SLL` (113): a 16-byte cooked header, what `-i any` gives.
    LinuxSll,
    /// Something else. Packets are counted but not dissected.
    Other(u32),
}

impl LinkType {
    fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Null,
            1 => Self::Ethernet,
            101 => Self::Raw,
            113 => Self::LinuxSll,
            other => Self::Other(other),
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Ethernet => 1,
            Self::Raw => 101,
            Self::LinuxSll => 113,
            Self::Other(code) => code,
        }
    }

    /// Bytes of link-layer framing before the network header, or None when the
    /// framing is not one this crate strips.
    pub fn header_len(self) -> Option<usize> {
        match self {
            Self::Null => Some(4),
            Self::Ethernet => Some(14),
            Self::Raw => Some(0),
            Self::LinuxSll => Some(16),
            Self::Other(_) => None,
        }
    }
}

/// One record's metadata. The payload is handed out separately so the reader
/// can lend a slice of its own buffer rather than allocate per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// Capture timestamp in nanoseconds since the Unix epoch. Microsecond
    /// captures are scaled up, so one unit here means the same thing whatever
    /// the file's precision was.
    pub timestamp_nanos: u64,
    /// Bytes present in the file for this record, after the per-record cap.
    pub captured_len: usize,
    /// Length the record claimed the original frame had, which is larger than
    /// `captured_len` when the capture was taken with a short snaplen.
    pub original_len: u32,
    /// True when this crate shortened the record to [`MAX_PACKET_BYTES`].
    pub truncated_by_cap: bool,
}

/// What a read of a whole capture encountered, including every cap it reached.
///
/// `malformed` and the `*_cap_reached` flags exist so a caller can tell "this
/// is all the traffic in the file" from "we stopped early", which are different
/// claims and must not render the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets: usize,
    pub bytes: u64,
    /// A record header or body was short, or a length field was impossible.
    pub malformed: bool,
    pub packet_cap_reached: bool,
    pub byte_cap_reached: bool,
    /// Records shortened to [`MAX_PACKET_BYTES`].
    pub oversized_records: usize,
}

/// Streaming reader over a classic PCAP file.
///
/// Reuses one [`MAX_PACKET_BYTES`] buffer, so peak memory does not grow with
/// the capture. A 2 GB capture costs the same as a 2 KB one.
pub struct PcapReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    link_type: LinkType,
    swapped: bool,
    nanosecond: bool,
    snaplen: u32,
    stats: CaptureStats,
    finished: bool,
}

/// Hand-written rather than derived: the inner reader is not `Debug` and the
/// reusable buffer is a quarter of a megabyte that nobody wants printed.
impl<R: Read> std::fmt::Debug for PcapReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapReader")
            .field("link_type", &self.link_type)
            .field("swapped", &self.swapped)
            .field("nanosecond", &self.nanosecond)
            .field("snaplen", &self.snaplen)
            .field("stats", &self.stats)
            .field("finished", &self.finished)
            .finish()
    }
}

impl PcapReader<BufReader<std::fs::File>> {
    /// Open a capture file.
    ///
    /// # Errors
    ///
    /// [`StegError::FileNotFound`] when the path does not exist,
    /// [`StegError::Io`] for any other open failure, and
    /// [`StegError::UnsupportedFormat`] when the file is not a classic PCAP.
    pub fn open(path: &Path) -> Result<Self, StegError> {
        let file = std::fs::File::open(path).map_err(|err| match err.kind() {
            ErrorKind::NotFound => StegError::FileNotFound(path.display().to_string()),
            _ => StegError::Io(err),
        })?;
        Self::new(BufReader::new(file))
    }
}

impl<R: Read> PcapReader<R> {
    /// Read the global header and prepare to stream records.
    ///
    /// # Errors
    ///
    /// [`StegError::UnsupportedFormat`] when the magic is not a classic PCAP
    /// magic (PCAPNG included, which is a different format and says so), or
    /// [`StegError::Io`] on a short or failing read.
    pub fn new(mut inner: R) -> Result<Self, StegError> {
        let mut header = [0u8; GLOBAL_HEADER_LEN];
        read_exact_or_short(&mut inner, &mut header).map_err(StegError::Io)?;

        let raw = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let (swapped, nanosecond) = match raw {
            MAGIC_USEC => (false, false),
            MAGIC_NSEC => (false, true),
            value if value.swap_bytes() == MAGIC_USEC => (true, false),
            value if value.swap_bytes() == MAGIC_NSEC => (true, true),
            // PCAPNG's first block type, worth naming because it is the file a
            // user is most likely to have and the error should say what to do.
            0x0a0d_0d0a => {
                return Err(StegError::UnsupportedFormat(
                    "this is a pcapng capture; convert it to classic pcap first \
                     (for example with `tshark -F pcap`)"
                        .to_string(),
                ))
            }
            _ => {
                return Err(StegError::UnsupportedFormat(
                    "not a pcap capture: the file does not start with a pcap signature".to_string(),
                ))
            }
        };
        let read_u32 = |bytes: &[u8]| -> u32 {
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if swapped {
                value.swap_bytes()
            } else {
                value
            }
        };
        let snaplen = read_u32(&header[16..20]);
        let link_type = LinkType::from_code(read_u32(&header[20..24]));

        Ok(Self {
            inner,
            // Allocated once and reused. Sized to the cap rather than to the
            // file's snaplen, because a hostile file can claim any snaplen and
            // the cap is the only number worth trusting.
            buffer: vec![0u8; MAX_PACKET_BYTES],
            link_type,
            swapped,
            nanosecond,
            snaplen,
            stats: CaptureStats {
                bytes: GLOBAL_HEADER_LEN as u64,
                ..CaptureStats::default()
            },
            finished: false,
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Snaplen the capture's own header declared. Informational: the reader
    /// trusts [`MAX_PACKET_BYTES`] instead.
    pub fn declared_snaplen(&self) -> u32 {
        self.snaplen
    }

    pub fn stats(&self) -> CaptureStats {
        self.stats
    }

    /// Read the next record, or None at the end of the capture or at a cap.
    ///
    /// A malformed record ends the stream and sets [`CaptureStats::malformed`]:
    /// once a length field has lied there is no way to find the next record
    /// boundary, so carrying on would be inventing data.
    ///
    /// # Errors
    ///
    /// [`StegError::Io`] only for a genuine read failure. A truncated file is
    /// data, not an error.
    pub fn next_packet(&mut self) -> Result<Option<(PacketMeta, &[u8])>, StegError> {
        if self.finished {
            return Ok(None);
        }
        if self.stats.packets >= MAX_PACKETS {
            self.stats.packet_cap_reached = true;
            self.finished = true;
            return Ok(None);
        }
        if self.stats.bytes >= MAX_CAPTURE_BYTES {
            self.stats.byte_cap_reached = true;
            self.finished = true;
            return Ok(None);
        }

        let mut header = [0u8; RECORD_HEADER_LEN];
        let got = read_up_to(&mut self.inner, &mut header).map_err(StegError::Io)?;
        if got == 0 {
            self.finished = true;
            return Ok(None);
        }
        if got < RECORD_HEADER_LEN {
            self.stats.malformed = true;
            self.finished = true;
            return Ok(None);
        }
        self.stats.bytes += RECORD_HEADER_LEN as u64;

        let field = |offset: usize| -> u32 {
            let value = u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ]);
            if self.swapped {
                value.swap_bytes()
            } else {
                value
            }
        };
        let seconds = u64::from(field(0));
        let fraction = u64::from(field(4));
        let captured = field(8);
        let original = field(12);

        // A microsecond field above a million, or a nanosecond field above a
        // billion, is a malformed timestamp. Clamped rather than rejected: the
        // packet's contents are still worth reading and the timing signals
        // treat a clamped gap as the outlier it is.
        let nanos_in_second = if self.nanosecond {
            fraction.min(999_999_999)
        } else {
            fraction.min(999_999) * 1000
        };
        let timestamp_nanos = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos_in_second);

        let declared = captured as usize;
        let wanted = declared.min(MAX_PACKET_BYTES);
        if declared > MAX_PACKET_BYTES {
            self.stats.oversized_records += 1;
        }
        let body = &mut self.buffer[..wanted];
        let got = read_up_to(&mut self.inner, body).map_err(StegError::Io)?;
        self.stats.bytes += got as u64;
        if got < wanted {
            // The file ended inside a record. What was read is still real
            // traffic, so it is returned, and the stream ends.
            self.stats.malformed = true;
            self.finished = true;
            if got == 0 {
                return Ok(None);
            }
            self.stats.packets += 1;
            return Ok(Some((
                PacketMeta {
                    timestamp_nanos,
                    captured_len: got,
                    original_len: original,
                    truncated_by_cap: false,
                },
                &self.buffer[..got],
            )));
        }
        // Skip whatever the cap left behind so the next record header is found.
        if declared > wanted {
            let mut remaining = (declared - wanted) as u64;
            while remaining > 0 {
                let chunk = remaining.min(MAX_PACKET_BYTES as u64) as usize;
                let read = read_up_to(&mut self.inner, &mut self.buffer[..chunk])
                    .map_err(StegError::Io)?;
                self.stats.bytes += read as u64;
                if read < chunk {
                    self.stats.malformed = true;
                    self.finished = true;
                    return Ok(None);
                }
                remaining -= read as u64;
            }
            // The buffer now holds skipped bytes rather than the packet, so this
            // record cannot be handed out. Counting it keeps the packet total
            // honest about what the file contained.
            self.stats.packets += 1;
            return Ok(Some((
                PacketMeta {
                    timestamp_nanos,
                    captured_len: 0,
                    original_len: original,
                    truncated_by_cap: true,
                },
                &[],
            )));
        }

        self.stats.packets += 1;
        Ok(Some((
            PacketMeta {
                timestamp_nanos,
                captured_len: wanted,
                original_len: original,
                truncated_by_cap: false,
            },
            &self.buffer[..wanted],
        )))
    }
}

/// Writer for classic PCAP, used to build the detector's test fixtures.
///
/// Every timestamp comes from the caller, so output is reproducible.
pub struct PcapWriter<W: Write> {
    inner: W,
}

impl PcapWriter<BufWriter<std::fs::File>> {
    /// Create a capture file, truncating any existing one.
    ///
    /// # Errors
    ///
    /// [`StegError::Io`] on a create or write failure.
    pub fn create(path: &Path, link_type: LinkType) -> Result<Self, StegError> {
        let file = std::fs::File::create(path).map_err(StegError::Io)?;
        Self::new(BufWriter::new(file), link_type)
    }
}

impl<W: Write> PcapWriter<W> {
    /// Write the global header. Microsecond precision and native endianness,
    /// which is what every tool reads without comment.
    ///
    /// # Errors
    ///
    /// [`StegError::Io`] on a write failure.
    pub fn new(mut inner: W, link_type: LinkType) -> Result<Self, StegError> {
        let mut header = [0u8; GLOBAL_HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC_USEC.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes());
        header[6..8].copy_from_slice(&4u16.to_le_bytes());
        // thiszone and sigfigs are zero, as every modern writer leaves them.
        header[16..20].copy_from_slice(&(MAX_PACKET_BYTES as u32).to_le_bytes());
        header[20..24].copy_from_slice(&link_type.code().to_le_bytes());
        inner.write_all(&header).map_err(StegError::Io)?;
        Ok(Self { inner })
    }

    /// Append one record.
    ///
    /// # Errors
    ///
    /// [`StegError::Io`] on a write failure, or
    /// [`StegError::UnsupportedFormat`] for a frame past [`MAX_PACKET_BYTES`],
    /// which the reader could not hand back whole and so must not be written.
    pub fn write_packet(&mut self, timestamp_nanos: u64, frame: &[u8]) -> Result<(), StegError> {
        if frame.len() > MAX_PACKET_BYTES {
            return Err(StegError::UnsupportedFormat(format!(
                "frame of {} bytes is past the {MAX_PACKET_BYTES} byte record cap",
                frame.len()
            )));
        }
        let mut header = [0u8; RECORD_HEADER_LEN];
        let seconds = (timestamp_nanos / 1_000_000_000) as u32;
        let micros = ((timestamp_nanos % 1_000_000_000) / 1000) as u32;
        header[0..4].copy_from_slice(&seconds.to_le_bytes());
        header[4..8].copy_from_slice(&micros.to_le_bytes());
        header[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        self.inner.write_all(&header).map_err(StegError::Io)?;
        self.inner.write_all(frame).map_err(StegError::Io)?;
        Ok(())
    }

    /// Flush the underlying writer.
    ///
    /// # Errors
    ///
    /// [`StegError::Io`] on a flush failure.
    pub fn finish(mut self) -> Result<(), StegError> {
        self.inner.flush().map_err(StegError::Io)
    }
}

/// Read until the buffer is full or the source ends, retrying on interruption.
/// Returns how much was read, so a short read is data rather than an error.
fn read_up_to<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// Fill the buffer or fail with `UnexpectedEof`, for the one header that must
/// be complete for the file to be a capture at all.
fn read_exact_or_short<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<()> {
    if read_up_to(reader, buffer)? < buffer.len() {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "capture file is shorter than a pcap header",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a capture in memory. Hand-written bytes rather than a fixture
    /// file, so every test states the input it parses.
    fn capture(link: LinkType, packets: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = PcapWriter::new(&mut out, link).expect("header");
        for (timestamp, frame) in packets {
            writer.write_packet(*timestamp, frame).expect("record");
        }
        writer.finish().expect("flush");
        out
    }

    fn read_all(bytes: &[u8]) -> (Vec<(PacketMeta, Vec<u8>)>, CaptureStats, LinkType) {
        let mut reader = PcapReader::new(Cursor::new(bytes.to_vec())).expect("header");
        let link = reader.link_type();
        let mut out = Vec::new();
        while let Some((meta, body)) = reader.next_packet().expect("read") {
            out.push((meta, body.to_vec()));
        }
        (out, reader.stats(), link)
    }

    #[test]
    fn a_capture_round_trips_through_the_writer_and_the_reader() {
        let packets = vec![
            (1_700_000_000_000_000_000u64, vec![1u8, 2, 3, 4]),
            (1_700_000_000_500_000_000u64, vec![9u8; 64]),
        ];
        let bytes = capture(LinkType::Ethernet, &packets);
        let (read, stats, link) = read_all(&bytes);
        assert_eq!(link, LinkType::Ethernet);
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].1, vec![1, 2, 3, 4]);
        assert_eq!(read[1].1, vec![9u8; 64]);
        assert_eq!(read[0].0.timestamp_nanos, 1_700_000_000_000_000_000);
        assert_eq!(read[1].0.timestamp_nanos, 1_700_000_000_500_000_000);
        assert!(!stats.malformed);
        assert_eq!(stats.packets, 2);
    }

    #[test]
    fn the_writer_is_deterministic() {
        let packets = vec![(42_000_000_000u64, vec![7u8; 32])];
        assert_eq!(
            capture(LinkType::Raw, &packets),
            capture(LinkType::Raw, &packets)
        );
    }

    #[test]
    fn a_big_endian_capture_reads_the_same_as_a_little_endian_one() {
        let packets = vec![(1_000_000_000u64, vec![5u8; 20])];
        let little = capture(LinkType::Ethernet, &packets);
        // Byte-swap the four 32-bit fields of the global header and of the one
        // record header, and flip the magic, which is what a capture taken on a
        // big-endian host looks like.
        let mut big = little.clone();
        big[0..4].copy_from_slice(&MAGIC_USEC.swap_bytes().to_le_bytes());
        for offset in [16, 20] {
            let value = u32::from_le_bytes(little[offset..offset + 4].try_into().unwrap());
            big[offset..offset + 4].copy_from_slice(&value.swap_bytes().to_le_bytes());
        }
        // version fields are u16 and not read, so they are left alone.
        for offset in [24, 28, 32, 36] {
            let value = u32::from_le_bytes(little[offset..offset + 4].try_into().unwrap());
            big[offset..offset + 4].copy_from_slice(&value.swap_bytes().to_le_bytes());
        }
        let (read, stats, _) = read_all(&big);
        assert_eq!(read.len(), 1, "stats: {stats:?}");
        assert_eq!(read[0].1, vec![5u8; 20]);
        assert_eq!(read[0].0.timestamp_nanos, 1_000_000_000);
    }

    #[test]
    fn a_nanosecond_capture_keeps_its_precision() {
        let mut bytes = capture(LinkType::Raw, &[(1_000_000_123_000u64, vec![1u8; 8])]);
        bytes[0..4].copy_from_slice(&MAGIC_NSEC.to_le_bytes());
        // Rewrite the fraction field as nanoseconds rather than microseconds.
        bytes[28..32].copy_from_slice(&123_456_789u32.to_le_bytes());
        let (read, _, _) = read_all(&bytes);
        assert_eq!(read[0].0.timestamp_nanos % 1_000_000_000, 123_456_789);
    }

    #[test]
    fn an_out_of_range_timestamp_fraction_is_clamped_rather_than_overflowing() {
        let mut bytes = capture(LinkType::Raw, &[(1_000_000_000u64, vec![1u8; 8])]);
        bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        let (read, _, _) = read_all(&bytes);
        // 999999 microseconds is the largest legal value.
        assert_eq!(read[0].0.timestamp_nanos % 1_000_000_000, 999_999_000);
    }

    #[test]
    fn a_pcapng_file_is_refused_with_advice_rather_than_a_bare_error() {
        let mut bytes = vec![0x0a, 0x0d, 0x0d, 0x0a];
        bytes.extend_from_slice(&[0u8; 32]);
        let err = PcapReader::new(Cursor::new(bytes)).expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("pcapng"), "{message}");
        assert!(message.contains("convert"), "{message}");
    }

    #[test]
    fn a_file_that_is_not_a_capture_is_refused() {
        let err = PcapReader::new(Cursor::new(b"hello there, not a capture".to_vec()))
            .expect_err("must refuse");
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn a_file_shorter_than_the_global_header_is_an_io_error_not_a_panic() {
        let err = PcapReader::new(Cursor::new(vec![0u8; 10])).expect_err("must refuse");
        assert!(matches!(err, StegError::Io(_)));
    }

    #[test]
    fn an_empty_capture_reads_as_no_packets() {
        let bytes = capture(LinkType::Ethernet, &[]);
        let (read, stats, _) = read_all(&bytes);
        assert!(read.is_empty());
        assert_eq!(stats.packets, 0);
        assert!(!stats.malformed);
    }

    #[test]
    fn a_record_header_cut_short_is_malformed_and_stops_the_stream() {
        let mut bytes = capture(LinkType::Raw, &[(1_000_000_000u64, vec![1u8; 16])]);
        bytes.extend_from_slice(&[0u8; 9]); // nine bytes of a sixteen-byte header
        let (read, stats, _) = read_all(&bytes);
        assert_eq!(read.len(), 1);
        assert!(stats.malformed);
    }

    #[test]
    fn a_record_body_cut_short_returns_what_was_there_and_stops() {
        let mut bytes = capture(LinkType::Raw, &[(1_000_000_000u64, vec![1u8; 32])]);
        bytes.truncate(bytes.len() - 10);
        let (read, stats, _) = read_all(&bytes);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1.len(), 22);
        assert!(stats.malformed);
    }

    #[test]
    fn a_record_claiming_more_bytes_than_the_file_holds_does_not_allocate_them() {
        // Declared length just under the cap, body of four bytes. The reader
        // must not try to hold the declared length.
        let mut bytes = capture(LinkType::Raw, &[]);
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[8..12].copy_from_slice(&200_000u32.to_le_bytes());
        header[12..16].copy_from_slice(&200_000u32.to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[0xAB; 4]);
        let (read, stats, _) = read_all(&bytes);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1.len(), 4);
        assert!(stats.malformed);
    }

    #[test]
    fn a_record_past_the_per_packet_cap_is_counted_and_skipped_cleanly() {
        // One oversized record followed by a normal one: the normal one must
        // still be found, which only works if the skip lands exactly.
        let mut bytes = capture(LinkType::Raw, &[]);
        let oversized = MAX_PACKET_BYTES + 100;
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[8..12].copy_from_slice(&(oversized as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(oversized as u32).to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&vec![0xCD; oversized]);
        let mut second = [0u8; RECORD_HEADER_LEN];
        second[0..4].copy_from_slice(&2u32.to_le_bytes());
        second[8..12].copy_from_slice(&8u32.to_le_bytes());
        second[12..16].copy_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&second);
        bytes.extend_from_slice(&[0xEE; 8]);

        let (read, stats, _) = read_all(&bytes);
        assert_eq!(read.len(), 2, "the record after the oversized one was lost");
        assert!(read[0].0.truncated_by_cap);
        assert!(read[0].1.is_empty());
        assert_eq!(read[1].1, vec![0xEE; 8]);
        assert_eq!(stats.oversized_records, 1);
        assert!(!stats.malformed);
    }

    #[test]
    fn the_writer_refuses_a_frame_past_the_record_cap() {
        let mut out = Vec::new();
        let mut writer = PcapWriter::new(&mut out, LinkType::Raw).expect("header");
        let err = writer
            .write_packet(0, &vec![0u8; MAX_PACKET_BYTES + 1])
            .expect_err("must refuse");
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn link_header_lengths_are_what_the_formats_say() {
        assert_eq!(LinkType::Null.header_len(), Some(4));
        assert_eq!(LinkType::Ethernet.header_len(), Some(14));
        assert_eq!(LinkType::Raw.header_len(), Some(0));
        assert_eq!(LinkType::LinuxSll.header_len(), Some(16));
        assert_eq!(LinkType::Other(999).header_len(), None);
    }

    #[test]
    fn link_types_round_trip_through_their_codes() {
        for link in [
            LinkType::Null,
            LinkType::Ethernet,
            LinkType::Raw,
            LinkType::LinuxSll,
            LinkType::Other(276),
        ] {
            assert_eq!(LinkType::from_code(link.code()), link);
        }
    }

    #[test]
    fn an_unknown_link_type_survives_the_round_trip_and_reads_its_packets() {
        let bytes = capture(LinkType::Other(276), &[(1_000_000_000, vec![3u8; 10])]);
        let (read, _, link) = read_all(&bytes);
        assert_eq!(link, LinkType::Other(276));
        assert_eq!(read.len(), 1);
    }

    #[test]
    fn the_declared_snaplen_is_reported_but_not_trusted_for_sizing() {
        let mut bytes = capture(LinkType::Raw, &[(1_000_000_000, vec![1u8; 8])]);
        // A hostile snaplen far past the cap must not cause an allocation.
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut reader = PcapReader::new(Cursor::new(bytes)).expect("header");
        assert_eq!(reader.declared_snaplen(), u32::MAX);
        assert!(reader.next_packet().expect("read").is_some());
    }

    #[test]
    fn a_read_failure_is_surfaced_rather_than_read_as_end_of_file() {
        struct Failing {
            header_sent: usize,
        }
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.header_sent < GLOBAL_HEADER_LEN {
                    let mut header = [0u8; GLOBAL_HEADER_LEN];
                    header[0..4].copy_from_slice(&MAGIC_USEC.to_le_bytes());
                    header[20..24].copy_from_slice(&1u32.to_le_bytes());
                    let take = buf.len().min(GLOBAL_HEADER_LEN - self.header_sent);
                    buf[..take].copy_from_slice(&header[self.header_sent..self.header_sent + take]);
                    self.header_sent += take;
                    return Ok(take);
                }
                Err(io::Error::other("the capture device fell over"))
            }
        }
        let mut reader = PcapReader::new(Failing { header_sent: 0 }).expect("header");
        let err = reader.next_packet().expect_err("must surface");
        assert!(err.to_string().contains("fell over"));
    }

    #[test]
    fn the_packet_cap_stops_the_stream_and_says_so() {
        // Drive the cap directly rather than writing two million records.
        let bytes = capture(LinkType::Raw, &[(1, vec![1u8; 4]), (2, vec![2u8; 4])]);
        let mut reader = PcapReader::new(Cursor::new(bytes)).expect("header");
        reader.stats.packets = MAX_PACKETS;
        assert!(reader.next_packet().expect("read").is_none());
        assert!(reader.stats().packet_cap_reached);
    }

    #[test]
    fn the_byte_cap_stops_the_stream_and_says_so() {
        let bytes = capture(LinkType::Raw, &[(1, vec![1u8; 4])]);
        let mut reader = PcapReader::new(Cursor::new(bytes)).expect("header");
        reader.stats.bytes = MAX_CAPTURE_BYTES;
        assert!(reader.next_packet().expect("read").is_none());
        assert!(reader.stats().byte_cap_reached);
    }

    #[test]
    fn opening_a_missing_capture_is_a_loud_file_not_found() {
        let err = PcapReader::open(Path::new("/nonexistent/stegcore/capture.pcap"))
            .expect_err("must fail");
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn a_capture_written_to_disk_reads_back_identically() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("fixture.pcap");
        let mut writer = PcapWriter::create(&path, LinkType::Ethernet).expect("create");
        writer
            .write_packet(1_000_000_000, &[1, 2, 3])
            .expect("write");
        writer
            .write_packet(2_000_000_000, &[4, 5, 6])
            .expect("write");
        writer.finish().expect("flush");

        let mut reader = PcapReader::open(&path).expect("open");
        let mut bodies = Vec::new();
        while let Some((_, body)) = reader.next_packet().expect("read") {
            bodies.push(body.to_vec());
        }
        assert_eq!(bodies, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }
}
