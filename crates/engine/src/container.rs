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

//! Container metadata scanner: the slots a file carries beside its pixels.
//!
//! # Why this module exists
//!
//! `analyse_image` decodes a file to RGB8 and runs spatial LSB detectors over
//! the pixels. Anything hidden in the *container* rather than in the pixels is
//! therefore invisible to it, and "invisible" here is literal rather than
//! "weak". Measured on 40 matched cover/stego pairs per placement, every pair
//! verified pixel-identical:
//!
//! | Placement | Detected by the spatial ensemble |
//! |---|---|
//! | Appended after JPEG EOI | 100% (an existing fingerprint catches it) |
//! | JPEG COM segment (`FF FE`) | 0% |
//! | JPEG APP1 / EXIF | 0% |
//! | PNG `tEXt` chunk | 0% |
//!
//! The maximum absolute change across all five detector scores over all 160
//! pairs was exactly `0.00e+00`. The information never reaches the ensemble, so
//! no recalibration can recover it; only a parser can. That is this module.
//!
//! # What it does and does not decide
//!
//! It reports **measurements**, never a verdict. Each region it finds carries
//! its Shannon entropy, its LZ4 compression ratio and its printable-ASCII
//! ratio, and says nothing about whether those numbers are alarming. Choosing
//! the numbers at which a region becomes suspicious is a separate calibration
//! step against real corpora at a documented false-positive ceiling, exactly as
//! the detector thresholds were (CLAUDE.md A3 forbids guessed thresholds, and a
//! container threshold guessed here would be the same mistake in a new place).
//! An EXIF block of camera settings looks nothing like ciphertext, and the
//! point of the three measures is that they say so quantitatively; the point of
//! not thresholding them here is that *how much* unlike is an empirical
//! question this module has no evidence for.
//!
//! # Resource caps
//!
//! Every cap is a hard constant with a number, per baseline §2.1. A malformed
//! file with a hundred thousand tiny APP segments must not hang or allocate
//! without bound, and neither must a 2 GB file.
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_STRUCTURE_STEPS`] | 100000 | Segments or chunks walked before the walk stops |
//! | [`MAX_REGIONS`] | 4096 | Findings returned, so output cannot grow with a hostile file |
//! | [`MAX_REGION_BYTES`] | 65536 | Bytes read from any one region, which is also the largest single allocation |
//! | [`MAX_SCAN_BYTES`] | 268435456 | Total bytes this module will read from a file |
//! | [`MAX_FILL_BYTES`] | 64 | Consecutive `FF` fill bytes tolerated before a JPEG marker |
//! | [`MIN_REGION_BYTES`] | 16 | Reporting floor: shorter regions are not reported |
//!
//! [`MIN_REGION_BYTES`] is a reporting floor rather than a detection threshold.
//! Sixteen bytes is below any plausible encrypted payload (an AEAD nonce and
//! tag alone exceed it) and entropy estimated from fewer than sixteen samples
//! is bounded by `log2(n)` rather than by the data, so a shorter region would
//! contribute a number that means nothing while still costing a row of output.
//!
//! # Streaming
//!
//! Nothing reads the whole file. The walk seeks from segment header to segment
//! header and reads at most [`MAX_REGION_BYTES`] of each region's body, so peak
//! memory is one 64 KiB buffer regardless of file size. The entry point is
//! generic over `Read + Seek` so a 2 GB file costs two orders of magnitude less
//! memory than `std::fs::read` would, and so the tests can drive the walker
//! from an in-memory `Cursor` with no fixture files on disk.
//!
//! # Determinism
//!
//! Findings come back sorted by byte offset, which is unique per region, so
//! identical input gives byte-identical output. The entropy histogram is summed
//! in index order rather than in hash order for the same reason.

use std::fs::File;
use std::io::{self, BufReader, Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::StegError;

// ── Resource caps ─────────────────────────────────────────────────────────────

/// Maximum segments (JPEG) or chunks (PNG) walked before the walk gives up.
/// Matches the existing structure-walk cap in `analysis.rs` so the two agree.
pub const MAX_STRUCTURE_STEPS: usize = 100_000;

/// Maximum findings returned from one scan. A file engineered to carry a
/// million empty APP segments produces at most this many rows.
pub const MAX_REGIONS: usize = 4096;

/// Maximum bytes read from any single region, and so the largest buffer this
/// module ever allocates. 64 KiB is above the 64 KiB-minus-2 ceiling a JPEG
/// segment length field can express, so for JPEG it is never the binding
/// constraint; it binds on PNG chunks and on trailing data, where a declared
/// length can be arbitrary.
pub const MAX_REGION_BYTES: u64 = 64 * 1024;

/// Total bytes read from a file across one scan, including the bytes skipped
/// through while hunting the marker that ends a JPEG entropy-coded scan.
/// Reaching it sets [`ContainerScan::limits_hit`] rather than failing.
pub const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Consecutive `0xFF` fill bytes tolerated between a JPEG segment and the next
/// marker. The standard permits padding; an unbounded run is a malformed file.
pub const MAX_FILL_BYTES: usize = 64;

/// Reporting floor in bytes. See the module-level note: this bounds output
/// noise and keeps entropy estimable, and is not a detection threshold.
pub const MIN_REGION_BYTES: usize = 16;

// ── Finding types ─────────────────────────────────────────────────────────────

/// Which PNG text chunk a finding sits in. The three differ in encoding, not
/// in how usefully they hide bytes: `zTXt` is zlib-compressed and `iTXt` may
/// be, so a payload hidden in either is measured post-container but
/// pre-decompression, which is noted on the finding's entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PngTextKind {
    /// `tEXt`: Latin-1 keyword and value, uncompressed.
    Text,
    /// `zTXt`: Latin-1 keyword, zlib-compressed value.
    CompressedText,
    /// `iTXt`: UTF-8 keyword and value, optionally zlib-compressed.
    InternationalText,
}

/// The container slot a finding was located in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot", rename_all = "snake_case")]
pub enum ContainerSlot {
    /// JPEG comment segment, marker `FF FE`. Arbitrary bytes, no structure the
    /// standard constrains, which is why it is the textbook hiding place.
    JpegComment,
    /// JPEG application segment, marker `FF E0` through `FF EF`. `n` is the
    /// marker's low nibble, so APP1 (where EXIF lives) is `n == 1`.
    JpegApp { n: u8 },
    /// PNG text chunk.
    PngText { kind: PngTextKind },
    /// A PNG ancillary chunk whose type this scanner does not recognise. The
    /// ancillary bit is the lowercase first letter, so a decoder is required to
    /// ignore these, which makes an invented chunk type a durable hiding place.
    PngUnknownAncillary { chunk_type: String },
    /// Bytes past the format's logical end: after the JPEG `FF D9` EOI marker,
    /// or after the PNG `IEND` chunk's CRC. Found by parsing to the end rather
    /// than by searching backwards for the marker, because appended payload
    /// bytes can contain the marker and would spoof a reverse search.
    Trailing,
}

impl ContainerSlot {
    /// Plain-language name for user-facing output. British English, no jargon
    /// a reader would have to look up, per the documentation philosophy.
    pub fn label(&self) -> String {
        match self {
            Self::JpegComment => "JPEG comment segment".to_string(),
            Self::JpegApp { n } => format!("JPEG APP{n} segment"),
            Self::PngText { kind } => {
                let name = match kind {
                    PngTextKind::Text => "tEXt",
                    PngTextKind::CompressedText => "zTXt",
                    PngTextKind::InternationalText => "iTXt",
                };
                format!("PNG {name} chunk")
            }
            Self::PngUnknownAncillary { chunk_type } => {
                format!("PNG unrecognised chunk ({chunk_type})")
            }
            Self::Trailing => "data after the end of the file's image data".to_string(),
        }
    }
}

/// One suspicious-*shaped* region of container metadata, with the measurements
/// that describe how unlike ordinary metadata its contents are.
///
/// No field is a verdict. `entropy_bits_per_byte` near 8.0 with
/// `compressed_ratio` near 1.0 and `printable_ratio` near 0.0 is what
/// ciphertext looks like, and the same three numbers on a thumbnail JPEG inside
/// an EXIF block look similar, which is precisely why the threshold is a
/// calibration question and not a constant in this file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerFinding {
    /// Where in the container's structure the region sits.
    #[serde(flatten)]
    pub slot: ContainerSlot,
    /// Byte offset of the region's first content byte within the file.
    pub offset: u64,
    /// Content bytes actually present in the file, which is the declared length
    /// clamped to what the file holds.
    pub length: u64,
    /// Length the container's own header claimed. Differs from `length` only
    /// when the file is truncated.
    pub declared_length: u64,
    /// Bytes actually read and measured, capped at [`MAX_REGION_BYTES`]. Every
    /// measure below describes this prefix, not the whole region.
    pub examined: u64,
    /// Shannon entropy of the examined bytes in bits per byte, 0.0 to 8.0.
    /// Order-insensitive: it sees the byte histogram and not the arrangement.
    pub entropy_bits_per_byte: f64,
    /// LZ4 compressed size divided by examined size. Complements entropy by
    /// seeing repetition, which a histogram cannot: a region of 60000 bytes
    /// cycling `00 FF` has middling entropy and a ratio near zero. Values above
    /// 1.0 are possible and ordinary, since incompressible input pays LZ4's
    /// framing overhead.
    pub compressed_ratio: f64,
    /// Fraction of examined bytes that are printable ASCII, tab, newline or
    /// carriage return. Ordinary comments and EXIF strings sit high; encrypted
    /// bytes sit near 3/8.
    pub printable_ratio: f64,
    /// The container claimed more bytes here than the file contains, so the
    /// measures describe only the surviving prefix.
    pub truncated: bool,
}

/// Which container this scanner was able to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    Jpeg,
    Png,
    /// Recognised by no parser here. The scan is empty, and empty because
    /// nothing was looked at rather than because nothing was there; that
    /// distinction is the whole reason this variant exists instead of a bare
    /// empty vector.
    Unsupported,
}

/// A whole scan: what was parsed, what was found, and whether the walk ran to
/// a clean end.
///
/// `structure_ok` and `limits_hit` exist so a caller can tell "we parsed this
/// file to its end and these are all of its metadata regions" from "we stopped
/// early", which are different claims and must not render identically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerScan {
    pub format: ContainerFormat,
    /// Findings sorted by `offset`, ascending. Offsets are unique per region,
    /// so the order is total and stable across runs and machines.
    pub findings: Vec<ContainerFinding>,
    /// The container's structure parsed from its signature to its logical end.
    /// False means the file is truncated or malformed and the findings are
    /// whatever was readable before the walk stopped.
    pub structure_ok: bool,
    /// At least one resource cap was reached, so the findings may be
    /// incomplete even when `structure_ok` holds.
    pub limits_hit: bool,
}

impl ContainerScan {
    fn unsupported() -> Self {
        Self {
            format: ContainerFormat::Unsupported,
            findings: Vec::new(),
            structure_ok: true,
            limits_hit: false,
        }
    }
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Scan a file's container slots and return every region found, sorted by
/// offset.
///
/// A path rather than a byte slice, because the whole point of the streaming
/// walk is that the file is never held in memory, and a `&[u8]` parameter would
/// force the caller to defeat that before the first line ran. Callers that
/// already hold bytes can wrap them in a `std::io::Cursor` and use
/// [`scan_reader`].
///
/// Returns an empty vector for a format with no container parser here. Use
/// [`scan_container_detail`] when the difference between "looked and found
/// nothing" and "never looked" matters, which for a coverage record it does.
///
/// # Errors
///
/// Only I/O errors: the file not existing, not being readable, or failing
/// mid-read. A truncated, malformed, or mislabelled file is data rather than an
/// error, and comes back as a scan with `structure_ok == false`.
pub fn scan_container(path: &Path) -> Result<Vec<ContainerFinding>, StegError> {
    scan_container_detail(path).map(|scan| scan.findings)
}

/// Scan a file and return the full record, including whether the structure
/// parsed and whether any cap was reached.
///
/// # Errors
///
/// As [`scan_container`].
pub fn scan_container_detail(path: &Path) -> Result<ContainerScan, StegError> {
    let file = File::open(path).map_err(|err| match err.kind() {
        ErrorKind::NotFound => StegError::FileNotFound(path.display().to_string()),
        _ => StegError::Io(err),
    })?;
    scan_reader(BufReader::new(file))
}

/// Scan anything seekable. The walker reads only segment headers and bounded
/// region prefixes, so this is the memory-safe path for a very large file and
/// the fixture-free path for tests.
///
/// # Errors
///
/// As [`scan_container`].
pub fn scan_reader<R: Read + Seek>(reader: R) -> Result<ContainerScan, StegError> {
    let mut walker = Walker::new(reader)?;
    let Some(format) = walker.sniff()? else {
        return Ok(ContainerScan::unsupported());
    };
    let mut findings = Vec::new();
    let structure_ok = match format {
        ContainerFormat::Jpeg => walker.walk_jpeg(&mut findings)?,
        ContainerFormat::Png => walker.walk_png(&mut findings)?,
        // `sniff` returns None for this, so it is unreachable; a match arm is
        // cheaper than an unreachable panic and cannot become one later.
        ContainerFormat::Unsupported => true,
    };
    findings.sort_by_key(|finding| (finding.offset, finding.length));
    Ok(ContainerScan {
        format,
        findings,
        structure_ok,
        limits_hit: walker.limits_hit,
    })
}

// ── Measurements ──────────────────────────────────────────────────────────────

/// Shannon entropy in bits per byte over the byte histogram. Summed in byte
/// order so the floating-point result is identical run to run; a hash-ordered
/// sum would not be, and the difference would leak into serialised output.
fn shannon_entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut histogram = [0u64; 256];
    for &byte in buf {
        histogram[byte as usize] += 1;
    }
    let total = buf.len() as f64;
    let mut entropy = 0.0;
    for &count in histogram.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compressed size over original size, using the LZ4 block codec the engine
/// already depends on. Cheap enough to run on every region and sensitive to the
/// repetition that entropy is blind to.
fn compressed_ratio(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    lz4_flex::block::compress(buf).len() as f64 / buf.len() as f64
}

/// Fraction of bytes that a person would recognise as text.
fn printable_ratio(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let printable = buf
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r')
        .count();
    printable as f64 / buf.len() as f64
}

// ── The walker ────────────────────────────────────────────────────────────────

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Chunk size for the forward hunt through JPEG entropy-coded data. Bounded by
/// [`MAX_REGION_BYTES`] so this allocation obeys the same ceiling as a region.
const MARKER_HUNT_CHUNK: usize = 16 * 1024;

/// Largest value a PNG chunk length field may hold, per the specification.
const PNG_MAX_CHUNK_LEN: u64 = 0x7FFF_FFFF;

/// PNG chunk types this scanner knows about and therefore does not report as
/// unrecognised. Sorted for readability only; membership is a linear scan over
/// 25 four-byte entries, which is not worth a set.
const KNOWN_PNG_CHUNKS: [&[u8; 4]; 25] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB",
    b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"cICP",
    b"mDCv", b"cLLi", b"tEXt", b"zTXt", b"iTXt",
];

struct Walker<R: Read + Seek> {
    reader: R,
    pos: u64,
    file_len: u64,
    budget: u64,
    limits_hit: bool,
}

impl<R: Read + Seek> Walker<R> {
    fn new(mut reader: R) -> io::Result<Self> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            pos: 0,
            file_len,
            budget: MAX_SCAN_BYTES,
            limits_hit: false,
        })
    }

    /// Read up to `n` bytes from the current position, returning fewer at
    /// end of file or when the scan budget runs out. Never allocates more than
    /// `n`, and every call site passes a value bounded by a documented cap.
    fn read_up_to(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let allowed = (n as u64).min(self.budget) as usize;
        if allowed < n {
            self.limits_hit = true;
        }
        let mut buf = vec![0u8; allowed];
        let mut got = 0;
        while got < allowed {
            match self.reader.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(read) => got += read,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        buf.truncate(got);
        self.pos += got as u64;
        self.budget -= got as u64;
        Ok(buf)
    }

    fn seek_to(&mut self, offset: u64) -> io::Result<()> {
        self.reader.seek(SeekFrom::Start(offset))?;
        self.pos = offset;
        Ok(())
    }

    /// Identify the container from its leading bytes rather than from a file
    /// extension, matching the engine's content-sniffing convention: a JPEG
    /// named `.png` is still a JPEG and must still be walked as one.
    fn sniff(&mut self) -> io::Result<Option<ContainerFormat>> {
        self.seek_to(0)?;
        let head = self.read_up_to(PNG_SIGNATURE.len())?;
        self.seek_to(0)?;
        if head.len() >= 8 && head[..8] == PNG_SIGNATURE {
            return Ok(Some(ContainerFormat::Png));
        }
        if head.len() >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
            return Ok(Some(ContainerFormat::Jpeg));
        }
        Ok(None)
    }

    /// Measure one region and push a finding if it clears the reporting floor.
    /// Leaves the cursor wherever the read ended; callers seek explicitly.
    fn measure(
        &mut self,
        slot: ContainerSlot,
        offset: u64,
        declared_length: u64,
    ) -> io::Result<Option<ContainerFinding>> {
        if offset >= self.file_len {
            return Ok(None);
        }
        self.seek_to(offset)?;
        let available = self.file_len - offset;
        let want = declared_length.min(available).min(MAX_REGION_BYTES) as usize;
        if declared_length > MAX_REGION_BYTES {
            self.limits_hit = true;
        }
        let buf = self.read_up_to(want)?;
        if buf.len() < MIN_REGION_BYTES {
            return Ok(None);
        }
        Ok(Some(ContainerFinding {
            slot,
            offset,
            length: declared_length.min(available),
            declared_length,
            examined: buf.len() as u64,
            entropy_bits_per_byte: shannon_entropy(&buf),
            compressed_ratio: compressed_ratio(&buf),
            printable_ratio: printable_ratio(&buf),
            truncated: declared_length > available,
        }))
    }

    /// Push a finding unless the output cap has been reached. Returns false
    /// when the cap is hit, which tells the caller to stop walking: continuing
    /// would burn the scan budget producing findings that cannot be returned.
    fn push(&mut self, findings: &mut Vec<ContainerFinding>, finding: ContainerFinding) -> bool {
        if findings.len() >= MAX_REGIONS {
            self.limits_hit = true;
            return false;
        }
        findings.push(finding);
        true
    }

    /// Record whatever lies past a format's logical end.
    fn record_trailing(
        &mut self,
        findings: &mut Vec<ContainerFinding>,
        end: u64,
    ) -> io::Result<()> {
        if end >= self.file_len {
            return Ok(());
        }
        let length = self.file_len - end;
        if let Some(finding) = self.measure(ContainerSlot::Trailing, end, length)? {
            self.push(findings, finding);
        }
        Ok(())
    }

    // ── JPEG ──────────────────────────────────────────────────────────────

    /// Drive the JPEG marker walk, handing every segment to `on_segment` as
    /// `(walker, marker, body_offset, body_length, truncated)`. Returns whether
    /// a clean EOI was reached.
    ///
    /// This exists so the engine has exactly one JPEG marker walker. The
    /// metadata scan and the DCT analysis in `dct_analysis` need different
    /// segments (COM and APPn against DQT and SOF) but the same caps, the same
    /// treatment of fill bytes and restart markers, and above all the same
    /// answer about where a segment begins. Two walkers would eventually
    /// disagree about that, and the file they disagreed on would be the
    /// adversarial one.
    ///
    /// EOI is reported as marker `0xD9` with `body_offset` set to the offset
    /// just past it and a zero length, so a caller interested in trailing data
    /// learns where it starts without needing its own copy of the walk.
    fn drive_jpeg<F>(&mut self, mut on_segment: F) -> io::Result<bool>
    where
        F: FnMut(&mut Self, u8, u64, u64, bool) -> io::Result<Decision>,
    {
        // Past the SOI; `sniff` has already confirmed FF D8 FF.
        self.seek_to(2)?;
        for _ in 0..MAX_STRUCTURE_STEPS {
            let Some(marker) = self.next_jpeg_marker()? else {
                return Ok(false);
            };
            match marker {
                // Standalone markers: TEM and the restart markers carry no
                // length field and no payload.
                0x01 | 0xD0..=0xD7 => continue,
                // EOI: everything after this is appended data.
                0xD9 => {
                    let end = self.pos;
                    if let Decision::Stop(reached_end) = on_segment(self, 0xD9, end, 0, false)? {
                        return Ok(reached_end);
                    }
                    return Ok(true);
                }
                _ => {}
            }
            let header = self.read_up_to(2)?;
            if header.len() < 2 {
                return Ok(false);
            }
            let declared = u64::from(u16::from_be_bytes([header[0], header[1]]));
            // The length field counts itself, so anything below 2 is malformed
            // and anything equal to 2 is a zero-length payload.
            if declared < 2 {
                return Ok(false);
            }
            let body_offset = self.pos;
            let body_length = declared - 2;
            let truncated = body_offset + body_length > self.file_len;

            if let Decision::Stop(reached_end) =
                on_segment(self, marker, body_offset, body_length, truncated)?
            {
                return Ok(reached_end);
            }
            if truncated {
                // The segment claims more bytes than the file holds, so there
                // is no next marker to find. Whatever prefix existed has
                // already been measured.
                return Ok(false);
            }
            self.seek_to(body_offset + body_length)?;

            // SOS is followed by entropy-coded data of a length no header
            // states, so the only way to the next marker is forward through it.
            if marker == 0xDA && !self.hunt_next_marker()? {
                return Ok(false);
            }
        }
        self.limits_hit = true;
        Ok(false)
    }

    /// Walk the JPEG marker stream for metadata regions. Returns whether it
    /// reached a clean EOI.
    fn walk_jpeg(&mut self, findings: &mut Vec<ContainerFinding>) -> io::Result<bool> {
        self.drive_jpeg(|walker, marker, body_offset, body_length, truncated| {
            if marker == 0xD9 {
                walker.record_trailing(findings, body_offset)?;
                return Ok(Decision::Continue);
            }
            let slot = match marker {
                0xFE => Some(ContainerSlot::JpegComment),
                0xE0..=0xEF => Some(ContainerSlot::JpegApp { n: marker & 0x0F }),
                _ => None,
            };
            if let Some(slot) = slot {
                if let Some(finding) = walker.measure(slot, body_offset, body_length)? {
                    if !walker.push(findings, finding) {
                        return Ok(Decision::Stop(!truncated));
                    }
                }
            }
            Ok(Decision::Continue)
        })
    }

    /// Consume `FF` (with bounded fill) and return the marker byte, or None if
    /// the stream is not where a marker should be.
    fn next_jpeg_marker(&mut self) -> io::Result<Option<u8>> {
        let lead = self.read_up_to(1)?;
        if lead.first() != Some(&0xFF) {
            return Ok(None);
        }
        for _ in 0..MAX_FILL_BYTES {
            let next = self.read_up_to(1)?;
            match next.first() {
                None => return Ok(None),
                // Fill byte; the standard allows a run of them before a marker.
                Some(0xFF) => continue,
                Some(&marker) => return Ok(Some(marker)),
            }
        }
        self.limits_hit = true;
        Ok(None)
    }

    /// Move the cursor to the `FF` of the next real marker, skipping
    /// entropy-coded data. Stuffed bytes (`FF 00`) and restart markers
    /// (`FF D0` to `FF D7`) are part of the scan and are not markers here.
    fn hunt_next_marker(&mut self) -> io::Result<bool> {
        let mut pending_ff_at: Option<u64> = None;
        loop {
            let chunk_start = self.pos;
            let chunk = self.read_up_to(MARKER_HUNT_CHUNK)?;
            if chunk.is_empty() {
                return Ok(false);
            }
            // A FF that ended the previous chunk is resolved by this chunk's
            // first byte, which is why the position is carried rather than the
            // flag: the marker starts at the FF, not at the byte after it.
            if let Some(ff_at) = pending_ff_at.take() {
                let candidate = chunk[0];
                if is_real_marker(candidate) {
                    self.seek_to(ff_at)?;
                    return Ok(true);
                }
            }
            let mut index = 0;
            while index < chunk.len() {
                if chunk[index] != 0xFF {
                    index += 1;
                    continue;
                }
                match chunk.get(index + 1) {
                    None => {
                        pending_ff_at = Some(chunk_start + index as u64);
                        break;
                    }
                    Some(&candidate) if is_real_marker(candidate) => {
                        self.seek_to(chunk_start + index as u64)?;
                        return Ok(true);
                    }
                    // FF 00 is a stuffed data byte and FF FF is fill; in both
                    // cases step one byte so an FF run is still examined.
                    Some(_) => index += 1,
                }
            }
            if chunk.len() < MARKER_HUNT_CHUNK {
                return Ok(false);
            }
        }
    }

    // ── PNG ───────────────────────────────────────────────────────────────

    /// Walk the PNG chunk stream. Returns whether it reached a clean IEND.
    fn walk_png(&mut self, findings: &mut Vec<ContainerFinding>) -> io::Result<bool> {
        self.seek_to(PNG_SIGNATURE.len() as u64)?;
        for _ in 0..MAX_STRUCTURE_STEPS {
            let header = self.read_up_to(8)?;
            if header.len() < 8 {
                return Ok(false);
            }
            let declared = u64::from(u32::from_be_bytes([
                header[0], header[1], header[2], header[3],
            ]));
            if declared > PNG_MAX_CHUNK_LEN {
                return Ok(false);
            }
            let chunk_type: [u8; 4] = [header[4], header[5], header[6], header[7]];
            if !chunk_type.iter().all(u8::is_ascii_alphabetic) {
                return Ok(false);
            }
            let body_offset = self.pos;
            // Chunk data is followed by a 4-byte CRC, which must also be
            // present for the chunk to be complete.
            let truncated = body_offset + declared + 4 > self.file_len;

            if &chunk_type == b"IEND" {
                if truncated {
                    return Ok(false);
                }
                let end = body_offset + declared + 4;
                self.record_trailing(findings, end)?;
                return Ok(true);
            }

            let slot = png_slot(&chunk_type);
            if let Some(slot) = slot {
                if let Some(finding) = self.measure(slot, body_offset, declared)? {
                    if !self.push(findings, finding) {
                        return Ok(false);
                    }
                }
            }
            if truncated {
                return Ok(false);
            }
            self.seek_to(body_offset + declared + 4)?;
        }
        self.limits_hit = true;
        Ok(false)
    }
}

/// Whether the JPEG walk carries on after a segment, and if it stops, whether
/// it is stopping having reached the stream's logical end.
enum Decision {
    Continue,
    Stop(bool),
}

/// Walk a JPEG's segment headers and hand each one to `visitor` as
/// `(marker, body_offset, body_length)`, both offsets into `bytes`.
///
/// Shares the metadata scanner's walker, and therefore its caps: at most
/// [`MAX_STRUCTURE_STEPS`] segments, at most [`MAX_SCAN_BYTES`] read. The
/// visitor returns false to stop the walk early, which is how a caller that
/// only wants DQT and SOF avoids traversing the entropy-coded scan.
///
/// EOI and any segment whose declared length runs past the end of `bytes` are
/// not handed to the visitor, so a visitor may slice `bytes` at the offset and
/// length it is given without checking them again.
///
/// Returns whether the walk reached the stream's logical end, which for an
/// early-stopping visitor is true: it stopped because it had what it wanted.
///
/// # Errors
///
/// [`StegError::UnsupportedFormat`] if `bytes` does not begin with a JPEG
/// signature. I/O errors cannot arise from an in-memory slice, so in practice
/// that is the only failure.
pub fn visit_jpeg_segments<F>(bytes: &[u8], mut visitor: F) -> Result<bool, StegError>
where
    F: FnMut(u8, usize, usize) -> bool,
{
    let mut walker = Walker::new(Cursor::new(bytes))?;
    if walker.sniff()? != Some(ContainerFormat::Jpeg) {
        return Err(StegError::UnsupportedFormat(
            "not a JPEG: no SOI marker".to_string(),
        ));
    }
    let mut stopped_early = false;
    let reached_end = walker.drive_jpeg(|_walker, marker, offset, length, truncated| {
        if marker == 0xD9 || truncated {
            return Ok(Decision::Continue);
        }
        if !visitor(marker, offset as usize, length as usize) {
            stopped_early = true;
            return Ok(Decision::Stop(true));
        }
        Ok(Decision::Continue)
    })?;
    Ok(reached_end || stopped_early)
}

/// Does this byte, following an `FF` inside entropy-coded data, start a real
/// marker? `00` is a stuffed data byte, `FF` is fill, and `D0` to `D7` are
/// restart markers that belong to the scan itself.
fn is_real_marker(byte: u8) -> bool {
    byte != 0x00 && byte != 0xFF && !(0xD0..=0xD7).contains(&byte)
}

/// Classify a PNG chunk type, or None for a chunk whose contents this scanner
/// has no interest in.
fn png_slot(chunk_type: &[u8; 4]) -> Option<ContainerSlot> {
    match chunk_type {
        b"tEXt" => Some(ContainerSlot::PngText {
            kind: PngTextKind::Text,
        }),
        b"zTXt" => Some(ContainerSlot::PngText {
            kind: PngTextKind::CompressedText,
        }),
        b"iTXt" => Some(ContainerSlot::PngText {
            kind: PngTextKind::InternationalText,
        }),
        other => {
            // The ancillary bit is bit 5 of the first byte: lowercase means a
            // decoder may ignore the chunk, which is what makes an invented
            // ancillary type a durable hiding place. A critical chunk we do not
            // know is a different problem and not this module's.
            let ancillary = other[0].is_ascii_lowercase();
            let known = KNOWN_PNG_CHUNKS.contains(&other);
            (ancillary && !known).then(|| ContainerSlot::PngUnknownAncillary {
                chunk_type: String::from_utf8_lossy(other).into_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixture builders ──────────────────────────────────────────────────
    //
    // Hand-constructed byte sequences rather than fixture files: the walker is
    // a byte-level parser, so a test that cannot state the exact bytes it is
    // parsing is not testing the thing that breaks.

    /// A minimal but structurally valid JPEG: SOI, the given segments, SOS with
    /// a tiny entropy-coded scan, EOI.
    fn jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8, 0xFF, 0xE0];
        // APP0/JFIF so the sniff sees FF D8 FF and the first segment is real.
        let jfif = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0".to_vec();
        out.extend_from_slice(&((jfif.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&jfif);
        for (marker, body) in segments {
            out.push(0xFF);
            out.push(*marker);
            out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(body);
        }
        // SOS: a 10-byte header, then scan data containing a stuffed FF 00 and
        // a restart marker, both of which must not be mistaken for the EOI.
        out.push(0xFF);
        out.push(0xDA);
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0, 0, 0, 0]);
        out.extend_from_slice(&[0xAB, 0xFF, 0x00, 0xCD, 0xFF, 0xD0, 0x12, 0x34]);
        out.push(0xFF);
        out.push(0xD9);
        out
    }

    fn png_chunk(chunk_type: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(body);
        // The CRC is not verified by this scanner, so a placeholder is honest
        // about what the walker depends on: the length field and the type.
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend_from_slice(&png_chunk(
            b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        ));
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&png_chunk(b"IEND", &[]));
        out
    }

    fn scan(bytes: &[u8]) -> ContainerScan {
        scan_reader(Cursor::new(bytes.to_vec())).expect("in-memory scan cannot fail on I/O")
    }

    /// Bytes cycling 0 to 255: a perfectly flat histogram, so entropy is
    /// exactly 8.0 bits per byte. Deliberately *not* used where compressibility
    /// is asserted, because a repeating 256-byte cycle is highly compressible
    /// and so looks nothing like ciphertext on that measure.
    fn flat_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

    /// Deterministic pseudorandom bytes (SplitMix64), which is what the three
    /// measures should see as indistinguishable from encrypted output. Fixed
    /// seed, so every assertion below is reproducible.
    fn pseudorandom_bytes(n: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        (0..n)
            .map(|_| {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                ((z ^ (z >> 31)) & 0xFF) as u8
            })
            .collect()
    }

    // ── Sniffing and unsupported input ────────────────────────────────────

    #[test]
    fn unsupported_format_is_reported_as_unsupported_not_as_clean() {
        let result = scan(b"RIFF....WEBPVP8 and some more padding bytes here");
        assert_eq!(result.format, ContainerFormat::Unsupported);
        assert!(result.findings.is_empty());
        assert!(result.structure_ok);
        assert!(!result.limits_hit);
    }

    #[test]
    fn empty_input_is_unsupported_and_does_not_panic() {
        let result = scan(b"");
        assert_eq!(result.format, ContainerFormat::Unsupported);
    }

    #[test]
    fn truncated_signature_is_unsupported() {
        // Seven bytes of the eight-byte PNG signature, and two of the three
        // JPEG sniff bytes: both short reads must be handled, not indexed.
        assert_eq!(
            scan(&PNG_SIGNATURE[..7]).format,
            ContainerFormat::Unsupported
        );
        assert_eq!(scan(&[0xFF, 0xD8]).format, ContainerFormat::Unsupported);
    }

    #[test]
    fn format_is_sniffed_from_content_not_from_any_extension() {
        // The walker never sees a filename, so this is a statement about the
        // sniff order: a PNG signature wins regardless of what follows.
        assert_eq!(scan(&png(&[])).format, ContainerFormat::Png);
        assert_eq!(scan(&jpeg(&[])).format, ContainerFormat::Jpeg);
    }

    // ── JPEG ──────────────────────────────────────────────────────────────

    #[test]
    fn clean_jpeg_yields_nothing() {
        let result = scan(&jpeg(&[]));
        assert_eq!(result.format, ContainerFormat::Jpeg);
        assert!(result.structure_ok);
        assert!(!result.limits_hit);
        // A real JFIF APP0 payload is 14 bytes, below the reporting floor, so an
        // ordinary camera JPEG produces no rows at all. That the floor happens
        // to clear the one segment every JPEG carries is why 16 is a workable
        // number rather than a lucky one.
        assert!(result.findings.is_empty());
    }

    #[test]
    fn jpeg_comment_segment_is_found_with_high_entropy() {
        let payload = flat_bytes(1024);
        let result = scan(&jpeg(&[(0xFE, payload.clone())]));
        let comment = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::JpegComment)
            .expect("the COM segment must be found");
        assert_eq!(comment.length, 1024);
        assert_eq!(comment.declared_length, 1024);
        assert_eq!(comment.examined, 1024);
        assert!(!comment.truncated);
        assert!(
            comment.entropy_bits_per_byte > 7.9,
            "flat histogram should be near 8 bits/byte, got {}",
            comment.entropy_bits_per_byte
        );
        assert!(comment.printable_ratio < 0.5);
    }

    #[test]
    fn jpeg_app1_exif_payload_is_found_and_the_app_number_is_the_low_nibble() {
        let mut exif = b"Exif\0\0".to_vec();
        exif.extend_from_slice(&flat_bytes(600));
        let result = scan(&jpeg(&[(0xE1, exif)]));
        let app1 = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::JpegApp { n: 1 })
            .expect("APP1 must be found");
        assert_eq!(app1.length, 606);
        // APP15 maps to n == 15, which is the other end of the nibble range.
        let result = scan(&jpeg(&[(0xEF, flat_bytes(64))]));
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegApp { n: 15 }));
    }

    #[test]
    fn ordinary_text_and_ciphertext_separate_on_all_three_measures() {
        // The reason the module records three numbers: a readable comment and
        // an encrypted blob of the same length look nothing alike, and this is
        // the evidence for that claim rather than an assertion of it.
        let prose = b"Photographed in Edinburgh on a grey afternoon, Nikon D750, 35mm, \
                      hand held at 1/125s. Converted from raw without any further editing."
            .repeat(8);
        let cipher = pseudorandom_bytes(prose.len());

        let prose_scan = scan(&jpeg(&[(0xFE, prose.clone())]));
        let cipher_scan = scan(&jpeg(&[(0xFE, cipher)]));
        let find = |s: &ContainerScan| {
            s.findings
                .iter()
                .find(|f| f.slot == ContainerSlot::JpegComment)
                .cloned()
                .expect("comment")
        };
        let text = find(&prose_scan);
        let blob = find(&cipher_scan);

        assert!(text.entropy_bits_per_byte < blob.entropy_bits_per_byte);
        assert!(text.compressed_ratio < blob.compressed_ratio);
        assert!(text.printable_ratio > 0.99);
        assert!(blob.printable_ratio < 0.4);
    }

    #[test]
    fn jpeg_trailing_bytes_after_eoi_are_reported() {
        let mut bytes = jpeg(&[]);
        let eoi_end = bytes.len() as u64;
        bytes.extend_from_slice(&flat_bytes(300));
        let result = scan(&bytes);
        assert!(result.structure_ok);
        let trailing = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::Trailing)
            .expect("appended data must be found");
        assert_eq!(trailing.offset, eoi_end);
        assert_eq!(trailing.length, 300);
    }

    #[test]
    fn appended_bytes_containing_a_fake_eoi_do_not_spoof_the_logical_end() {
        // A reverse search for FF D9 would stop inside the appended data and
        // report a shorter trailer, or none. The forward parse cannot.
        let mut bytes = jpeg(&[]);
        let eoi_end = bytes.len() as u64;
        let mut appended = vec![0xFF, 0xD9];
        appended.extend_from_slice(&flat_bytes(200));
        appended.extend_from_slice(&[0xFF, 0xD9]);
        bytes.extend_from_slice(&appended);
        let result = scan(&bytes);
        let trailing = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::Trailing)
            .expect("trailing");
        assert_eq!(trailing.offset, eoi_end);
        assert_eq!(trailing.length, appended.len() as u64);
    }

    #[test]
    fn every_finding_is_reported_not_only_the_first() {
        // C5: a file with a stuffed COM segment, a stuffed APP1 and appended
        // data must report three regions. `fingerprint_image` returns on first
        // match and would report one.
        let mut bytes = jpeg(&[(0xFE, flat_bytes(200)), (0xE1, flat_bytes(300))]);
        bytes.extend_from_slice(&flat_bytes(400));
        let result = scan(&bytes);
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegComment));
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegApp { n: 1 }));
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::Trailing));
        assert_eq!(result.findings.len(), 3);
    }

    #[test]
    fn zero_length_and_short_segments_are_not_reported() {
        // A zero-length COM is legal and carries nothing; a 15-byte one is
        // below the reporting floor. Neither may panic and neither may appear.
        let result = scan(&jpeg(&[(0xFE, Vec::new()), (0xFE, flat_bytes(15))]));
        assert!(result.structure_ok);
        assert!(!result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegComment));
        // Exactly at the floor, it is reported.
        let result = scan(&jpeg(&[(0xFE, flat_bytes(16))]));
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegComment));
    }

    #[test]
    fn jpeg_segment_length_running_past_eof_is_measured_and_flagged_truncated() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xFE];
        bytes.extend_from_slice(&4002u16.to_be_bytes()); // claims 4000 bytes
        bytes.extend_from_slice(&flat_bytes(100)); // provides 100
        let result = scan(&bytes);
        assert!(!result.structure_ok, "a truncated file must not claim OK");
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert!(finding.truncated);
        assert_eq!(finding.declared_length, 4000);
        assert_eq!(finding.length, 100);
        assert_eq!(finding.examined, 100);
    }

    #[test]
    fn jpeg_declared_length_below_two_is_malformed_and_stops_the_walk() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xFE];
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&flat_bytes(64));
        let result = scan(&bytes);
        assert!(!result.structure_ok);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn jpeg_segment_header_cut_mid_length_field_stops_cleanly() {
        let bytes = vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00];
        let result = scan(&bytes);
        assert_eq!(result.format, ContainerFormat::Jpeg);
        assert!(!result.structure_ok);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn jpeg_without_an_eoi_reports_what_it_read_and_does_not_claim_ok() {
        let mut bytes = jpeg(&[(0xFE, flat_bytes(100))]);
        // Drop the EOI so the scan runs off the end of the file.
        bytes.truncate(bytes.len() - 2);
        let result = scan(&bytes);
        assert!(!result.structure_ok);
        assert!(result
            .findings
            .iter()
            .any(|f| f.slot == ContainerSlot::JpegComment));
    }

    #[test]
    fn a_byte_that_is_not_a_marker_where_one_is_due_stops_the_walk() {
        let bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0x41, 0x42, 0x43];
        let result = scan(&bytes);
        assert!(!result.structure_ok);
    }

    #[test]
    fn standalone_markers_carry_no_length_field() {
        // TEM (FF 01) and a restart marker must be stepped over without the
        // walker trying to read a length that is not there.
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0x01, 0xFF, 0xD3, 0xFF, 0xFE];
        bytes.extend_from_slice(&66u16.to_be_bytes());
        bytes.extend_from_slice(&flat_bytes(64));
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        let result = scan(&bytes);
        assert!(result.structure_ok);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].slot, ContainerSlot::JpegComment);
    }

    #[test]
    fn fill_bytes_before_a_marker_are_tolerated_up_to_the_cap() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF];
        bytes.extend_from_slice(&[0xFF; 8]);
        bytes.push(0xFE);
        bytes.extend_from_slice(&66u16.to_be_bytes());
        bytes.extend_from_slice(&flat_bytes(64));
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        let result = scan(&bytes);
        assert!(result.structure_ok);
        assert_eq!(result.findings.len(), 1);

        // Past the cap, the walk stops and says a limit was reached rather than
        // spinning through an unbounded run.
        let mut hostile = vec![0xFF, 0xD8, 0xFF];
        hostile.extend_from_slice(&[0xFF; MAX_FILL_BYTES + 4]);
        hostile.push(0xFE);
        hostile.extend_from_slice(&66u16.to_be_bytes());
        hostile.extend_from_slice(&flat_bytes(64));
        let result = scan(&hostile);
        assert!(!result.structure_ok);
        assert!(result.limits_hit);
    }

    #[test]
    fn a_file_ending_immediately_after_an_ff_does_not_panic() {
        let result = scan(&[0xFF, 0xD8, 0xFF]);
        assert_eq!(result.format, ContainerFormat::Jpeg);
        assert!(!result.structure_ok);
    }

    #[test]
    fn the_scan_data_hunt_crosses_chunk_boundaries_correctly() {
        // An FF that lands as the last byte of one 16 KiB read, with its marker
        // byte as the first of the next, is the off-by-one this guards. The
        // scan is padded so the EOI straddles that boundary.
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xDA];
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0, 0, 0, 0]);
        let header_end = bytes.len();
        // Pad so that the FF of the EOI falls exactly at the end of the first
        // MARKER_HUNT_CHUNK read, which begins at header_end.
        let pad = MARKER_HUNT_CHUNK - 1;
        bytes.extend_from_slice(&vec![0x7E; pad]);
        assert_eq!(bytes.len() - header_end, MARKER_HUNT_CHUNK - 1);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        let eoi_end = bytes.len() as u64;
        bytes.extend_from_slice(&flat_bytes(80));
        let result = scan(&bytes);
        assert!(result.structure_ok, "the EOI must be found across the seam");
        let trailing = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::Trailing)
            .expect("trailing");
        assert_eq!(trailing.offset, eoi_end);
        assert_eq!(trailing.length, 80);
    }

    #[test]
    fn scan_data_that_never_ends_stops_without_claiming_ok() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xDA];
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0, 0, 0, 0]);
        // Stuffed bytes and restart markers only: no real marker anywhere.
        for _ in 0..2000 {
            bytes.extend_from_slice(&[0x11, 0xFF, 0x00, 0xFF, 0xD0]);
        }
        let result = scan(&bytes);
        assert!(!result.structure_ok);
    }

    #[test]
    fn a_huge_segment_is_examined_only_up_to_the_region_cap() {
        // MAX_REGION_BYTES is 64 KiB and a JPEG length field tops out just
        // below it, so PNG is where this binds; the JPEG side checks the
        // boundary case of a segment at the field's maximum.
        let body = flat_bytes(0xFFFF - 2);
        let result = scan(&jpeg(&[(0xFE, body)]));
        let comment = result
            .findings
            .iter()
            .find(|f| f.slot == ContainerSlot::JpegComment)
            .expect("comment");
        assert_eq!(comment.declared_length, 0xFFFF - 2);
        assert!(comment.examined <= MAX_REGION_BYTES);
    }

    // ── PNG ───────────────────────────────────────────────────────────────

    #[test]
    fn clean_png_yields_nothing() {
        let result = scan(&png(&[]));
        assert_eq!(result.format, ContainerFormat::Png);
        assert!(result.structure_ok);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn png_text_chunks_are_found_and_distinguished() {
        let mut text = b"Comment\0".to_vec();
        text.extend_from_slice(&flat_bytes(200));
        let mut ztxt = b"Comment\0\0".to_vec();
        ztxt.extend_from_slice(&flat_bytes(200));
        let mut itxt = b"Comment\0\0\0en\0Comment\0".to_vec();
        itxt.extend_from_slice(&flat_bytes(200));
        let result = scan(&png(&[
            png_chunk(b"tEXt", &text),
            png_chunk(b"zTXt", &ztxt),
            png_chunk(b"iTXt", &itxt),
        ]));
        assert!(result.structure_ok);
        let kinds: Vec<_> = result.findings.iter().map(|f| f.slot.clone()).collect();
        assert_eq!(
            kinds,
            vec![
                ContainerSlot::PngText {
                    kind: PngTextKind::Text
                },
                ContainerSlot::PngText {
                    kind: PngTextKind::CompressedText
                },
                ContainerSlot::PngText {
                    kind: PngTextKind::InternationalText
                },
            ]
        );
    }

    #[test]
    fn an_invented_ancillary_chunk_is_reported_and_a_known_one_is_not() {
        let result = scan(&png(&[
            png_chunk(b"stEG", &flat_bytes(200)),
            png_chunk(b"pHYs", &flat_bytes(200)),
        ]));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].slot,
            ContainerSlot::PngUnknownAncillary {
                chunk_type: "stEG".to_string()
            }
        );
    }

    #[test]
    fn an_unknown_critical_chunk_is_not_this_modules_business() {
        // Uppercase first letter: a decoder must not ignore it, so it is not a
        // place data hides quietly. Reporting it would be noise.
        let result = scan(&png(&[png_chunk(b"STEG", &flat_bytes(200))]));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn png_trailing_bytes_after_iend_are_reported() {
        let mut bytes = png(&[]);
        let iend_end = bytes.len() as u64;
        bytes.extend_from_slice(&flat_bytes(500));
        let result = scan(&bytes);
        assert!(result.structure_ok);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].slot, ContainerSlot::Trailing);
        assert_eq!(result.findings[0].offset, iend_end);
        assert_eq!(result.findings[0].length, 500);
    }

    #[test]
    fn appended_bytes_containing_a_fake_iend_do_not_spoof_the_logical_end() {
        let mut bytes = png(&[]);
        let iend_end = bytes.len() as u64;
        bytes.extend_from_slice(&png_chunk(b"IEND", &[]));
        bytes.extend_from_slice(&flat_bytes(100));
        let result = scan(&bytes);
        assert_eq!(result.findings[0].offset, iend_end);
    }

    #[test]
    fn a_png_chunk_length_running_past_eof_is_measured_and_flagged() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&png_chunk(
            b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        ));
        bytes.extend_from_slice(&50_000u32.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(&flat_bytes(120));
        let result = scan(&bytes);
        assert!(!result.structure_ok);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].truncated);
        assert_eq!(result.findings[0].declared_length, 50_000);
        assert_eq!(result.findings[0].length, 120);
    }

    #[test]
    fn a_png_chunk_length_above_the_specification_maximum_stops_the_walk() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(&flat_bytes(64));
        let result = scan(&bytes);
        assert!(!result.structure_ok);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn a_non_alphabetic_chunk_type_stops_the_walk() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        bytes.extend_from_slice(&flat_bytes(64));
        let result = scan(&bytes);
        assert!(!result.structure_ok);
    }

    #[test]
    fn a_png_chunk_header_cut_short_stops_the_walk() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 5, b't']);
        let result = scan(&bytes);
        assert_eq!(result.format, ContainerFormat::Png);
        assert!(!result.structure_ok);
    }

    #[test]
    fn a_png_whose_iend_crc_is_missing_does_not_claim_ok() {
        let mut bytes = png(&[]);
        bytes.truncate(bytes.len() - 2);
        let result = scan(&bytes);
        assert!(!result.structure_ok);
    }

    #[test]
    fn a_png_with_no_iend_does_not_claim_ok() {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&png_chunk(b"tEXt", &flat_bytes(100)));
        let result = scan(&bytes);
        assert!(!result.structure_ok);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn a_png_chunk_larger_than_the_region_cap_is_examined_only_to_the_cap() {
        let body = flat_bytes((MAX_REGION_BYTES as usize) * 2);
        let result = scan(&png(&[png_chunk(b"tEXt", &body)]));
        let finding = &result.findings[0];
        assert_eq!(finding.declared_length, MAX_REGION_BYTES * 2);
        assert_eq!(finding.length, MAX_REGION_BYTES * 2);
        assert_eq!(finding.examined, MAX_REGION_BYTES);
        assert!(result.limits_hit, "hitting the region cap must be visible");
    }

    // ── Caps, ordering and determinism ────────────────────────────────────

    #[test]
    fn the_findings_cap_bounds_output_on_a_hostile_file() {
        // Many more stuffed chunks than MAX_REGIONS: the output must stop at
        // the cap and say so, not grow with the attacker's file.
        let chunk = png_chunk(b"stEG", &flat_bytes(32));
        let chunks: Vec<Vec<u8>> = (0..MAX_REGIONS + 50).map(|_| chunk.clone()).collect();
        let result = scan(&png(&chunks));
        assert_eq!(result.findings.len(), MAX_REGIONS);
        assert!(result.limits_hit);
    }

    #[test]
    fn thousands_of_tiny_segments_terminate_without_unbounded_work() {
        // Below the reporting floor, so nothing is returned, but the structure
        // walk still has to traverse them all and stop.
        let chunk = png_chunk(b"stEG", &[0u8; 4]);
        let chunks: Vec<Vec<u8>> = (0..50_000).map(|_| chunk.clone()).collect();
        let result = scan(&png(&chunks));
        assert!(result.findings.is_empty());
        assert!(result.structure_ok);
    }

    #[test]
    fn the_structure_step_cap_stops_a_file_with_too_many_chunks() {
        let chunk = png_chunk(b"stEG", &[]);
        let chunks: Vec<Vec<u8>> = (0..MAX_STRUCTURE_STEPS + 10)
            .map(|_| chunk.clone())
            .collect();
        let result = scan(&png(&chunks));
        assert!(!result.structure_ok);
        assert!(result.limits_hit);
    }

    #[test]
    fn findings_are_sorted_by_offset_and_the_order_is_stable() {
        let mut bytes = jpeg(&[(0xE1, flat_bytes(100)), (0xFE, flat_bytes(100))]);
        bytes.extend_from_slice(&flat_bytes(100));
        let first = scan(&bytes).findings;
        let second = scan(&bytes).findings;
        assert_eq!(first, second, "two runs must agree exactly");
        let offsets: Vec<u64> = first.iter().map(|f| f.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn serialised_output_is_byte_identical_across_runs() {
        let mut bytes = png(&[png_chunk(b"tEXt", &flat_bytes(300))]);
        bytes.extend_from_slice(&flat_bytes(64));
        let a = serde_json::to_string(&scan(&bytes)).expect("serialisable");
        let b = serde_json::to_string(&scan(&bytes)).expect("serialisable");
        assert_eq!(a, b);
        // The slot flattens into the finding, so a consumer sees one object.
        assert!(a.contains("\"slot\":\"png_text\""));
        assert!(a.contains("\"slot\":\"trailing\""));
    }

    #[test]
    fn a_scan_round_trips_through_json() {
        let bytes = jpeg(&[(0xFE, flat_bytes(64))]);
        let original = scan(&bytes);
        let json = serde_json::to_string(&original).expect("serialisable");
        let back: ContainerScan = serde_json::from_str(&json).expect("deserialisable");
        assert_eq!(original, back);
    }

    // ── Measurement edge cases ────────────────────────────────────────────

    #[test]
    fn entropy_is_zero_for_a_constant_region_and_eight_for_a_flat_one() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0x41; 512]), 0.0);
        assert!((shannon_entropy(&flat_bytes(256)) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn compressibility_sees_the_repetition_entropy_is_blind_to() {
        // Alternating two bytes: entropy is 1 bit per byte, nowhere near 8, yet
        // the region is obviously not ciphertext and the ratio says so.
        let repetitive: Vec<u8> = (0..4096)
            .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
            .collect();
        assert!((shannon_entropy(&repetitive) - 1.0).abs() < 1e-9);
        assert!(compressed_ratio(&repetitive) < 0.05);
        assert!(compressed_ratio(&pseudorandom_bytes(4096)) > 0.9);
        assert_eq!(compressed_ratio(&[]), 0.0);
        // And the converse: a flat histogram is maximal entropy yet still very
        // compressible when it is a repeating cycle, so neither measure alone
        // would do.
        assert!((shannon_entropy(&flat_bytes(4096)) - 8.0).abs() < 1e-12);
        assert!(compressed_ratio(&flat_bytes(4096)) < 0.5);
    }

    #[test]
    fn printable_ratio_counts_whitespace_as_text() {
        assert_eq!(printable_ratio(b"abc\t\n\r"), 1.0);
        assert_eq!(printable_ratio(&[0x00, 0x01, 0xFF, 0x80]), 0.0);
        assert_eq!(printable_ratio(&[]), 0.0);
    }

    #[test]
    fn slot_labels_are_plain_language_for_every_variant() {
        let labels = [
            ContainerSlot::JpegComment.label(),
            ContainerSlot::JpegApp { n: 1 }.label(),
            ContainerSlot::PngText {
                kind: PngTextKind::Text,
            }
            .label(),
            ContainerSlot::PngText {
                kind: PngTextKind::CompressedText,
            }
            .label(),
            ContainerSlot::PngText {
                kind: PngTextKind::InternationalText,
            }
            .label(),
            ContainerSlot::PngUnknownAncillary {
                chunk_type: "stEG".to_string(),
            }
            .label(),
            ContainerSlot::Trailing.label(),
        ];
        assert_eq!(labels[1], "JPEG APP1 segment");
        assert_eq!(labels[2], "PNG tEXt chunk");
        assert_eq!(labels[3], "PNG zTXt chunk");
        assert_eq!(labels[4], "PNG iTXt chunk");
        for label in &labels {
            assert!(!label.is_empty());
            assert!(!label.contains('_'), "{label} reads like an identifier");
        }
    }

    #[test]
    fn is_real_marker_rejects_stuffing_fill_and_restarts() {
        assert!(!is_real_marker(0x00));
        assert!(!is_real_marker(0xFF));
        for byte in 0xD0..=0xD7 {
            assert!(!is_real_marker(byte));
        }
        assert!(is_real_marker(0xD9));
        assert!(is_real_marker(0xC4));
    }

    // ── Path entry points ─────────────────────────────────────────────────

    #[test]
    fn scanning_a_real_file_from_disk_agrees_with_the_in_memory_walk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("carrier.jpg");
        let mut bytes = jpeg(&[(0xFE, flat_bytes(256))]);
        bytes.extend_from_slice(&flat_bytes(64));
        std::fs::write(&path, &bytes).expect("write fixture");

        let from_disk = scan_container(&path).expect("scan");
        assert_eq!(from_disk, scan(&bytes).findings);

        let detail = scan_container_detail(&path).expect("scan");
        assert_eq!(detail.format, ContainerFormat::Jpeg);
        assert!(detail.structure_ok);
    }

    #[test]
    fn a_missing_file_is_a_loud_file_not_found_error() {
        let err = scan_container(Path::new("/nonexistent/stegcore/container-test.png"))
            .expect_err("must fail");
        assert!(matches!(err, StegError::FileNotFound(_)));
        assert!(err.to_string().contains("File not found"));
    }

    #[test]
    fn a_directory_is_an_io_error_rather_than_a_panic() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = scan_container(dir.path());
        // Opening a directory succeeds on some platforms and reading it fails;
        // either way the module must surface an error rather than panic.
        if let Ok(findings) = result {
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn an_unsupported_file_on_disk_yields_an_empty_finding_list() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, b"this is not an image at all").expect("write");
        assert!(scan_container(&path).expect("scan").is_empty());
        assert_eq!(
            scan_container_detail(&path).expect("scan").format,
            ContainerFormat::Unsupported
        );
    }

    // ── The JPEG side of the caps, and I/O failure ────────────────────────

    #[test]
    fn the_findings_cap_also_bounds_the_jpeg_walk() {
        // The PNG walk has its own cap test; the JPEG walk has a separate
        // early-return and so needs its own, or one of the two could regress
        // silently.
        let segments: Vec<(u8, Vec<u8>)> = (0..MAX_REGIONS + 20)
            .map(|_| (0xFEu8, flat_bytes(32)))
            .collect();
        let result = scan(&jpeg(&segments));
        assert_eq!(result.findings.len(), MAX_REGIONS);
        assert!(result.limits_hit);
    }

    #[test]
    fn the_structure_step_cap_also_stops_the_jpeg_walk() {
        // Below the reporting floor, so the step cap rather than the findings
        // cap is what has to fire.
        let mut bytes = vec![0xFF, 0xD8, 0xFF];
        for _ in 0..MAX_STRUCTURE_STEPS + 10 {
            bytes.push(0xFE);
            bytes.extend_from_slice(&6u16.to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 0]);
            bytes.push(0xFF);
        }
        bytes.push(0xD9);
        let result = scan(&bytes);
        assert!(result.findings.is_empty());
        assert!(!result.structure_ok);
        assert!(result.limits_hit);
    }

    #[test]
    fn a_segment_whose_body_begins_exactly_at_eof_is_not_measured() {
        // A zero-length COM whose header is the last thing in the file. The
        // body offset equals the file length, so there is nothing to read and
        // nothing to index into.
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xFE];
        bytes.extend_from_slice(&2u16.to_be_bytes());
        let result = scan(&bytes);
        assert!(result.findings.is_empty());
        assert!(!result.structure_ok);
    }

    #[test]
    fn scan_data_beginning_exactly_at_eof_ends_the_walk_without_panicking() {
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xDA];
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0, 0, 0, 0]);
        let result = scan(&bytes);
        assert!(!result.structure_ok);
    }

    /// A reader that reports a length, survives one `Interrupted`, then fails.
    /// Interrupted is retried by the standard-library convention; a real error
    /// must propagate rather than be mistaken for end of file, because
    /// treating a failed read as EOF would silently shorten a scan.
    struct FailingReader {
        interrupted_once: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted_once {
                self.interrupted_once = true;
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            Err(io::Error::other("device fell over"))
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match pos {
                SeekFrom::End(_) => Ok(4096),
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn a_read_failure_is_surfaced_loudly_and_never_mistaken_for_end_of_file() {
        let err = scan_reader(FailingReader {
            interrupted_once: false,
        })
        .expect_err("a failing device must not look like a clean file");
        assert!(matches!(err, StegError::Io(_)));
        assert!(err.to_string().contains("device fell over"));
    }
}
