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

//! Stegcore engine — adaptive LSB, deniable dual-payload, steganalysis suite.

pub mod analysis;
pub mod audio_analysis;
pub mod bruteforce;
pub mod container;
pub mod covert;
pub mod crypto;
pub mod dct_analysis;
pub mod errors;
pub mod fingerprints;
pub mod forensics;
pub mod jpeg_dct;
pub mod keyfile;
pub mod repro;
pub mod secmem;
pub mod slotseed;
pub mod steg;
pub mod utils;
pub mod watermark;
mod wav;
pub mod wild;
pub mod workflow;
