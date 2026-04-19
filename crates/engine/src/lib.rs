// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

//! Stegcore engine — adaptive LSB, deniable dual-payload, steganalysis suite.

pub mod analysis;
pub mod crypto;
pub mod errors;
pub mod jpeg_dct;
pub mod keyfile;
pub mod steg;
pub mod utils;
