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

//! Inference backends: the implementations of [`crate::model::Backend`].
//!
//! Exactly one ships today, behind the `backend-tract` feature. The trait is
//! what matters: the decision is reversible by adding a sibling module, and
//! nothing above this layer names a runtime.
//!
//! # Why `tract` and not `ort`
//!
//! Measured on this crate's own tree rather than argued from reputation.
//!
//! | | `tract-onnx` 0.21 | `ort` (ONNX Runtime) |
//! |---|---|---|
//! | Transitive crates added | 88, measured: 43 without the feature, 131 with | fewer crates, plus one large prebuilt binary |
//! | Stripped binary, measured | 531 KB to 16.4 MB, so **+15.9 MB**, all of it statically linked | a small Rust shim plus a `libonnxruntime` of broadly the same order, shipped separately |
//! | Native toolchain | `cc` only, pulled by `tract-linalg` for its assembly kernels | a C++ runtime, either downloaded as a prebuilt library or built from source with CMake |
//! | Shipping shape | one file | a separate dynamic library that must travel with the installer on all three platforms |
//! | Supply-chain surface | pure Rust, lockfile-managed, visible to `cargo audit` | a prebuilt binary fetched at build time, which `cargo audit` cannot see inside |
//! | Speed | slower, single-threaded by default | faster, with GPU execution providers |
//! | Release build, measured | 5m 44s from cold at `-j 2` on the dev laptop | faster to build, slower to set up |
//!
//! The size row is **not** the argument, and it would be dishonest to present it
//! as one: 15.9 MB is a real cost and ONNX Runtime is not obviously smaller once
//! its library is counted. The measurement is here so nobody has to guess, and
//! so the figure quoted is one that was taken rather than assumed. The way to
//! shrink it is a release profile with `lto` and `panic = "abort"` on whatever
//! binary ships this, and that is a packaging decision, not a backend one.
//!
//! The deciding column is "shipping shape". Stegcore ships a Tauri desktop bundle on
//! Linux, macOS and Windows, and an inference runtime that has to be packaged
//! as a separate dynamic library turns one build problem into three packaging
//! problems, each of which fails in the user's installer rather than in CI. The
//! supply-chain row decides it twice over under baseline section 5: a
//! downloaded-at-build-time binary blob is exactly the dependency shape that
//! section exists to refuse, and no cooldown window or audit tool reaches
//! inside one.
//!
//! The costs accepted are speed and 15.9 MB. Inference here is a *tile* of 256 by 256 run
//! once per cover, on a detection path that already pays Argon2id at 128 MiB
//! elsewhere and already runs a classical ensemble, so the runtime is not the
//! term that dominates. If it ever becomes the term that dominates, `ort`
//! arrives as a second module behind a second feature, which is why `Backend`
//! is a trait with three small methods and no runtime type in its signature.
//!
//! What is **not** measured yet, and must not be claimed until it is: that
//! `tract-linalg`'s assembly kernels build under MSVC on the Windows runner.
//! The dependency tree was measured on Linux. See the report's "cannot measure
//! yet" list.

#[cfg(feature = "backend-tract")]
pub mod tract;
