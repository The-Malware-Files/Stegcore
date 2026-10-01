// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial

//! Measures what the inference backend costs in shipped bytes.
//!
//! Built twice, once with `--features backend-tract` and once without, and the
//! difference between the two stripped binaries is the number quoted in
//! `src/backend.rs`. It exists because "tract is small" is a claim, and this
//! crate's rule is that a claim in a doc comment has a measurement behind it.
//!
//! It is an example rather than a test so it links a real binary; an rlib's size
//! says nothing about what reaches a user.

fn main() {
    let path = std::env::args().nth(1);

    #[cfg(feature = "backend-tract")]
    {
        use detego_ml::representation::Domain;
        let Some(path) = path else {
            println!("usage: size-probe <graph.onnx>");
            return;
        };
        let bytes = std::fs::read(&path).expect("read graph");
        match detego_ml::backend::tract::TractBackend::from_onnx(&bytes, Domain::Spatial, 256) {
            Ok(b) => println!("loaded {path}: {b:?}"),
            Err(e) => println!("refused {path}: {e}"),
        }
    }

    #[cfg(not(feature = "backend-tract"))]
    {
        // Still touches the crate, so the no-backend build is not optimised down
        // to nothing and the comparison stays honest.
        let card = detego_ml::ModelCard::from_json(path.as_deref().unwrap_or("{}"));
        println!("no backend compiled in; card parse said {:?}", card.is_ok());
    }
}
