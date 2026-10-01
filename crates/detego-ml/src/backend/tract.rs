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

//! `tract` implementation of [`Backend`].
//!
//! # The fixed-shape decision
//!
//! `tract` optimises a graph against a concrete input shape, so this backend is
//! built for one shape and refuses any other. That is not a limitation worked
//! around; it is the behaviour wanted. Both architectures were trained on a
//! fixed crop, the card's operating points were measured at that crop, and a
//! tensor of a different size would be scored against thresholds that were
//! never measured for it. [`crate::representation::Representation::tiles`] is
//! how a larger cover reaches this backend, one trained-geometry tile at a
//! time.
//!
//! # What the graph can and cannot be checked for
//!
//! Read back from the ONNX file: the input layer's channel count. That catches
//! a card claiming [`Domain::Spatial`] over a 64 plane graph, which is the
//! mismatch that would otherwise produce a confident number from nonsense.
//!
//! Not readable from the file: which of the two DCT domains a 64 plane graph
//! was trained on, because quantised and dequantised coefficients have the same
//! shape and differ only in scale. That distinction rests on the card, and the
//! envelope's `zero_fraction` range is what catches it in practice: dequantised
//! coefficients have a visibly different zero fraction, so a mismatched pair
//! declines as out of distribution rather than answering wrongly. Stated here
//! because an unverifiable claim that reads as verified is worse than an
//! acknowledged gap.

use std::io::Cursor;

use tract_onnx::prelude::*;
// `concretize` lives on the `Factoid` trait, which the prelude does not re-export.
use tract_onnx::tract_hir::infer::Factoid;

use crate::error::{MlError, Result};
use crate::model::Backend;
use crate::representation::{Domain, Representation};

type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// A loaded, optimised graph pinned to one input shape.
pub struct TractBackend {
    plan: Plan,
    domain: Domain,
    shape: [usize; 3],
}

impl TractBackend {
    /// Load an ONNX graph for one domain and one cover crop side.
    ///
    /// `cover_side` is in cover pixels, matching
    /// [`crate::model::ModelCard::input_side`]; the tensor side is derived from
    /// the domain so the two can never be confused at a call site.
    ///
    /// Takes bytes, not a path: nothing on the inference path touches the
    /// filesystem, so the caller keeps the IO policy and this is testable from a
    /// byte literal.
    pub fn from_onnx(onnx: &[u8], domain: Domain, cover_side: u32) -> Result<Self> {
        let side = domain.tensor_side(cover_side);
        if side == 0 {
            return Err(MlError::Backend(format!(
                "a cover side of {cover_side} pixels is smaller than one {} unit",
                domain.name()
            )));
        }
        let channels = domain.channels();

        let fail = |stage: &str, e: tract_onnx::prelude::TractError| {
            MlError::Backend(format!("{stage}: {e}"))
        };

        let mut cursor = Cursor::new(onnx);
        let inference = tract_onnx::onnx()
            .model_for_read(&mut cursor)
            .map_err(|e| fail("the ONNX graph could not be parsed", e))?;

        let declared = Self::input_channels(&inference);
        if let Some(got) = declared {
            if got != channels {
                return Err(MlError::RepresentationMismatch {
                    expected: domain.name(),
                    actual: if got == 1 {
                        "a single channel graph"
                    } else {
                        "a graph with a different channel count"
                    },
                });
            }
        }

        let plan = inference
            .with_input_fact(0, f32::fact([1, channels, side, side]).into())
            .map_err(|e| fail("the graph rejected the input shape this card declares", e))?
            .into_optimized()
            .map_err(|e| fail("the graph could not be optimised", e))?
            .into_runnable()
            .map_err(|e| fail("the optimised graph could not be made runnable", e))?;

        Ok(Self {
            plan,
            domain,
            shape: [channels, side, side],
        })
    }

    /// Channel count of input 0 where the file states it, `None` where the graph
    /// leaves it symbolic. A symbolic input is not an error: an exporter is
    /// allowed to leave the batch and spatial dimensions free, and this check is
    /// a cross-check rather than the only guard.
    fn input_channels(model: &InferenceModel) -> Option<usize> {
        let outlet = *model.input_outlets().ok()?.first()?;
        let fact = model.outlet_fact(outlet).ok()?;
        // NCHW, so index 1. `dim` rather than a whole-shape concretisation
        // because an exporter is entitled to leave the batch dimension
        // symbolic, and demanding a fully concrete shape would turn this
        // cross-check off for exactly the graphs that have it.
        let dim = fact.shape.dim(1)?.concretize()?;
        let n = dim.as_i64()?;
        usize::try_from(n).ok()
    }

    /// The exact tensor shape this backend accepts, excluding the batch
    /// dimension. Public so a caller can tile to it without re-deriving it.
    pub fn shape(&self) -> [usize; 3] {
        self.shape
    }
}

impl std::fmt::Debug for TractBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TractBackend")
            .field("domain", &self.domain)
            .field("shape", &self.shape)
            .finish()
    }
}

impl Backend for TractBackend {
    fn logit(&self, input: &Representation) -> Result<f64> {
        if input.domain() != self.domain {
            return Err(MlError::RepresentationMismatch {
                expected: self.domain.name(),
                actual: input.domain().name(),
            });
        }
        if input.shape() != self.shape {
            let [_, h, w] = input.shape();
            return Err(MlError::TooSmall {
                got: w as u32,
                got_h: h as u32,
                need: self.shape[1] as u32,
            });
        }

        let [c, h, w] = self.shape;
        let tensor = Tensor::from_shape(&[1, c, h, w], input.data())
            .map_err(|e| MlError::Backend(format!("the input tensor could not be built: {e}")))?;
        let out = self
            .plan
            .run(tvec!(tensor.into()))
            .map_err(|e| MlError::Backend(format!("inference failed: {e}")))?;
        let first = out
            .first()
            .ok_or_else(|| MlError::Backend("the graph returned no output".to_string()))?;
        let view = first
            .to_array_view::<f32>()
            .map_err(|e| MlError::Backend(format!("the output is not f32: {e}")))?;
        let values: Vec<f32> = view.iter().copied().collect();

        // Both shapes the export script can produce are accepted, because
        // pinning one would make the Rust side and the Python side disagree over
        // a detail neither cares about. Two values is a class pair, so the logit
        // is their difference; one value is already the logit.
        match values.len() {
            1 => Ok(values[0] as f64),
            2 => Ok((values[1] - values[0]) as f64),
            n => Err(MlError::Backend(format!(
                "the graph produced {n} outputs; a presence detector returns one logit or a pair \
                 of class scores"
            ))),
        }
    }

    fn graph_domain(&self) -> Domain {
        self.domain
    }

    fn backend_name(&self) -> &'static str {
        "tract-onnx"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_onnx_is_refused_with_a_reason() {
        let err = TractBackend::from_onnx(b"not an onnx graph", Domain::Spatial, 256).unwrap_err();
        match err {
            MlError::Backend(d) => assert!(d.contains("could not be parsed"), "{d}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    /// Three graphs exported from PyTorch on the ROG on 2026-10-01 by
    /// `scratchpad/mk_onnx.sh`, each a frozen high-pass front end, one trainable
    /// convolution, global average pooling and a linear head. They are
    /// deliberately tiny (1 KB and 12 KB) and synthetic, so CI can prove this
    /// backend executes a real ONNX graph without torch, a corpus or a trained
    /// model being present. The expected numbers below came from the same torch
    /// session that wrote the files.
    const SPATIAL_2CLASS: &[u8] = include_bytes!("../../tests/assets/tiny-spatial-2class.onnx");
    const SPATIAL_1LOGIT: &[u8] = include_bytes!("../../tests/assets/tiny-spatial-1logit.onnx");
    const DCT_2CLASS: &[u8] = include_bytes!("../../tests/assets/tiny-dct-2class.onnx");

    /// The same integer ramp the torch side evaluated, so the two numbers are
    /// comparable. An integer modulo then an f32 divide reproduces bit for bit
    /// in either language, which a floating-point generator would not.
    fn ramp(domain: Domain, channels: usize, side: usize) -> Representation {
        let mut data = Vec::with_capacity(channels * side * side);
        for c in 0..channels {
            for y in 0..side {
                for x in 0..side {
                    let v = ((c * 7 + y * 13 + x * 29) % 251) as f32;
                    data.push(v / 255.0 - 0.5);
                }
            }
        }
        Representation::new(domain, data, channels, side, side).expect("ramp")
    }

    #[test]
    fn a_two_class_spatial_graph_produces_the_logit_torch_produced() {
        let b = TractBackend::from_onnx(SPATIAL_2CLASS, Domain::Spatial, 256).expect("load");
        assert_eq!(b.backend_name(), "tract-onnx");
        assert_eq!(b.graph_domain(), Domain::Spatial);
        assert_eq!(b.shape(), [1, 256, 256]);
        let got = b.logit(&ramp(Domain::Spatial, 1, 256)).expect("logit");
        // torch: raw [0.004062721971422434, -0.002456625923514366], so the class
        // difference is -0.0065193478949368. The tolerance is the same 1e-5 the
        // export script asserts its own round trip to.
        assert!(
            (got - -0.006_519_347_894_936_8).abs() < 1e-5,
            "tract gave {got}, torch gave -0.0065193478949368"
        );
    }

    #[test]
    fn a_single_logit_head_is_read_as_the_logit_itself() {
        let b = TractBackend::from_onnx(SPATIAL_1LOGIT, Domain::Spatial, 256).expect("load");
        let got = b.logit(&ramp(Domain::Spatial, 1, 256)).expect("logit");
        assert!(
            (got - -0.000_576_795_777_305_960_7).abs() < 1e-5,
            "tract gave {got}"
        );
    }

    #[test]
    fn a_sixty_four_plane_dct_graph_runs_at_a_thirty_two_element_side() {
        // 256 cover pixels is 32 DCT blocks, which is the unit confusion this
        // backend exists to make impossible at a call site.
        let b = TractBackend::from_onnx(DCT_2CLASS, Domain::JpegDctQuantised, 256).expect("load");
        assert_eq!(b.shape(), [64, 32, 32]);
        let got = b
            .logit(&ramp(Domain::JpegDctQuantised, 64, 32))
            .expect("logit");
        assert!(
            (got - 0.025_343_827_437_609_434).abs() < 1e-5,
            "tract gave {got}"
        );
    }

    #[test]
    fn running_the_spatial_graph_is_deterministic() {
        // Baseline reproducibility: two runs on one input agree exactly, not
        // approximately. If tract ever picks a kernel by timing this fails.
        let b = TractBackend::from_onnx(SPATIAL_2CLASS, Domain::Spatial, 256).expect("load");
        let input = ramp(Domain::Spatial, 1, 256);
        assert_eq!(b.logit(&input).unwrap(), b.logit(&input).unwrap());
    }

    #[test]
    fn a_card_claiming_the_wrong_domain_for_the_graph_is_caught_at_load() {
        // The 64 plane graph presented as a spatial model. This is the mismatch
        // that would otherwise yield a confident number from nonsense.
        let err = TractBackend::from_onnx(DCT_2CLASS, Domain::Spatial, 256).unwrap_err();
        assert!(
            matches!(err, MlError::RepresentationMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_tensor_of_the_wrong_size_is_refused_rather_than_reshaped() {
        let b = TractBackend::from_onnx(SPATIAL_2CLASS, Domain::Spatial, 256).expect("load");
        let err = b.logit(&ramp(Domain::Spatial, 1, 128)).unwrap_err();
        assert!(
            matches!(err, MlError::TooSmall { need: 256, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_tensor_from_the_other_domain_is_refused_even_at_the_right_size() {
        let b = TractBackend::from_onnx(DCT_2CLASS, Domain::JpegDctQuantised, 256).expect("load");
        let mut t = ramp(Domain::JpegDctQuantised, 64, 32);
        t = Representation::new(Domain::JpegDctDequantised, t.data().to_vec(), 64, 32, 32).unwrap();
        let err = b.logit(&t).unwrap_err();
        assert!(
            matches!(err, MlError::RepresentationMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_cover_side_below_one_dct_block_is_refused_rather_than_rounded_to_zero() {
        let err = TractBackend::from_onnx(b"", Domain::JpegDctQuantised, 4).unwrap_err();
        match err {
            MlError::Backend(d) => assert!(d.contains("smaller than one"), "{d}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
