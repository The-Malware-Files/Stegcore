# Fingerprint validation harness

Permanent verification that each `check_<tool>()` fingerprint in
[`crates/engine/src/analysis.rs`](../../crates/engine/src/analysis.rs)
actually fires on real tool output (TPR), doesn't fire on clean covers (FPR),
and doesn't collide with other tools' fingerprints (specificity).

## Run

From the repo root (the venv has the cv2 + numpy used for procedural covers):

```bash
./private/steganalysis/venv-lsbsteg/bin/python tests/fingerprint/harness.py --smoke
```

Modes:

- `--smoke` (default); one cover × one payload per tool. ~20 seconds. Suitable for CI.
- `--full`; multiple cover formats and payload sizes. Local only.

## Why procedural noise covers

The harness generates covers from numpy seeds; no image fixtures are
committed to the repo. Noise covers are appropriate for *fingerprint* testing
(structural checks on specific bytes / LSBs, not statistical detection) and
keep the run fully deterministic and CI-friendly.

## Tools

| Tool | Where | Status |
|---|---|---|
| LSBSteg | `private/tools/LSB-Steganography/LSBSteg.py` | required |
| Steghide | system `steghide` (apt) | required for steghide tests |
| OpenStego | `$STEGOBENCH_OPENSTEGO_JAR` or `vendor/openstego.jar` | optional; skipped if absent |

Each tool is checked at runtime; missing ones are reported and skipped, not
errors.

## What it asserts

| Check | Pass condition |
|---|---|
| TPR  | Each tool's stego matches the expected fingerprint label |
| FPR  | Clean noise covers (PNG, BMP, JPG) match no fingerprint |
| Specificity | Tool A's stego must not trip Tool B's fingerprint |

## Expected outcomes (v4.0.1)

| Tool | Fingerprint expected |
|---|---|
| LSBSteg | `LSBSteg (heuristic match)` |
| OpenStego | `OpenStego (exact signature)` |
| Steghide | **none**; `check_steghide` was removed because the offset-0 magic check never fired against real Steghide output. Proper structural detection requires seed brute-force, which is the path of the planned `stegcore brute-force` standalone command on the roadmap. The harness asserts no fingerprint is produced. |

## CI

Not wired up yet; keeping GitHub Actions minutes deliberate. The `--smoke`
mode is designed to be the eventual CI invocation when budget is allocated:
deterministic, ~20 s, requires only `apt install steghide` plus the committed
`LSBSteg.py` (OpenStego skipped if the jar isn't provisioned).
