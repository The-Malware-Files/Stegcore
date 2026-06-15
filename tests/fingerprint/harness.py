#!/usr/bin/env python3
"""Permanent fingerprint validation harness for Stegcore.

Generates noise covers procedurally, embeds payloads with each *real* tool,
runs the engine over the results, and asserts:

  TPR         — each tool's stego matches its own fingerprint.
  FPR         — a clean cover matches no fingerprint.
  Specificity — tool A's stego does not trip tool B's fingerprint.

Procedural noise covers keep the run deterministic and committable without any
image fixtures in the repo. cv2 + numpy come from the venv-lsbsteg interpreter.

Modes:
  --smoke  one cover × one payload per tool — for CI (deterministic, ~20 s).
  --full   broader sweep (multiple cover formats, payload sizes) — local only.

Tools verified (each is skipped if absent):
  LSBSteg   — private/tools/LSB-Steganography/LSBSteg.py (committed in private/)
  Steghide  — system `steghide`
  OpenStego — jar at $STEGOBENCH_OPENSTEGO_JAR or vendor/openstego.jar

Run from anywhere with the venv-lsbsteg python:

  ./private/steganalysis/venv-lsbsteg/bin/python tests/fingerprint/harness.py --smoke
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BIN = REPO / "target" / "release" / "stegcore"
LSBSTEG_TOOL = REPO / "private" / "tools" / "LSB-Steganography" / "LSBSteg.py"
LSBSTEG_PY = REPO / "private" / "steganalysis" / "venv-lsbsteg" / "bin" / "python"
OPENSTEGO_JAR = Path(
    os.environ.get("STEGOBENCH_OPENSTEGO_JAR", str(REPO / "vendor" / "openstego.jar"))
)


@dataclass
class Result:
    tool: str
    cover_fmt: str
    seed: int
    payload_bytes: int
    fingerprint: str | None
    expected: str | None
    passed: bool
    note: str = ""


def make_cover(seed: int, w: int, h: int, fmt: str, out_dir: Path) -> Path:
    """Procedural noise cover — deterministic from `seed`."""
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, (h, w, 3), dtype=np.uint8)
    path = out_dir / f"cover_{seed}_{w}x{h}.{fmt}"
    if fmt == "jpg":
        cv2.imwrite(str(path), arr, [cv2.IMWRITE_JPEG_QUALITY, 92])
    else:
        cv2.imwrite(str(path), arr)
    return path


def lsbsteg_embed(cover: Path, payload: Path, out: Path) -> None:
    # LSBSteg.py's main() does `out_f.split(".")` and only re-appends `.png`
    # when the requested extension is "lossy" — passing `.png` directly strips
    # the extension before cv2.imwrite, which then silently fails. Workaround:
    # pass `.jpg` and let LSBSteg rewrite the path to `.png` itself.
    call_out = out.with_suffix(".jpg")
    subprocess.run(
        [str(LSBSTEG_PY), str(LSBSTEG_TOOL), "encode",
         "-i", str(cover), "-o", str(call_out), "-f", str(payload)],
        check=True, capture_output=True,
    )
    # When `out` is .png, LSBSteg writes to exactly that path — nothing to do.
    if not out.exists():
        produced = call_out.with_suffix(".png")
        if produced.exists():
            os.rename(produced, out)


def steghide_embed(cover: Path, payload: Path, out: Path) -> None:
    subprocess.run(
        ["steghide", "embed", "-cf", str(cover), "-ef", str(payload),
         "-sf", str(out), "-p", "testpass", "-q", "-f"],
        check=True, capture_output=True,
    )


def openstego_embed(cover: Path, payload: Path, out: Path) -> None:
    # No password: OpenStego's default RandomLSB plugin then seeds its bit
    # scatter from the fixed constant 98234782 (StringUtil.passwordHash("")),
    # which is exactly the seed check_openstego replays. A password would seed
    # from an MD5 we cannot predict, so that case is (by design) not detected.
    subprocess.run(
        ["java", "-jar", str(OPENSTEGO_JAR), "embed",
         "-mf", str(payload), "-cf", str(cover), "-sf", str(out)],
        check=True, capture_output=True,
    )


# The three v4.1 fingerprints below key on deterministic structural artefacts,
# so the harness reproduces those artefacts directly from the catalogued spec
# rather than driving the original (often Windows-only) tools. This tests the
# DETECTOR, which is the point; real-sample validation is tracked separately.

def append_embed(cover: Path, payload: Path, out: Path) -> None:
    """Append-after-EOF class: concatenate the payload past the carrier's end."""
    extra = payload.read_bytes()
    if len(extra) < 16:
        extra += b"\0" * (16 - len(extra))
    out.write_bytes(cover.read_bytes() + extra)


def camouflage_embed(cover: Path, payload: Path, out: Path) -> None:
    """Camouflage: append its `00 00 XX ED CD 01` signature blob after the
    carrier (signature verified against zsteg's reference sample)."""
    blob = b"\x00\x00\x42\xed\xcd\x01" + payload.read_bytes()
    out.write_bytes(cover.read_bytes() + blob)


def f5_embed(cover: Path, payload: Path, out: Path) -> None:
    """F5: stamp the James/Weeks JpegEncoder COM comment into the JPEG (the
    structural tell check_f5 keys on). The payload is not used; the comment is
    the fingerprint."""
    data = cover.read_bytes()
    marker = b"JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech"
    com = b"\xff\xfe" + (len(marker) + 2).to_bytes(2, "big") + marker
    out.write_bytes(data[:2] + com + data[2:])  # COM right after SOI


def analyse(path: Path) -> dict:
    r = subprocess.run(
        [str(BIN), "analyse", str(path), "--json"],
        capture_output=True, text=True, timeout=30,
    )
    return json.loads(r.stdout)["data"][0]


def fp_of(d: dict) -> str | None:
    return d.get("tool_fingerprint")


def make_payload(out: Path, n: int) -> None:
    out.write_bytes(b"x" * n)


# Per-tool expected fingerprint LABEL prefix. None means "the engine should
# return no fingerprint" — currently Steghide (the offset-0 magic check was
# dead code; proper detection deferred to v4.1+ as tech-debt T-14).
EXPECT = {
    "lsbsteg": "LSBSteg",
    # check_openstego (v4.1) replays OpenStego's java.util.Random bit scatter
    # to reconstruct the OPENSTEGO header magic — fires on the no-password
    # default embed (closed T-27). Password-seeded embeds stay undetectable.
    "openstego": "OpenStego",
    # check_steghide dropped in v4.0.1 — offset-0 magic check was dead code;
    # seed-brute-force detector deferred to v4.1+ (T-26).
    "steghide": None,
    # v4.1 structural fingerprints (synthetic embedders above).
    "camouflage": "Camouflage",
    "append": "appended data after EOF",
    "f5": "F5",
}

EMBEDDERS = {
    # tool name -> (embedder fn, list of cover formats to test)
    "lsbsteg": (lsbsteg_embed, ["png"]),
    "steghide": (steghide_embed, ["jpg", "bmp"]),
    "openstego": (openstego_embed, ["png"]),
    "camouflage": (camouflage_embed, ["png", "jpg"]),
    "append": (append_embed, ["png", "jpg"]),
    "f5": (f5_embed, ["jpg"]),
}


def have_tool(name: str) -> bool:
    if name == "lsbsteg":
        return LSBSTEG_TOOL.exists() and LSBSTEG_PY.exists()
    if name == "openstego":
        return OPENSTEGO_JAR.exists()
    if name == "steghide":
        return subprocess.run(["which", "steghide"], capture_output=True).returncode == 0
    # Synthetic structural embedders need no external tool.
    if name in ("camouflage", "append", "f5"):
        return True
    return False


def run_tpr(tool: str, fmt: str, seed: int, payload_size: int,
            workdir: Path) -> tuple[Result, Path | None]:
    """Generate stego with `tool`, analyse, return (result, stego_path)."""
    cover = make_cover(seed, 512, 512, fmt, workdir)
    payload = workdir / f"payload_{payload_size}.bin"
    make_payload(payload, payload_size)
    stego_ext = "png" if tool == "lsbsteg" else fmt
    stego = workdir / f"stego_{tool}_{fmt}_{seed}_{payload_size}.{stego_ext}"
    embedder, _ = EMBEDDERS[tool]
    try:
        embedder(cover, payload, stego)
    except subprocess.CalledProcessError as e:
        return (
            Result(tool=tool, cover_fmt=fmt, seed=seed,
                   payload_bytes=payload_size, fingerprint=None,
                   expected=EXPECT[tool], passed=False,
                   note=f"embed failed: {e.stderr[:60].decode(errors='replace')}"),
            None,
        )
    fp = fp_of(analyse(stego))
    expected = EXPECT[tool]
    if expected is None:
        ok = fp is None
        note = "no fp (expected)" if ok else "expected no fp"
    else:
        ok = fp is not None and fp.startswith(expected)
        note = "matched" if ok else "TPR fail"
    return (
        Result(tool=tool, cover_fmt=fmt, seed=seed,
               payload_bytes=payload_size, fingerprint=fp,
               expected=expected, passed=ok, note=note),
        stego,
    )


def run_fpr(fmt: str, seed: int, workdir: Path) -> Result:
    """Clean noise cover must match no fingerprint."""
    cover = make_cover(seed, 512, 512, fmt, workdir)
    fp = fp_of(analyse(cover))
    ok = fp is None
    return Result(tool="(clean)", cover_fmt=fmt, seed=seed,
                  payload_bytes=0, fingerprint=fp, expected=None,
                  passed=ok, note="clean" if ok else "spurious fp")


def run_specificity(producer: str, stego_path: Path) -> Result:
    """Stego from `producer` must not trip a *different* tool's fingerprint."""
    fp = fp_of(analyse(stego_path))
    expected_self = EXPECT[producer]
    if fp is None:
        ok, note = True, "no fp (ok)"
    elif expected_self and fp.startswith(expected_self):
        ok, note = True, "own fp (ok)"
    else:
        ok, note = False, f"cross-tool: {producer} → {fp}"
    return Result(tool=f"cross:{producer}", cover_fmt="(reused)", seed=-1,
                  payload_bytes=0, fingerprint=fp, expected=expected_self,
                  passed=ok, note=note)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true",
                    help="quick deterministic run, suitable for CI")
    ap.add_argument("--full", action="store_true",
                    help="broader sweep — multiple cover formats, payload sizes")
    args = ap.parse_args()
    if not args.smoke and not args.full:
        args.smoke = True

    if not BIN.exists():
        sys.exit(f"engine binary not built: {BIN}\n"
                 f"build with: cargo build --release --bin stegcore")

    workdir = Path(tempfile.mkdtemp(prefix="stegcore-fp-"))
    results: list[Result] = []
    stegos: dict[str, Path] = {}

    tool_status = {t: have_tool(t) for t in EMBEDDERS}
    print("Tools:")
    for t, ok in tool_status.items():
        print(f"  {t:10} {'available' if ok else 'MISSING (skipping)'}")
    print(f"\nMode: {'smoke' if args.smoke else 'full'}\nWorkdir: {workdir}\n")

    if args.smoke:
        seeds, payload_sizes = [42], [256]
    else:
        seeds, payload_sizes = [42, 137], [256, 4096]

    # 1) TPR — each tool's stego must match its own fingerprint
    for tool, (_, fmts) in EMBEDDERS.items():
        if not tool_status[tool]:
            continue
        for seed in seeds:
            for fmt in fmts:
                for pl in payload_sizes:
                    r, stego = run_tpr(tool, fmt, seed, pl, workdir)
                    results.append(r)
                    if r.passed and stego and tool not in stegos:
                        stegos[tool] = stego

    # 2) FPR — clean noise covers must match nothing
    for fmt in ("png", "bmp", "jpg"):
        for seed in seeds:
            results.append(run_fpr(fmt, seed + 1000, workdir))

    # 3) Specificity — each tool's stego must not trip a different tool's fp
    for producer, stego in stegos.items():
        results.append(run_specificity(producer, stego))

    # ---- report ----------------------------------------------------------
    hdr = f"{'tool':14} {'fmt':5} {'pld':>6} {'expect':10} {'fingerprint':36} {'note':22} ok"
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        fp_disp = (r.fingerprint or "—")[:36]
        exp_disp = (r.expected or "(none)")[:10]
        tick = "✓" if r.passed else "✗"
        print(f"{r.tool:14} {r.cover_fmt:5} {r.payload_bytes:>6} "
              f"{exp_disp:10} {fp_disp:36} {r.note:22} {tick}")

    passed = sum(1 for r in results if r.passed)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
