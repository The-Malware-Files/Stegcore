# Analysing files

Stegcore reads a file and tells you whether it looks like something is hidden
inside it. That's steganalysis, and it's the other half of the tool.

```bash
stegcore analyse suspect.png
```

You get a score per detector and one verdict: **Clean**, **Suspicious** or
**Likely stego**.

## Running it

```bash
# A folder. Quote the pattern so Stegcore expands it, not your shell
stegcore analyse --batch "*.png"

# A report you can send someone
stegcore analyse suspect.png --report html -o report.html
stegcore analyse --batch "*.png" --report csv -o scan.csv

# Machine readable
stegcore analyse suspect.png --json

# Watch a drop folder and analyse whatever lands in it
stegcore analyse --watch /tmp/incoming/
```

`stegcore analyse *.png` doesn't work: your shell turns that into several
arguments and the command takes one file. That's what `--batch` is for.

Stegcore decides how to read a file by its first few bytes rather than its
name, so a PNG called `cat.jpg` is still analysed as a PNG.

## Reading the verdict

| Verdict | What fired |
|---|---|
| Clean | No detector passed its threshold and no tool fingerprint matched |
| Suspicious | One calibrated detector fired, or a heuristic fingerprint matched |
| Likely stego | Several detectors fired, or an exact fingerprint matched |

A verdict is evidence, not proof. Clean means nothing above the threshold was
found, which is a different statement from nothing being there.

## What it catches, and what it doesn't

Stegcore is specific about this because a detector nobody can characterise is a
detector nobody should trust.

| | How it does |
|---|---|
| Spatial LSB replacement, moderate payload and up | Strong |
| Tools that leave a structural signature, OpenStego for one | Strong, and effectively decisive |
| Very small payloads | Weak. This is where classical steganalysis runs out |
| LSB matching | Weak |
| Hiding in JPEG DCT coefficients | Not covered |

The last three are limits of the classical detector family, not of this
implementation in particular. Anything claiming to be solid across all five
rows is worth a second look.

## Where the thresholds come from

Every detector's threshold is fitted against real clean photographs, never
picked by hand. The reference set is the union of Cassavia 2022, BOSSbase 1.01
and a sample of ALASKA2, and the target is a combined false-alarm rate of about
4% held on the worst of those sub-distributions rather than on the average.

Fitting on the average is how a detector ends up looking excellent in a paper
and firing constantly on somebody's holiday photos. An earlier calibration here
did exactly that, so the rule is now that the worst sub-distribution sets the
number.

Three of the detectors (Sample Pair Analysis, RS and Weighted Stego) are ports
of [Aletheia](https://github.com/daniellerch/aletheia), the public reference
implementation, and agree with it to floating-point precision on the test
corpus. Stegcore is allowed to be faster than Aletheia, about 24 times on the
RS path; it isn't allowed to give a different answer.

[The security model](security-model#steganalysis-suite) has the per-detector
breakdown and the fingerprint tiers.

## Checking it yourself

The numbers above are ours. Run it on your own clean images and see what the
false-alarm rate looks like on your material:

```bash
stegcore analyse --batch "your-images/*.png" --json > scores.json
```

Per-release detection figures, with the corpus and payload rates they were
measured at, are in the
[changelog](https://github.com/The-Malware-Files/Stegcore/blob/main/CHANGELOG.md).
