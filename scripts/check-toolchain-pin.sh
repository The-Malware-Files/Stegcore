#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Malware Files
#
# Every place that names a Rust version must name the same one.
#
# rust-toolchain.toml is the source of truth, but GitHub Actions refs and a
# Dockerfile FROM line cannot read it, so they repeat the version. This checks
# that the repetition still agrees. It exists because the repetition had
# already drifted: CI linted on 1.98 while the image we ship to users was
# built by 1.88, and nothing said so.
set -uo pipefail

cd "$(dirname "$0")/.."

fail=0
note() { printf '  %-58s %s\n' "$1" "$2"; }

want=$(grep -oP '^channel\s*=\s*"\K[^"]+' rust-toolchain.toml)
if [ -z "$want" ]; then
  echo "cannot read a channel from rust-toolchain.toml, so nothing can be checked" >&2
  exit 2
fi
echo "rust-toolchain.toml pins $want. Checking everything that repeats it."

# Workflow action refs. A ref of @stable or @nightly is a floating toolchain
# and is the thing this check exists to prevent, so it fails loudly rather
# than being reported as a mismatch.
while IFS= read -r line; do
  file=${line%%:*}
  ref=$(printf '%s' "$line" | grep -oP 'dtolnay/rust-toolchain@\K[^\s]+')
  if [ "$ref" = "$want" ]; then
    note "$file" "ok"
  elif [ "$ref" = "stable" ] || [ "$ref" = "nightly" ]; then
    note "$file" "FLOATING (@$ref)"
    fail=1
  else
    note "$file" "MISMATCH (@$ref)"
    fail=1
  fi
done < <(grep -rn 'dtolnay/rust-toolchain@' .github/workflows/ | grep -v 'toolchain-drift.yml')

# The drift workflow is deliberately floating and is excluded above. If it
# ever stops being floating it is no longer doing its job, so that is checked
# in the opposite direction.
if [ -f .github/workflows/toolchain-drift.yml ]; then
  if grep -q 'dtolnay/rust-toolchain@stable' .github/workflows/toolchain-drift.yml; then
    note ".github/workflows/toolchain-drift.yml" "ok (floating on purpose)"
  else
    note ".github/workflows/toolchain-drift.yml" "NOT FLOATING, so it warns of nothing"
    fail=1
  fi
fi

# The Docker builder base.
base=$(grep -oP '^FROM rust:\K[^ ]+' docker/Dockerfile | head -1)
if [ "$base" = "${want}-slim" ]; then
  note "docker/Dockerfile" "ok"
else
  note "docker/Dockerfile" "MISMATCH (rust:$base, wanted rust:${want}-slim)"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<EOF

The Rust version is not the same everywhere. Set every place above to $want,
or change rust-toolchain.toml if the intent was to move the pin.
EOF
  exit 1
fi
echo "all pins agree on $want"
