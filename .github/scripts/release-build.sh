#!/usr/bin/env bash
# Build and stage one release artifact per explicit target CPU.
set -euo pipefail

target="${1:?target}"
binary="${2:?binary}"
shift 2
if [[ $# -eq 0 ]]; then
  echo "usage: release-build.sh <target> <binary> <cpu>..." >&2
  exit 1
fi
cpus=("$@")

for cpu in "${cpus[@]}"; do
  if [[ "${cpu}" == "native" ]]; then
    echo "target-cpu=native is forbidden for release artifacts" >&2
    exit 1
  fi
done

export CARGO_INCREMENTAL=0
for cpu in "${cpus[@]}"; do
  export RUSTFLAGS="-Ctarget-cpu=${cpu}"
  cargo build --release --locked --target "${target}" -p snell
  stage="target/release-artifacts/${target}/${cpu}"
  mkdir -p "${stage}"
  cp "target/${target}/release/${binary}" "${stage}/${binary}"
done
