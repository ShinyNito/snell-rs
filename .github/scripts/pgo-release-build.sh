#!/usr/bin/env bash
# Two-pass LLVM PGO for snell-rs: pgo-release-build.sh <target> <binary> <cpu>...
# Trains the pgo_train workload once, then builds one artifact per cpu.
# target-cpu=native is forbidden: artifacts must run on machines other than the builder.
#
# The instrumented pass is built at a portable target-cpu for the target's
# architecture so the training workload can always run on the builder, even
# when an artifact cpu is newer than the builder (x86-64-v3/v4 artifacts on
# baseline runners, x86_64 macOS artifacts trained under Rosetta 2). LLVM
# profiles are keyed by function, not by target-cpu, so the final
# profile-use builds apply the one merged profile at each artifact cpu.
#
# Each final binary is staged at pgo-data/bin/<cpu>/<binary> with its PGO
# status alongside at pgo-data/bin/<cpu>/PGO.
set -euo pipefail

target="${1:?target}"
binary="${2:?binary}"
shift 2
if [[ $# -eq 0 ]]; then
  echo "usage: pgo-release-build.sh <target> <binary> <cpu>..." >&2
  exit 1
fi
cpus=("$@")

for cpu in "${cpus[@]}"; do
  if [[ "${cpu}" == "native" ]]; then
    echo "target-cpu=native is forbidden for release artifacts" >&2
    exit 1
  fi
done

case "${target}" in
  x86_64-*) train_cpu="x86-64" ;;
  aarch64-apple-*) train_cpu="apple-m1" ;;
  *) train_cpu="generic" ;;
esac

pgo="${PWD}/pgo-data"
rm -rf "${pgo}"
mkdir -p "${pgo}"

sysroot="$(rustc --print sysroot)"
sysroot="${sysroot//\\//}"
host="$(rustc -vV | awk '/^host:/{print $2}')"
rustc_pgo="${pgo}"
if [[ "${host}" == *-pc-windows-* ]]; then
  rustc_pgo="$(cygpath -m "${pgo}")"
fi
profdata="${sysroot}/lib/rustlib/${host}/bin/llvm-profdata"
if [[ ! -x "${profdata}" && -x "${profdata}.exe" ]]; then
  profdata="${profdata}.exe"
fi
if [[ ! -x "${profdata}" ]]; then
  echo "llvm-profdata not found at ${profdata} (need rustup component llvm-tools-preview)" >&2
  exit 1
fi

export CARGO_INCREMENTAL=0
bin="${PWD}/target/${target}/release/${binary}"

# build_final <cpu> <status> [extra rustflags...]
build_final() {
  local cpu="$1" status="$2"
  shift 2
  export RUSTFLAGS="-Ctarget-cpu=${cpu}${*:+ $*}"
  cargo build --release --locked --target "${target}" -p snell
  mkdir -p "${pgo}/bin/${cpu}"
  cp "${bin}" "${pgo}/bin/${cpu}/${binary}"
  echo "${status}" >"${pgo}/bin/${cpu}/PGO"
}

export CARGO_PROFILE_RELEASE_STRIP=none
export RUSTFLAGS="-Ctarget-cpu=${train_cpu} -Cprofile-generate=${rustc_pgo}"
cargo build --release --locked --target "${target}" -p snell

if [[ ! -f "${bin}" ]]; then
  echo "missing instrumented binary ${bin}" >&2
  exit 1
fi

if ! "${bin}" version >/dev/null 2>&1; then
  echo "::warning::PGO skipped for ${target}: instrumented binary at train cpu ${train_cpu} cannot run on this builder"
  unset CARGO_PROFILE_RELEASE_STRIP
  for cpu in "${cpus[@]}"; do
    build_final "${cpu}" "skipped: instrumented binary cannot run on this builder"
  done
  exit 0
fi

export LLVM_PROFILE_FILE="${rustc_pgo}/snell-%p-%m.profraw"

cargo test --release --locked --target "${target}" -p snell-runtime --bench pgo_train

shopt -s nullglob
raws=("${pgo}"/*.profraw)
if [[ ${#raws[@]} -eq 0 ]]; then
  echo "PGO produced no .profraw files" >&2
  exit 1
fi
"${profdata}" merge -o "${pgo}/merged.profdata" "${raws[@]}"
covered="$("${profdata}" show --covered "${pgo}/merged.profdata")"
for crate in snell_runtime snell_protocol; do
  if ! grep -q "${crate}" <<<"${covered}"; then
    echo "PGO profile does not cover ${crate}" >&2
    exit 1
  fi
done

unset CARGO_PROFILE_RELEASE_STRIP
for cpu in "${cpus[@]}"; do
  build_final "${cpu}" \
    "trained: pgo_train at target-cpu=${train_cpu}, applied at target-cpu=${cpu}" \
    "-Cprofile-use=${rustc_pgo}/merged.profdata"
done
