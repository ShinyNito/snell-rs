#!/usr/bin/env bash
# Two-pass LLVM PGO for snell-rs. Training runs the pgo_train workload.
# target-cpu=native is forbidden: artifacts must run on machines other than the builder.
#
# The instrumented pass is built at a portable target-cpu for the target's
# architecture so the training workload can always run on the builder, even
# when the artifact cpu is newer than the builder (x86-64-v3/v4 artifacts on
# baseline runners, x86_64 macOS artifacts trained under Rosetta 2). LLVM
# profiles are keyed by function, not by target-cpu, so the final
# profile-use build applies them at the artifact cpu.
set -euo pipefail

target="${1:?target}"
cpu="${2:?cpu}"
binary="${3:?binary}"

if [[ "${cpu}" == "native" ]]; then
  echo "target-cpu=native is forbidden for release artifacts" >&2
  exit 1
fi

case "${target}" in
  x86_64-*) train_cpu="x86-64" ;;
  aarch64-apple-*) train_cpu="apple-m1" ;;
  *) train_cpu="generic" ;;
esac

pgo="${PWD}/pgo-data"
rm -rf "${pgo}"
mkdir -p "${pgo}"
status_file="${pgo}/status"

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

build_final() {
  unset CARGO_PROFILE_RELEASE_STRIP
  export RUSTFLAGS="-Ctarget-cpu=${cpu}"
  cargo build --release --locked --target "${target}" -p snell
}

export CARGO_PROFILE_RELEASE_STRIP=none
export RUSTFLAGS="-Ctarget-cpu=${train_cpu} -Cprofile-generate=${rustc_pgo}"
cargo build --release --locked --target "${target}" -p snell

if [[ ! -f "${bin}" ]]; then
  echo "missing instrumented binary ${bin}" >&2
  exit 1
fi

if ! "${bin}" version >/dev/null 2>&1; then
  echo "::warning::PGO skipped for ${target} cpu=${cpu}: instrumented binary cannot run on this builder"
  echo "skipped: instrumented binary cannot run on this builder" >"${status_file}"
  build_final
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
export RUSTFLAGS="-Ctarget-cpu=${cpu} -Cprofile-use=${rustc_pgo}/merged.profdata"
cargo build --release --locked --target "${target}" -p snell
echo "trained: pgo_train at target-cpu=${train_cpu}, applied at target-cpu=${cpu}" >"${status_file}"
