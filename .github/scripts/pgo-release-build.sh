#!/usr/bin/env bash
# Two-pass LLVM PGO for snell-rs. Training uses the runtime loopback benchmarks.
# target-cpu=native is forbidden: artifacts must run on machines other than the builder.
set -euo pipefail

target="${1:?target}"
cpu="${2:?cpu}"
binary="${3:?binary}"

if [[ "${cpu}" == "native" ]]; then
  echo "target-cpu=native is forbidden for release artifacts" >&2
  exit 1
fi

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
export RUSTFLAGS="-Ctarget-cpu=${cpu} -Cprofile-generate=${rustc_pgo}"
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

cargo test --release --locked --target "${target}" -p snell-runtime --bench tcp_loopback -- --nocapture
cargo test --release --locked --target "${target}" -p snell-runtime --bench reuse_loopback -- --nocapture
cargo test --release --locked --target "${target}" -p snell-runtime --bench udp_loopback -- --nocapture

shopt -s nullglob
raws=("${pgo}"/*.profraw)
if [[ ${#raws[@]} -eq 0 ]]; then
  echo "PGO produced no .profraw files" >&2
  exit 1
fi
"${profdata}" merge -o "${pgo}/merged.profdata" "${raws[@]}"
if ! "${profdata}" show --covered "${pgo}/merged.profdata" | awk '/snell_runtime/{found=1} END{exit !found}'; then
  echo "PGO profile does not cover snell-runtime" >&2
  exit 1
fi

unset CARGO_PROFILE_RELEASE_STRIP
export RUSTFLAGS="-Ctarget-cpu=${cpu} -Cprofile-use=${rustc_pgo}/merged.profdata"
cargo build --release --locked --target "${target}" -p snell
echo trained >"${status_file}"
