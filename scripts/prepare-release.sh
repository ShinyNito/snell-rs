#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/prepare-release.sh <version>" >&2
  echo "example: scripts/prepare-release.sh 0.1.1" >&2
  exit 2
fi

version="${1#v}"
tag="v${version}"

if ! command -v git-cliff >/dev/null 2>&1; then
  echo "git-cliff is required to generate CHANGELOG.md" >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree must be clean before preparing a release" >&2
  exit 1
fi

cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
if [ "${cargo_version}" != "${version}" ]; then
  echo "Cargo.toml version ${cargo_version} does not match ${version}" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "tag ${tag} already exists" >&2
  exit 1
fi

git cliff --unreleased --tag "${tag}" --prepend CHANGELOG.md

if git diff --quiet -- CHANGELOG.md; then
  echo "CHANGELOG.md did not change" >&2
  exit 1
fi

git add CHANGELOG.md
git commit -m "chore(release): 发布 ${version}"

echo "prepared ${tag}"
echo "next: git tag ${tag} && git push origin main ${tag}"
