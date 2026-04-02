#!/usr/bin/env bash
# Cross-compile MemeTracker and write SHA256 checksums.
# Usage: from repo root: bash scripts/build-release.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${MTR_VERSION:-1.0.0}"
OUT="$ROOT/dist"
mkdir -p "$OUT"
export CGO_ENABLED=0

build_one() {
  local goos="$1" goarch="$2" suffix="$3"
  local name="memetracker-v${VERSION}-${goos}-${goarch}${suffix}"
  echo "Building $name ..."
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "$OUT/$name" .
}

build_one windows amd64 .exe
build_one linux amd64 ""
build_one linux arm64 ""
build_one darwin amd64 ""
build_one darwin arm64 ""

(
  cd "$OUT"
  rm -f SHA256SUMS
  sha256sum memetracker-v* > SHA256SUMS
)
echo "Done. $OUT/ and $OUT/SHA256SUMS"
