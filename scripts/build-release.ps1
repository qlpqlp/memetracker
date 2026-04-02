# Cross-compile MemeTracker and write SHA256 checksums for all binaries.
# Requires Go 1.20+ on PATH. Output: dist/

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = if ($env:MTR_VERSION) { $env:MTR_VERSION } else { "1.0.0" }
$outDir = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$env:CGO_ENABLED = "0"

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; suffix = ".exe" },
    @{ GOOS = "linux";   GOARCH = "amd64"; suffix = "" },
    @{ GOOS = "linux";   GOARCH = "arm64"; suffix = "" },
    @{ GOOS = "darwin";  GOARCH = "amd64"; suffix = "" },
    @{ GOOS = "darwin";  GOARCH = "arm64"; suffix = "" }
)

foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $name = "memetracker-v${version}-$($t.GOOS)-$($t.GOARCH)$($t.suffix)"
    $dest = Join-Path $outDir $name
    Write-Host "Building $name ..."
    go build -trimpath -ldflags="-s -w" -o $dest .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$sumsPath = Join-Path $outDir "SHA256SUMS"
Remove-Item -Force -ErrorAction SilentlyContinue $sumsPath
Get-ChildItem $outDir -File | Where-Object { $_.Name -ne "SHA256SUMS" } | ForEach-Object {
    $h = Get-FileHash -Path $_.FullName -Algorithm SHA256
    "$($h.Hash.ToLower())  $($_.Name)" | Add-Content -Path $sumsPath -Encoding utf8
}

Write-Host "Done. Binaries and $sumsPath"
