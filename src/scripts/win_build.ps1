# win_build.ps1
# Builds Chromium or V8 with Debug/ASAN configuration

param (
    [string]$SourcePath, # e.g. D:\src\v8
    [string]$OutDir = "out\Debug",
    [switch]$ASAN = $false
)

$ErrorActionPreference = "Stop"

Set-Location $SourcePath

# 1. Generate Build Args
Write-Host "[*] Generating build config in $OutDir..."

$Args = @(
    "is_debug=true",
    "is_component_build=true", # Faster builds
    "symbol_level=2",          # Full symbols
    "target_cpu=""x64"""
)

if ($ASAN) {
    $Args += "is_asan=true"
    Write-Host "    [!] Enabled AddressSanitizer"
}

# Join args with newlines for gn
$ArgsStr = $Args -join " "

# GN gen
$GnCmd = "gn gen $OutDir --args=""$ArgsStr"""
Write-Host "    Running: $GnCmd"
cmd /c $GnCmd

if ($LASTEXITCODE -ne 0) { Write-Error "gn gen failed"; exit 1 }

# 2. Build
Write-Host "[*] Starting compilation with autoninja..."
cmd /c "autoninja -C $OutDir d8"

if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

Write-Host "[+] Build complete!"
Write-Host "    Target: $(Join-Path $SourcePath $OutDir)\d8.exe"
