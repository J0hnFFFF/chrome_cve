# win_fetch_source.ps1
# Fetches Chromium or V8 source code and syncs to specific version

param (
    [string]$RootPath = "D:\src",
    [string]$Target = "v8",        # "chromium" or "v8"
    [string]$Version = "main"      # Can be a tag (12.0.267.1), commit hash, or "main"
)

$ErrorActionPreference = "Stop"

# Ensure depot_tools is in path
if (-not (Get-Command "gclient" -ErrorAction SilentlyContinue)) {
    Write-Error "gclient not found! Please run setup_depot_tools.ps1 or add depot_tools to PATH."
}

if (-not (Test-Path $RootPath)) {
    New-Item -ItemType Directory -Path $RootPath | Out-Null
}

Set-Location $RootPath

# 1. Fetch (Initialize)
if (-not (Test-Path (Join-Path $RootPath $Target))) {
    Write-Host "[*] Fetching $Target (this takes a long time)..."
    try {
        cmd /c "fetch --no-history $Target"
    } catch {
        Write-Warning "Fetch returned error, but check if .gclient exists."
    }
}

# 2. Sync to Version
$SourceDir = Join-Path $RootPath $Target
Set-Location $SourceDir

Write-Host "[*] Syncing to version: $Version..."

if ($Version -match "^(HEAD|main|master)$") {
    # Sync latest
    cmd /c "gclient sync"
} else {
    # Check if it's a V8 version tag or Commit
    # The syntax for gclient sync is src@<revision> or v8@<revision>
    
    $RepoName = if ($Target -eq "chromium") { "src" } else { "v8" }
    
    # Reset git first to be safe
    Write-Host "    Resetting git state..."
    git reset --hard
    git clean -fd
    
    # Execute sync with revision
    # This syncs the main repo AND upgrades/downgrades all dependencies in DEPS
    $SyncCmd = "gclient sync --revision ${RepoName}@${Version} --force"
    Write-Host "    Running: $SyncCmd"
    
    cmd /c $SyncCmd
}

if ($LASTEXITCODE -ne 0) { 
    Write-Error "Sync failed. Please check if the version/commit exists."
    exit 1 
}

Write-Host "[+] Source ready at $SourceDir (Version: $Version)"
