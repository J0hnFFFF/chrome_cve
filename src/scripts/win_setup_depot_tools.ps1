# win_setup_depot_tools.ps1
# Sets up Google's depot_tools for Windows

param (
    [string]$InstallPath = "C:\src\depot_tools"
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Setting up depot_tools at $InstallPath..."

# 1. Create directory
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath | Out-Null
    Write-Host "    Created directory."
}

# 2. Download depot_tools bundle
$Url = "https://storage.googleapis.com/chrome-infra/depot_tools.zip"
$ZipPath = Join-Path $InstallPath "depot_tools.zip"

if (-not (Test-Path (Join-Path $InstallPath "gclient.bat"))) {
    Write-Host "    Downloading checkout bundle..."
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath
    
    Write-Host "    Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $InstallPath -Force
    Remove-Item $ZipPath
} else {
    Write-Host "    depot_tools seems to be present."
}

# 3. Configure Environment Variables
# NOTE: In a real persistent session, these need to be set in System PATH.
# For this script session, we set them process-level.

Write-Host "    Configuring environment..."

# Must disable local depot_tools win toolchain to use Visual Studio
[System.Environment]::SetEnvironmentVariable("DEPOT_TOOLS_WIN_TOOLCHAIN", "0", [System.EnvironmentVariableTarget]::Process)

# Add to PATH (Must be before python/git)
$CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Process)
if ($CurrentPath -notlike "*$InstallPath*") {
    $NewPath = "$InstallPath;$CurrentPath"
    [System.Environment]::SetEnvironmentVariable("Path", $NewPath, [System.EnvironmentVariableTarget]::Process)
    Write-Host "    Added to PATH."
}

# 4. Bootstrap
Write-Host "[*] Bootstrapping gclient (this may take a while)..."
# Just running gclient once will trigger self-update and python download
cmd /c "gclient --version"

Write-Host "[+] Setup complete. Ensure '$InstallPath' is in your System PATH manually for persistence."
