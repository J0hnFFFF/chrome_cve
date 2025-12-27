---
description: Setup and use the Windows Native Chromium Build System
---

# Windows Native Build Environment Setup

This workflow guides you through setting up a full Chromium/V8 build environment directly on Windows, enabling high-end vulnerability analysis with full debug symbols and ASAN.

## Prerequisites

3.  **Visual Studio 2022** (Community/Pro/Enterprise)
    *   Workload: "Desktop development with C++"
    *   Individual Components:
        *   "MFC for v143 build tools (x86 & x64)" (Required for some Chrome targets)
        *   "Windows 11 SDK" (or Windows 10 SDK)
        *   "Debugging Tools for Windows" (Verify in standard Windows component features if not here)

2.  **Disk Space**
    *   Separate NTFS drive recommended (e.g., `D:\`).
    *   **Minimum**: 100GB free.
    *   **Path**: Keep it short (e.g., `D:\src`) to avoid 260-char limit issues.

3.  **Python 3**
    *   Ensure Python 3 is in your `PATH`.

## Installation Steps

### 1. Configure the Agent
Update your `config.yaml` to enable the local build system:

```yaml
build:
  mode: "hybrid"  # Use "local_windows" to force build, or "hybrid" to try download first
  auto_fallback: true
  source_root: "D:/src"  # Where source code will be checked out
  msvc_path: "C:/Program Files/Microsoft Visual Studio/2022/Community" # Adjust if needed
```

### 2. Install Depot Tools (Automated)
The agent will handle this via `win_setup_depot_tools.ps1`, but you can run it manually to verify:

```powershell
./src/scripts/win_setup_depot_tools.ps1
```

### 3. Usage
Just run the CVE reproduction command as usual. The agent will automatically handle the rest:

```bash
python -m browser.main --cve CVE-2025-6554
```

**What happens next?**
1.  **Intel Collection**: Agent identifies the vulnerable version/commit.
2.  **Smart Decision**:
    *   It tries to download a binary first (Fast).
    *   If that fails (or you forced `local_windows`), it calls `win_fetch_source.ps1`.
3.  **Fetch & Sync**: It downloads V8/Chromium source and syncs to the exact vulnerable commit.
4.  **Build**: It runs `gn gen` (Debug + ASAN) and `autoninja`.
5.  **Verify**: It runs the PoC against the freshly compiled `d8.exe`.
