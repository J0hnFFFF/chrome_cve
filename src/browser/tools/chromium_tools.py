"""
Chromium source code analysis tools.

Tools for fetching patches, searching code, and analyzing Chromium source.
"""

import re
import base64
import requests
from typing import Optional
from agentlib.lib import tools


CHROMIUM_GITILES = "https://chromium.googlesource.com"
CHROMIUM_REVIEW = "https://chromium-review.googlesource.com"


@tools.tool
def fetch_chromium_commit(commit_hash: str, repo: str = "chromium/src") -> str:
    """
    Fetch the diff/patch for a specific Chromium commit.

    :param commit_hash: The git commit hash
    :param repo: Repository path (default: chromium/src, use v8/v8 for V8)
    :return: The commit diff content
    """
    # Gitiles API returns base64 encoded content with ?format=TEXT
    url = f"{CHROMIUM_GITILES}/{repo}/+/{commit_hash}%5E%21/?format=TEXT"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            # Decode base64 content
            diff = base64.b64decode(response.content).decode('utf-8', errors='ignore')
            return diff
        else:
            return f"Error: Failed to fetch commit {commit_hash}, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def fetch_chromium_file(file_path: str, commit_hash: str = "main", repo: str = "chromium/src") -> str:
    """
    Fetch a specific file from Chromium source at a given commit.

    :param file_path: Path to file in the repository (e.g., v8/src/compiler/js-call-reducer.cc)
    :param commit_hash: Commit hash or branch name (default: main)
    :param repo: Repository path
    :return: File content
    """
    url = f"{CHROMIUM_GITILES}/{repo}/+/{commit_hash}/{file_path}?format=TEXT"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            content = base64.b64decode(response.content).decode('utf-8', errors='ignore')
            return content
        else:
            return f"Error: Failed to fetch file {file_path}, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def search_chromium_code(query: str, repo: str = "chromium/src", max_results: int = 20) -> str:
    """
    Search for code in Chromium source using Chromium Code Search.

    :param query: Search query (supports regex)
    :param repo: Repository to search
    :param max_results: Maximum number of results
    :return: Search results with file paths and matching lines
    """
    # Use Chromium Code Search API
    # Note: This is a simplified version; real implementation may need API key
    search_url = f"https://source.chromium.org/search"

    # For now, return a note about manual search
    # In production, integrate with Chromium Code Search API or use local clone
    return f"""
Code search query: {query}

To search Chromium code:
1. Visit: https://source.chromium.org/chromium/chromium/src
2. Search for: {query}

Or use local repository:
  git clone https://chromium.googlesource.com/{repo}
  cd src && git grep "{query}"
"""


@tools.tool
def fetch_chromium_bug(bug_id: str) -> str:
    """
    Fetch information about a Chromium bug from the bug tracker.

    :param bug_id: Bug ID number (e.g., 1234567)
    :return: Bug information
    """
    # Chromium bugs are on bugs.chromium.org (Monorail)
    # The API requires authentication for most bugs
    url = f"https://bugs.chromium.org/p/chromium/issues/detail?id={bug_id}"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            # Parse basic info from HTML (simplified)
            # In production, use Monorail API with auth
            return f"""
Bug URL: {url}

Note: Full bug details may require authentication.
Visit the URL above to see complete information.
"""
        else:
            return f"Error: Failed to fetch bug {bug_id}, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def get_commit_info(commit_hash: str, repo: str = "chromium/src") -> str:
    """
    Get metadata about a commit (author, date, message).

    :param commit_hash: The git commit hash
    :param repo: Repository path
    :return: Commit metadata
    """
    url = f"{CHROMIUM_GITILES}/{repo}/+/{commit_hash}?format=JSON"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            # Gitiles JSON has a security prefix we need to skip
            json_text = response.text
            if json_text.startswith(")]}'"):
                json_text = json_text[4:]

            import json
            data = json.loads(json_text)

            return f"""
Commit: {data.get('commit', commit_hash)}
Author: {data.get('author', {}).get('name', 'Unknown')} <{data.get('author', {}).get('email', '')}>
Date: {data.get('author', {}).get('time', 'Unknown')}

Message:
{data.get('message', 'No message')}
"""
        else:
            return f"Error: Failed to fetch commit info, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def list_commit_files(commit_hash: str, repo: str = "chromium/src") -> str:
    """
    List all files changed in a commit.

    :param commit_hash: The git commit hash
    :param repo: Repository path
    :return: List of changed files
    """
    # Fetch the diff and parse file names
    diff = fetch_chromium_commit.func(commit_hash, repo)

    if diff.startswith("Error:"):
        return diff

    # Parse file names from diff
    files = []
    for line in diff.split('\n'):
        if line.startswith('diff --git'):
            # Extract file path from "diff --git a/path b/path"
            match = re.search(r'diff --git a/(.*) b/', line)
            if match:
                files.append(match.group(1))

    if files:
        return "Changed files:\n" + "\n".join(f"  - {f}" for f in files)
    else:
        return "No files found in commit"


@tools.tool
def analyze_patch_components(commit_hash: str, repo: str = "chromium/src") -> str:
    """
    Analyze a patch to identify which Chromium components are affected.

    :param commit_hash: The git commit hash
    :param repo: Repository path
    :return: Analysis of affected components
    """
    files_result = list_commit_files.func(commit_hash, repo)

    if files_result.startswith("Error:"):
        return files_result

    # Component detection based on file paths
    components = {
        "V8": ["v8/", "src/v8/"],
        "Blink": ["third_party/blink/", "blink/"],
        "Skia": ["third_party/skia/", "skia/"],
        "PDFium": ["third_party/pdfium/"],
        "WebRTC": ["third_party/webrtc/"],
        "FFmpeg": ["third_party/ffmpeg/"],
        "Network": ["net/", "services/network/"],
        "GPU": ["gpu/", "ui/gl/"],
        "Sandbox": ["sandbox/"],
        "Browser": ["chrome/browser/"],
        "Renderer": ["content/renderer/"],
    }

    detected = set()
    file_lines = files_result.split('\n')[1:]  # Skip header

    for line in file_lines:
        file_path = line.strip().lstrip('- ')
        for component, patterns in components.items():
            for pattern in patterns:
                if file_path.startswith(pattern):
                    detected.add(component)
                    break

    if detected:
        return f"Detected components:\n" + "\n".join(f"  - {c}" for c in sorted(detected))
    else:
        return "Could not determine component from file paths"
