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

    :param file_path: Path to file in the repository (e.g., src/compiler/js-call-reducer.cc for V8)
    :param commit_hash: Commit hash or branch name (default: main)
    :param repo: Repository path (chromium/src or v8/v8)
    :return: File content
    """
    # Auto-detect and fix V8 paths
    # If path starts with v8/, use v8/v8 repo and strip the prefix
    actual_repo = repo
    actual_path = file_path

    if file_path.startswith("v8/"):
        actual_repo = "v8/v8"
        actual_path = file_path[3:]  # Strip "v8/" prefix
        print(f"    [Tool] Auto-corrected: repo={actual_repo}, path={actual_path}")

    # Use HEAD for default if main doesn't work
    actual_commit = commit_hash
    if commit_hash == "main" and actual_repo == "v8/v8":
        # V8 uses "main" branch, but let's try HEAD first
        actual_commit = "HEAD"

    # Try fetching the file
    url = f"{CHROMIUM_GITILES}/{actual_repo}/+/{actual_commit}/{actual_path}?format=TEXT"

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            content = base64.b64decode(response.content).decode('utf-8', errors='ignore')
            return content
        elif response.status_code == 404 and actual_repo == "v8/v8":
            # Try with chromium/src if v8/v8 failed
            fallback_url = f"{CHROMIUM_GITILES}/chromium/src/+/{commit_hash}/{file_path}?format=TEXT"
            print(f"    [Tool] Trying fallback: chromium/src/{file_path}")
            response = requests.get(fallback_url, timeout=30)
            if response.status_code == 200:
                content = base64.b64decode(response.content).decode('utf-8', errors='ignore')
                return content
            return f"Error: File not found in v8/v8 or chromium/src: {file_path}"
        else:
            return f"Error: Failed to fetch file {actual_path} from {actual_repo}, status={response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def search_chromium_code(query: str, repo: str = "chromium/src", max_results: int = 20) -> str:
    """
    Search for code in Chromium source using local git repository or web scraping.

    :param query: Search query (supports regex)
    :param repo: Repository to search
    :param max_results: Maximum number of results
    :return: Search results with file paths and matching lines
    """
    import os
    import subprocess
    from pathlib import Path
    
    # Strategy 1: Try local git repository first
    possible_local_paths = [
        r"d:\src\chromium\src",
        r"C:\src\chromium\src",
        os.path.expanduser("~/chromium/src"),
        "./volumes/chromium/src",
    ]
    
    local_repo = None
    for path in possible_local_paths:
        if os.path.isdir(path) and os.path.isdir(os.path.join(path, ".git")):
            local_repo = path
            break
    
    if local_repo:
        try:
            # Use git grep for fast searching
            result = subprocess.run(
                ["git", "grep", "-n", "-i", "--max-count=5", query],
                cwd=local_repo,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')[:max_results]
                output = [f"Found {len(lines)} results in local repository ({local_repo}):\n"]
                
                for line in lines:
                    # Format: filename:line_number:content
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        file_path, line_num, content = parts[0], parts[1], parts[2]
                        output.append(f"  {file_path}:{line_num}")
                        output.append(f"    {content.strip()}")
                
                return "\n".join(output)
            else:
                return f"No results found in local repository for: {query}"
                
        except subprocess.TimeoutExpired:
            return f"Search timed out in local repository"
        except Exception as e:
            # Fall through to web-based search
            pass
    
    # Strategy 2: Use Chromium Code Search web interface
    try:
        from bs4 import BeautifulSoup
        
        # Chromium Code Search URL
        search_url = f"https://source.chromium.org/search?q={requests.utils.quote(query)}&ss=chromium%2Fchromium%2Fsrc"
        
        response = requests.get(search_url, timeout=30, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to extract search results from the page
            # Note: This is fragile and may break if Google changes the page structure
            results = []
            
            # Look for code snippets or file references
            # This is a simplified extraction - real implementation would need more robust parsing
            code_blocks = soup.find_all('div', class_=lambda x: x and 'search' in x.lower())
            
            if code_blocks:
                return f"""Found results on Chromium Code Search.
Direct link: {search_url}

Note: Please visit the link above to see detailed results.
For programmatic access, consider using a local Chromium checkout with git grep."""
            else:
                return f"""Search query: {query}

Web search available at: {search_url}

For better results, use a local Chromium repository:
  git clone https://chromium.googlesource.com/chromium/src
  cd src && git grep -n "{query}"
"""
        else:
            return f"Web search failed with status {response.status_code}"
            
    except ImportError:
        return f"""BeautifulSoup not available for web scraping.

Options:
1. Install: pip install beautifulsoup4
2. Use local repository: git clone https://chromium.googlesource.com/chromium/src
3. Visit manually: https://source.chromium.org/search?q={query}
"""
    except Exception as e:
        return f"""Search query: {query}

Manual search options:
1. Visit: https://source.chromium.org/chromium/chromium/src
2. Search for: {query}

Or use local repository:
  git clone https://chromium.googlesource.com/chromium/src
  cd src && git grep "{query}"

Error: {str(e)}
"""


@tools.tool
def fetch_chromium_bug(bug_id: str) -> str:
    """
    Fetch information about a Chromium bug from the bug tracker.

    :param bug_id: Bug ID number (e.g., 1234567)
    :return: Bug information
    """
    # Chromium bugs are on bugs.chromium.org (Monorail)
    url = f"https://bugs.chromium.org/p/chromium/issues/detail?id={bug_id}"

    try:
        response = requests.get(url, timeout=30, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract bug information from HTML
                bug_info = {
                    'id': bug_id,
                    'url': url,
                    'title': None,
                    'status': None,
                    'reporter': None,
                    'owner': None,
                    'components': [],
                    'labels': [],
                    'description': None,
                    'comments_count': 0
                }
                
                # Try to extract title
                title_elem = soup.find('span', {'id': 'issuemeta'})
                if not title_elem:
                    title_elem = soup.find('title')
                if title_elem:
                    title_text = title_elem.get_text().strip()
                    # Clean up title
                    if 'Issue' in title_text:
                        bug_info['title'] = title_text.split(':', 1)[-1].strip()
                    else:
                        bug_info['title'] = title_text
                
                # Try to extract status
                status_elem = soup.find('span', string=re.compile(r'Status:', re.I))
                if status_elem:
                    status_value = status_elem.find_next_sibling()
                    if status_value:
                        bug_info['status'] = status_value.get_text().strip()
                
                # Try to extract labels
                labels_section = soup.find_all('a', href=re.compile(r'q=label:'))
                bug_info['labels'] = [label.get_text().strip() for label in labels_section[:10]]
                
                # Try to extract description (first comment)
                comments = soup.find_all('div', class_=lambda x: x and 'comment' in str(x).lower())
                if comments:
                    bug_info['comments_count'] = len(comments)
                    # Get first comment as description
                    first_comment = comments[0]
                    desc_text = first_comment.get_text().strip()
                    if desc_text:
                        # Limit description length
                        bug_info['description'] = desc_text[:1000]
                
                # Format output
                output = [f"Bug #{bug_id}"]
                output.append(f"URL: {url}")
                output.append("")
                
                if bug_info['title']:
                    output.append(f"Title: {bug_info['title']}")
                
                if bug_info['status']:
                    output.append(f"Status: {bug_info['status']}")
                
                if bug_info['labels']:
                    output.append(f"Labels: {', '.join(bug_info['labels'][:5])}")
                
                if bug_info['description']:
                    output.append("\nDescription:")
                    output.append(bug_info['description'])
                
                if bug_info['comments_count'] > 0:
                    output.append(f"\nComments: {bug_info['comments_count']}")
                
                output.append("\nNote: Visit the URL above for complete information and attachments.")
                
                return "\n".join(output)
                
            except ImportError:
                return f"""Bug #{bug_id}
URL: {url}

Note: BeautifulSoup not available for HTML parsing.
Install with: pip install beautifulsoup4

Visit the URL above to see complete information."""
            except Exception as e:
                return f"""Bug #{bug_id}
URL: {url}

Note: Could not parse bug details (Error: {str(e)})
Visit the URL above to see complete information."""
        else:
            return f"Error: Failed to fetch bug {bug_id}, status={response.status_code}\nURL: {url}"
    except Exception as e:
        return f"Error: {str(e)}\nBug URL: {url}"


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
    # Use invoke instead of .func to avoid deprecation warning
    if hasattr(list_commit_files, 'invoke'):
        files_result = list_commit_files.invoke({"commit_hash": commit_hash, "repo": repo})
    else:
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
@tools.tool
def fetch_associated_tests(commit_hash: str, repo: str = "chromium/src") -> str:
    """
    Fetch regression tests (PoC candidates) associated with a commit.
    Scans the commit for files in test directories (LayoutTests, web_tests, etc.)
    and returns their content.

    :param commit_hash: The git commit hash
    :param repo: Repository path
    :return: Content of found test files with metadata
    """
    # Use invoke instead of .func to avoid deprecation warning
    if hasattr(list_commit_files, 'invoke'):
        files_result = list_commit_files.invoke({"commit_hash": commit_hash, "repo": repo})
    else:
        files_result = list_commit_files.func(commit_hash, repo)
    
    if files_result.startswith("Error:"):
        return f"Error listing files: {files_result}"
        
    # Heuristics for test files
    test_patterns = [
        r"LayoutTests/.*\.js$",
        r"LayoutTests/.*\.html$",
        r"web_tests/.*\.js$",
        r"web_tests/.*\.html$",
        r"chrome/test/data/.*\.js$",
        r"chrome/test/data/.*\.html$",
        r"v8/test/mjsunit/.*\.js$",
        r"v8/test/cctest/.*\.cc$",
        r"components/.*_unittest\.cc$",
        r".*regression.*\.js$",
        r".*repro.*\.js$",
    ]
    
    file_lines = files_result.split('\n')[1:] # Skip header
    found_tests = []
    
    print(f"    [Crawler] Scanning {len(file_lines)} files for tests...")
    
    for line in file_lines:
        file_path = line.strip().lstrip('- ')
        
        # Check if file matches any test pattern
        is_candidate = False
        for pattern in test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                is_candidate = True
                break
                
        if is_candidate:
            print(f"    [Crawler] Found candidate: {file_path}")
            # Fetch file content
            # Use invoke instead of .func to avoid deprecation warning
            if hasattr(fetch_chromium_file, 'invoke'):
                content = fetch_chromium_file.invoke({"file_path": file_path, "commit_hash": commit_hash, "repo": repo})
            else:
                content = fetch_chromium_file.func(file_path, commit_hash=commit_hash, repo=repo)
            if not content.startswith("Error:"):
                found_tests.append({
                    "path": file_path,
                    "content": content
                })
            else:
                print(f"    [Crawler] Failed to fetch {file_path}")

    if not found_tests:
        return "No regression tests found in this commit."
        
    # Format output
    output = [f"Found {len(found_tests)} regression tests in commit {commit_hash}:"]
    for test in found_tests:
        output.append(f"\n--- FILE: {test['path']} ---")
        output.append(test['content'])
        output.append("--- END FILE ---")
        
    return "\n".join(output)
