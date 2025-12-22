"""
Common utility tools for file operations and shell commands.
"""

import os
import subprocess
from agentlib.lib import tools


@tools.tool
def read_file(filepath: str) -> str:
    """
    Read content from a file.

    :param filepath: Path to the file
    :return: File content
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return f"Error: File not found: {filepath}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tools.tool
def write_file(filepath: str, content: str) -> str:
    """
    Write content to a file.

    :param filepath: Path to the file
    :param content: Content to write
    :return: Success message or error
    """
    try:
        # Create parent directories if needed
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"Successfully wrote to: {filepath}"
    except Exception as e:
        return f"Error writing file: {str(e)}"


@tools.tool
def list_directory(path: str = ".") -> str:
    """
    List contents of a directory.

    :param path: Directory path
    :return: Directory listing
    """
    try:
        entries = os.listdir(path)
        result = f"Contents of {path}:\n"
        for entry in sorted(entries):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                result += f"  [DIR]  {entry}/\n"
            else:
                size = os.path.getsize(full_path)
                result += f"  [FILE] {entry} ({size} bytes)\n"
        return result
    except FileNotFoundError:
        return f"Error: Directory not found: {path}"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def run_command(command: str, timeout: int = 60, cwd: str = None) -> str:
    """
    Run a shell command and return output.

    :param command: Command to run
    :param timeout: Timeout in seconds
    :param cwd: Working directory
    :return: Command output
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        output = f"Exit Code: {result.returncode}\n\n"
        if result.stdout:
            output += f"STDOUT:\n{result.stdout}\n"
        if result.stderr:
            output += f"STDERR:\n{result.stderr}\n"
        return output
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@tools.tool
def file_exists(filepath: str) -> str:
    """
    Check if a file exists.

    :param filepath: Path to check
    :return: Existence status
    """
    exists = os.path.exists(filepath)
    is_file = os.path.isfile(filepath)
    is_dir = os.path.isdir(filepath)

    if not exists:
        return f"Path does not exist: {filepath}"
    elif is_file:
        size = os.path.getsize(filepath)
        return f"File exists: {filepath} ({size} bytes)"
    elif is_dir:
        return f"Directory exists: {filepath}"
    else:
        return f"Path exists but is neither file nor directory: {filepath}"
