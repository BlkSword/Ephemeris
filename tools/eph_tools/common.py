"""Common helpers for Ephemeris terminal/GUI tools.

These tools are thin wrappers around the `eph` command-line binary.
They avoid reimplementing cryptography in Python and let the Rust core
handle all encryption/decryption/repudiation logic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


class EphToolError(RuntimeError):
    """Raised when the underlying `eph` CLI fails."""


def find_eph() -> str:
    """Locate the `eph` binary.

    Priority:
    1. $EPH_CLI if set
    2. `eph` on PATH
    3. ./target/release/eph(.exe)
    4. ./target/debug/eph(.exe)
    """
    env = os.environ.get("EPH_CLI")
    if env:
        return env

    which = shutil.which("eph")
    if which:
        return which

    suffix = ".exe" if os.name == "nt" else ""
    # repo root is two directories up from this file: tools/eph_tools/common.py
    root = Path(__file__).resolve().parents[2]
    for rel in ("target/release", "target/debug"):
        candidate = root / rel / f"eph{suffix}"
        if candidate.exists():
            return str(candidate)

    raise EphToolError(
        "Cannot find the `eph` CLI. Build it first with:\n"
        "    cargo build --release -p eph\n"
        "or set $EPH_CLI to the binary path."
    )


def run_eph(args: list[str], password: str | None = None, input_data: bytes | None = None) -> subprocess.CompletedProcess:
    """Run `eph` with the given arguments.

    Passwords are passed via `-p` so the wrapper does not need to create
    temporary password files. Note that command-line passwords are visible
    in the process list; this is acceptable for the convenience tools but
    not recommended for hostile environments.
    """
    cmd = [find_eph()]
    cmd += args
    if password is not None:
        cmd += ["-p", password]

    try:
        proc = subprocess.run(cmd, input=input_data, capture_output=True)
    except OSError as exc:
        raise EphToolError(f"Failed to execute `eph`: {exc}") from exc

    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise EphToolError(msg or f"eph exited with code {proc.returncode}")

    return proc


def encrypt_text(plaintext: str, password: str) -> str:
    """Encrypt a Unicode string and return ASCII-armored ciphertext text.

    The plaintext is encoded as UTF-8 before encryption, so Chinese text is
    supported naturally.
    """
    proc = run_eph(["encrypt", "-", "-", "-p", password], input_data=plaintext.encode("utf-8"))
    return proc.stdout.decode("utf-8")


def decrypt_text(ciphertext_text: str, password: str) -> str:
    """Decrypt armored/base64 ciphertext text back to a Unicode string.

    Returns the UTF-8 decoded plaintext.
    """
    data = ciphertext_text.strip().encode("utf-8")
    args = ["decrypt", "-", "-", "-p", password]
    if data.startswith(b"-----BEGIN EPHEMERIS-----"):
        # auto-detection also works, but make it explicit
        args.insert(3, "--armor")
    else:
        args.insert(3, "--text")

    proc = run_eph(args, input_data=data)
    return proc.stdout.decode("utf-8")


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    output_mode: str = "binary",
    shred: bool = False,
    force: bool = False,
) -> str:
    """Encrypt a file.

    output_mode: "binary" (default), "armor", or "text".
    """
    args = ["encrypt", input_path, output_path]
    if output_mode == "armor":
        args.append("--armor")
    elif output_mode == "text":
        args.append("--text")
    if shred:
        args.append("--shred")
    if force:
        args.append("--force")

    proc = run_eph(args, password=password)
    return proc.stderr.decode("utf-8", errors="replace")


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    input_mode: str = "binary",
    force: bool = False,
) -> str:
    """Decrypt a file.

    input_mode: "binary" (default), "armor", or "text".
    """
    args = ["decrypt", input_path, output_path]
    if input_mode == "armor":
        args.append("--armor")
    elif input_mode == "text":
        args.append("--text")
    if force:
        args.append("--force")

    proc = run_eph(args, password=password)
    return proc.stderr.decode("utf-8", errors="replace")


def repudiate_file(
    input_path: str,
    fake_path: str,
    output_path: str,
    fake_password: str,
    armor: bool = False,
    force: bool = False,
) -> str:
    """Replace the key blob with a fake-message key blob."""
    args = ["repudiate", input_path, output_path, fake_path]
    if armor:
        args.append("--armor")
    if force:
        args.append("--force")

    proc = run_eph(args, password=fake_password)
    return proc.stderr.decode("utf-8", errors="replace")


def info_file(path: str) -> str:
    """Return human-readable metadata for a .eph/.key file."""
    proc = run_eph(["info", path])
    return proc.stdout.decode("utf-8", errors="replace")


def generate_password(words: int = 6, show_entropy: bool = False) -> tuple[str, str]:
    """Generate a Diceware password.

    Returns (password, stderr_text). Entropy information appears in stderr
    when show_entropy is True.
    """
    args = ["gen-pass", "-n", str(words)]
    if show_entropy:
        args.append("-e")
    proc = run_eph(args)
    password = proc.stdout.decode("utf-8").strip()
    notes = proc.stderr.decode("utf-8", errors="replace")
    return password, notes


if __name__ == "__main__":
    # Quick self-test: encrypt and decrypt a Chinese string.
    password = "test-password"
    encrypted = encrypt_text("中文测试 Chinese", password)
    decrypted = decrypt_text(encrypted, password)
    print("encrypt/decrypt self-test:", "OK" if decrypted == "中文测试 Chinese" else "FAIL")
    print("eph binary:", find_eph())
