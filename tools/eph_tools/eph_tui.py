#!/usr/bin/env python3
"""Interactive terminal tool for Ephemeris.

A lightweight, menu-driven TUI wrapper around the Rust `eph` CLI.
Supports text/file encryption/decryption, repudiation, file info and
password generation.

Usage:
    python eph_tui.py
"""

from __future__ import annotations

import getpass
import sys

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

from common import (
    EphToolError,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    generate_password,
    info_file,
    repudiate_file,
)

END_MARKER = "END"


def ask(prompt: str, required: bool = True) -> str:
    while True:
        value = input(prompt).strip()
        if value or not required:
            return value
        print("输入不能为空。")


def ask_password(prompt: str = "密码: ") -> str:
    while True:
        pw = getpass.getpass(prompt)
        if pw:
            return pw
        print("密码不能为空。")


def read_multiline(prompt: str) -> str:
    """Read multiple lines until a line equal to END_MARKER alone."""
    print(prompt)
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == END_MARKER:
            break
        lines.append(line)
    return "\n".join(lines)


def choose_mode(prompt: str, choices: dict[str, str]) -> str:
    for key, desc in choices.items():
        print(f"  {key}. {desc}")
    while True:
        choice = input(prompt).strip().lower()
        if choice in choices:
            return choices[choice]
        print("无效选择。")


def cmd_encrypt_text() -> None:
    try:
        plaintext = read_multiline("输入要加密的文本（UTF-8，支持中文）；最后单独输入一行 END 结束：")
        password = ask_password("加密密码: ")
        ciphertext = encrypt_text(plaintext, password)
        print("\n密文（ASCII armor）:\n")
        print(ciphertext)
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_decrypt_text() -> None:
    try:
        data = read_multiline("粘贴 armor 或 base64 密文；最后单独输入一行 END 结束：")
        password = ask_password("解密密码: ")
        plaintext = decrypt_text(data, password)
        print("\n明文:\n")
        print(plaintext)
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_encrypt_file() -> None:
    try:
        src = ask("输入文件路径: ")
        dst = ask("输出文件路径: ")
        mode = choose_mode("输出格式: ", {"1": "binary", "2": "armor", "3": "text"})
        password = ask_password("加密密码: ")
        force = ask("文件已存在是否覆盖? [y/N]: ").strip().lower() == "y"
        shred = ask("加密后擦除原文件? [y/N]: ").strip().lower() == "y"
        msg = encrypt_file(src, dst, password, output_mode=mode, shred=shred, force=force)
        if msg:
            print(msg.strip())
        print("加密完成。")
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_decrypt_file() -> None:
    try:
        src = ask("输入 .eph / armor / base64 文件路径: ")
        dst = ask("输出文件路径: ")
        mode = choose_mode(
            "输入格式: ",
            {"1": "binary", "2": "armor", "3": "text"},
        )
        password = ask_password("解密密码: ")
        force = ask("文件已存在是否覆盖? [y/N]: ").strip().lower() == "y"
        msg = decrypt_file(src, dst, password, input_mode=mode, force=force)
        if msg:
            print(msg.strip())
        print("解密完成。")
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_repudiate() -> None:
    try:
        src = ask("原始 .eph 文件路径: ")
        fake = ask("假明文文件路径（必须与原文等长）: ")
        dst = ask("输出 .eph 文件路径: ")
        password = ask_password("假密码: ")
        armor = ask("输出为 armor 文本? [y/N]: ").strip().lower() == "y"
        force = ask("文件已存在是否覆盖? [y/N]: ").strip().lower() == "y"
        msg = repudiate_file(src, fake, dst, password, armor=armor, force=force)
        if msg:
            print(msg.strip())
        print("抵赖完成。")
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_info() -> None:
    try:
        path = ask("输入 .eph / .key / armor 文件路径: ")
        print(info_file(path))
    except EphToolError as e:
        print(f"[错误] {e}")


def cmd_genpass() -> None:
    try:
        words = int(ask("单词数量 [6]: ") or "6")
        if words < 1 or words > 20:
            print("单词数量限制在 1-20。")
            return
        entropy = ask("显示熵值? [y/N]: ").strip().lower() == "y"
        password, notes = generate_password(words, show_entropy=entropy)
        print(f"\n生成密码: {password}")
        if notes.strip():
            print(notes.strip())
    except ValueError:
        print("请输入数字。")
    except EphToolError as e:
        print(f"[错误] {e}")


MENU = [
    ("加密文本（输出字符密文）", cmd_encrypt_text),
    ("解密文本（粘贴字符密文）", cmd_decrypt_text),
    ("加密文件", cmd_encrypt_file),
    ("解密文件", cmd_decrypt_file),
    ("抵赖（生成假版本）", cmd_repudiate),
    ("查看文件信息", cmd_info),
    ("生成强密码", cmd_genpass),
]


def main() -> int:
    print("=" * 60)
    print("  Ephemeris 便捷终端工具")
    print("  底层使用 Rust `eph` CLI，支持中文与字符密文")
    print("=" * 60)

    while True:
        print("\n请选择操作：")
        for i, (title, _) in enumerate(MENU, 1):
            print(f"  {i}. {title}")
        print("  0. 退出")

        choice = input("\n选择: ").strip()
        if choice == "0":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(MENU)):
            print("无效选择。")
            continue

        try:
            MENU[int(choice) - 1][1]()
        except (KeyboardInterrupt, EOFError):
            print("\n已取消。")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[意外错误] {exc}")

    print("\n再见。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
