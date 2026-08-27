#!/usr/bin/env python3
"""Visual (Tkinter) tool for Ephemeris.

A desktop GUI wrapper around the Rust `eph` CLI. It provides:
- Text encryption/decryption (Chinese + armor/base64 text)
- File encryption/decryption
- Repudiation (fake cover versions)
- File info
- Password generation

Usage:
    python eph_gui.py
"""

from __future__ import annotations

import sys
import tkinter as tk

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")
from tkinter import filedialog, messagebox, scrolledtext, ttk

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


class EphGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Ephemeris 加密工具")
        self.geometry("820x620")
        self.minsize(720, 520)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self._build_text_tab()
        self._build_file_tab()
        self._build_repudiate_tab()
        self._build_info_tab()
        self._build_password_tab()

        # Common status bar
        self.status_var = tk.StringVar(value="就绪")
        status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    # Status / helpers
    # ------------------------------------------------------------------
    def set_status(self, message: str) -> None:
        self.status_var.set(message)
        self.update_idletasks()

    def browse(self, entry: tk.Entry) -> None:
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def browse_save(self, entry: tk.Entry) -> None:
        path = filedialog.asksaveasfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    @staticmethod
    def _get_password(entry: tk.Entry) -> str:
        return entry.get()

    @staticmethod
    def _entry(entry: tk.Entry) -> str:
        return entry.get().strip()

    def _run(self, fn, success: str) -> None:
        try:
            self.set_status("执行中...")
            info = fn()
            if info:
                self.set_status(info.strip().splitlines()[-1] if info.strip() else success)
            else:
                self.set_status(success)
            messagebox.showinfo("完成", success)
        except EphToolError as exc:
            self.set_status("失败")
            messagebox.showerror("错误", str(exc))

    # ------------------------------------------------------------------
    # Text tab
    # ------------------------------------------------------------------
    def _build_text_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="文本加解密")

        ttk.Label(tab, text="明文 / 密文（支持中文；密文为 ASCII armor 文本）").pack(anchor="w")
        self.text_area = scrolledtext.ScrolledText(tab, height=14, wrap="word")
        self.text_area.pack(fill="both", expand=True, pady=(6, 8))

        pw_row = ttk.Frame(tab)
        pw_row.pack(fill="x")
        ttk.Label(pw_row, text="密码:").pack(side="left")
        self.text_password = ttk.Entry(pw_row, show="*")
        self.text_password.pack(side="left", fill="x", expand=True, padx=(6, 0))

        btn_row = ttk.Frame(tab, padding=(0, 10, 0, 0))
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="加密为字符密文", command=self._on_text_encrypt).pack(side="left")
        ttk.Button(btn_row, text="解密密文", command=self._on_text_decrypt).pack(side="left", padx=8)
        ttk.Button(btn_row, text="清空", command=lambda: self.text_area.delete("1.0", tk.END)).pack(side="left")

    def _on_text_encrypt(self) -> None:
        def work():
            plaintext = self.text_area.get("1.0", tk.END).rstrip("\n")
            if not plaintext:
                raise EphToolError("请输入要加密的文本。")
            password = self._get_password(self.text_password)
            if not password:
                raise EphToolError("请输入密码。")
            ciphertext = encrypt_text(plaintext, password)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", ciphertext)
            return "加密完成，已输出字符密文"

        self._run(work, "加密完成")

    def _on_text_decrypt(self) -> None:
        def work():
            data = self.text_area.get("1.0", tk.END).strip()
            if not data:
                raise EphToolError("请输入密文。")
            password = self._get_password(self.text_password)
            if not password:
                raise EphToolError("请输入密码。")
            plaintext = decrypt_text(data, password)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", plaintext)
            return "解密完成"

        self._run(work, "解密完成")

    # ------------------------------------------------------------------
    # File tab
    # ------------------------------------------------------------------
    def _build_file_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="文件加解密")

        grid = ttk.Frame(tab)
        grid.pack(fill="x")

        ttk.Label(grid, text="输入文件:").grid(row=0, column=0, sticky="w", pady=4)
        self.file_input = ttk.Entry(grid)
        self.file_input.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(grid, text="浏览", command=lambda: self.browse(self.file_input)).grid(row=0, column=2)

        ttk.Label(grid, text="输出文件:").grid(row=1, column=0, sticky="w", pady=4)
        self.file_output = ttk.Entry(grid)
        self.file_output.grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(grid, text="浏览", command=lambda: self.browse_save(self.file_output)).grid(row=1, column=2)
        grid.columnconfigure(1, weight=1)

        opt_row = ttk.Frame(tab, padding=(0, 8, 0, 0))
        opt_row.pack(fill="x")
        ttk.Label(opt_row, text="模式:").pack(side="left")
        self.file_mode = ttk.Combobox(opt_row, state="readonly", values=["binary", "armor", "text"], width=10)
        self.file_mode.current(0)
        self.file_mode.pack(side="left", padx=(6, 12))

        self.file_force = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text="覆盖已存在文件", variable=self.file_force).pack(side="left")

        self.file_shred = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text="加密后擦除原文件(尽力)", variable=self.file_shred).pack(side="left", padx=12)

        pw_row = ttk.Frame(tab, padding=(0, 8, 0, 0))
        pw_row.pack(fill="x")
        ttk.Label(pw_row, text="密码:").pack(side="left")
        self.file_password = ttk.Entry(pw_row, show="*")
        self.file_password.pack(side="left", fill="x", expand=True, padx=(6, 0))

        btn_row = ttk.Frame(tab, padding=(0, 10, 0, 0))
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="加密文件", command=self._on_file_encrypt).pack(side="left")
        ttk.Button(btn_row, text="解密文件", command=self._on_file_decrypt).pack(side="left", padx=8)

        self.file_log = scrolledtext.ScrolledText(tab, height=8, state="disabled")
        self.file_log.pack(fill="both", expand=True, pady=(10, 0))

    def _log_file(self, text: str) -> None:
        self.file_log.configure(state="normal")
        self.file_log.delete("1.0", tk.END)
        self.file_log.insert("1.0", text)
        self.file_log.configure(state="disabled")

    def _on_file_encrypt(self) -> None:
        def work():
            src = self._entry(self.file_input)
            dst = self._entry(self.file_output)
            if not src or not dst:
                raise EphToolError("请选择输入和输出文件。")
            password = self._get_password(self.file_password)
            if not password:
                raise EphToolError("请输入密码。")
            mode = self.file_mode.get()
            msg = encrypt_file(
                src,
                dst,
                password,
                output_mode=mode,
                shred=self.file_shred.get(),
                force=self.file_force.get(),
            )
            self._log_file(msg or "加密完成")
        
            return "加密完成"

        self._run(work, "加密完成")

    def _on_file_decrypt(self) -> None:
        def work():
            src = self._entry(self.file_input)
            dst = self._entry(self.file_output)
            if not src or not dst:
                raise EphToolError("请选择输入和输出文件。")
            password = self._get_password(self.file_password)
            if not password:
                raise EphToolError("请输入密码。")
            mode = self.file_mode.get()
            msg = decrypt_file(src, dst, password, input_mode=mode, force=self.file_force.get())
            self._log_file(msg or "解密完成")
            return "解密完成"

        self._run(work, "解密完成")

    # ------------------------------------------------------------------
    # Repudiate tab
    # ------------------------------------------------------------------
    def _build_repudiate_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="抵赖")

        grid = ttk.Frame(tab)
        grid.pack(fill="x")

        ttk.Label(grid, text="原始 .eph:").grid(row=0, column=0, sticky="w", pady=4)
        self.rep_input = ttk.Entry(grid)
        self.rep_input.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(grid, text="浏览", command=lambda: self.browse(self.rep_input)).grid(row=0, column=2)

        ttk.Label(grid, text="假明文文件:").grid(row=1, column=0, sticky="w", pady=4)
        self.rep_fake = ttk.Entry(grid)
        self.rep_fake.grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(grid, text="浏览", command=lambda: self.browse(self.rep_fake)).grid(row=1, column=2)

        ttk.Label(grid, text="输出文件:").grid(row=2, column=0, sticky="w", pady=4)
        self.rep_output = ttk.Entry(grid)
        self.rep_output.grid(row=2, column=1, sticky="ew", padx=6)
        ttk.Button(grid, text="浏览", command=lambda: self.browse_save(self.rep_output)).grid(row=2, column=2)
        grid.columnconfigure(1, weight=1)

        opt_row = ttk.Frame(tab, padding=(0, 8, 0, 0))
        opt_row.pack(fill="x")
        self.rep_armor = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text="输出为 armor 文本", variable=self.rep_armor).pack(side="left")
        self.rep_force = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text="覆盖已存在文件", variable=self.rep_force).pack(side="left", padx=12)

        pw_row = ttk.Frame(tab, padding=(0, 8, 0, 0))
        pw_row.pack(fill="x")
        ttk.Label(pw_row, text="假密码:").pack(side="left")
        self.rep_password = ttk.Entry(pw_row, show="*")
        self.rep_password.pack(side="left", fill="x", expand=True, padx=(6, 0))

        ttk.Button(tab, text="执行抵赖", command=self._on_repudiate).pack(anchor="w", pady=12)

        hint = (
            "提示：假明文必须与原始消息字节等长；抵赖后原密码无法恢复真实消息。\n"
            "建议在胁迫前生成假版本，并销毁原始文件。"
        )
        ttk.Label(tab, text=hint, foreground="#555").pack(anchor="w")

    def _on_repudiate(self) -> None:
        def work():
            src = self._entry(self.rep_input)
            fake = self._entry(self.rep_fake)
            dst = self._entry(self.rep_output)
            if not src or not fake or not dst:
                raise EphToolError("请填写原始 .eph、假明文文件和输出文件。")
            password = self._get_password(self.rep_password)
            if not password:
                raise EphToolError("请输入假密码。")
            msg = repudiate_file(
                src,
                fake,
                dst,
                password,
                armor=self.rep_armor.get(),
                force=self.rep_force.get(),
            )
            return msg or "抵赖完成"

        self._run(work, "抵赖完成")

    # ------------------------------------------------------------------
    # Info tab
    # ------------------------------------------------------------------
    def _build_info_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="文件信息")

        row = ttk.Frame(tab)
        row.pack(fill="x")
        self.info_file = ttk.Entry(row)
        self.info_file.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览", command=lambda: self.browse(self.info_file)).pack(side="left", padx=6)

        ttk.Button(tab, text="查看信息", command=self._on_info).pack(anchor="w", pady=8)

        self.info_area = scrolledtext.ScrolledText(tab, height=14, state="disabled")
        self.info_area.pack(fill="both", expand=True)

    def _on_info(self) -> None:
        def work():
            path = self._entry(self.info_file)
            if not path:
                raise EphToolError("请选择文件。")
            text = info_file(path)
            self.info_area.configure(state="normal")
            self.info_area.delete("1.0", tk.END)
            self.info_area.insert("1.0", text)
            self.info_area.configure(state="disabled")
            return "信息已显示"

        self._run(work, "信息已显示")

    # ------------------------------------------------------------------
    # Password tab
    # ------------------------------------------------------------------
    def _build_password_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="密码生成")

        row = ttk.Frame(tab)
        row.pack(fill="x")
        ttk.Label(row, text="单词数量:").pack(side="left")
        self.pass_words = ttk.Spinbox(row, from_=1, to=20, width=5)
        self.pass_words.set(6)
        self.pass_words.pack(side="left", padx=(6, 12))

        self.pass_entropy = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="显示熵值", variable=self.pass_entropy).pack(side="left")

        ttk.Button(tab, text="生成密码", command=self._on_genpass).pack(anchor="w", pady=10)

        self.pass_output = scrolledtext.ScrolledText(tab, height=6)
        self.pass_output.pack(fill="x")

    def _on_genpass(self) -> None:
        def work():
            try:
                words = int(self.pass_words.get())
            except ValueError:
                raise EphToolError("单词数量必须是数字。")
            if words < 1 or words > 20:
                raise EphToolError("单词数量限制在 1-20。")
            password, notes = generate_password(words, show_entropy=self.pass_entropy.get())
            self.pass_output.delete("1.0", tk.END)
            self.pass_output.insert("1.0", password)
            if notes.strip():
                self.pass_output.insert(tk.END, "\n\n" + notes.strip())
            return "密码已生成"

        self._run(work, "密码已生成")


def main() -> int:
    app = EphGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
