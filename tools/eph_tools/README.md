# Ephemeris 便捷终端版 & 可视化版

这是 Ephemeris 的两款便捷工具，使用 Python 标准库编写，底层调用 Rust `eph` CLI 完成所有加密/解密/抵赖操作。

- `eph_tui.py`：交互式终端菜单工具
- `eph_gui.py`：Tkinter 桌面可视化工具

## 依赖

- Python 3.8+
- 可运行的 `eph` CLI

构建 CLI：

```bash
cargo build --release -p eph
```

工具会自动查找 `eph` / `eph.exe`，查找顺序：

1. 环境变量 `EPH_CLI`
2. `PATH` 中的 `eph`
3. `target/release/eph(.exe)`
4. `target/debug/eph(.exe)`

如果 CLI 不在上述位置，可以手动指定：

```bash
export EPH_CLI=/path/to/eph
```

## 终端版

```bash
python tools/eph_tools/eph_tui.py
```

功能：

- 加密文本：输入中文/UTF-8 文本，直接输出 ASCII armor 字符密文
- 解密文本：粘贴 armor/base64 密文，输出明文
- 加密文件
- 解密文件
- 抵赖：生成假版本文件
- 查看文件信息
- 生成强密码

## 可视化版

```bash
python tools/eph_tools/eph_gui.py
```

功能标签页：

- **文本加解密**：文本区直接输入中文，一键加密为字符密文或解密
- **文件加解密**：选择文件，支持 binary / armor / text 三种模式
- **抵赖**：选择原始 `.eph`、假明文文件，生成假版本
- **文件信息**：查看 `.eph` / `.key` 元数据
- **密码生成**：Diceware 密码生成器

## 安全提示

- 这两个工具通过 `-p` 参数把密码传给 `eph` CLI，密码会出现在进程列表中。日常便利使用可以接受，但在高威胁环境中建议使用原始 CLI 的交互式密码输入。
- 文本加密默认输出 ASCII armor 字符密文，适合复制粘贴。
- 抵赖要求假明文与原消息**字节等长**；请先用“文件信息”查看消息长度。
- `--shred` 属于尽力擦除，不能保证在 SSD/快照/云同步下彻底删除。
- 不要保留抵赖前的旧原始文件，否则攻击者可通过新旧文件对比发现抵赖。
