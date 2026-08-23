# Ephemeris

**消息级可否认加密库 —— 信息论安全。**

加密一条消息。被胁迫时，证明它解密为另一份无害内容；在理想操作下，任何数学手段都无法区分真假。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/ephemeris-core.svg)](https://crates.io/crates/ephemeris-core)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)

*English version: [README_EN.md](README_EN.md)*

---

## 目录

- [核心原理](#核心原理)
- [安全属性](#安全属性)
- [快速开始](#快速开始)
- [详细使用指南](#详细使用指南)
- [文件格式](#文件格式)
- [威胁模型](#威胁模型)
- [性能优化](#性能优化)
- [从源码构建](#从源码构建)
- [算法原创性与相关研究](#算法原创性与相关研究)
- [安全审计](#安全审计)
- [对比](#对比)
- [许可证与免责声明](#许可证与免责声明)

---

## 核心原理

```
┌────────────────────────────────────────────────────┐
│                    加密                              │
│                                                     │
│  1. 生成真随机 OTP 密钥 K（长度 = 消息长度）          │
│  2. C = 明文 ⊕ K              (XOR 加密)            │
│  3. 用 AES-256-CTR(KDF(密码, 盐), K) 封装 K         │
│  4. 存储：盐 ‖ 封装后的K ‖ 密文C                     │
│                                                     │
│                    抵赖                              │
│                                                     │
│  1. 给定任意无害假消息 P_fake（与真消息等长）          │
│  2. K_fake = C ⊕ P_fake        (算出假密钥)          │
│  3. 用假密码封装 K_fake                              │
│  4. 替换文件中的密钥块                               │
│                                                     │
│  结果：假密码 → 无害消息；真数据不可恢复               │
└────────────────────────────────────────────────────┘
```

### 为什么可否认

- **一次性密码本（OTP）**：对密文 C，任意等长明文 P' 都有唯一密钥 K' = C ⊕ P'。存在无限多组有效的 (密钥, 明文)。
- **非承诺密钥封装**：AES-256-CTR 无认证标签 —— 所有密码都产生“有效”输出，无法通过报错区分密码正确性。
- **抵赖无需真密码**：`repudiate` 直接从密文算出假密钥，胁迫场景下无需输入真实密码。

---

## 安全属性

| 属性 | 保证 |
|------|------|
| **可否认性** | OTP 层信息论安全：C 可解密为任意等长 P' |
| **密钥封装** | 非承诺式：所有密码都产生有效输出 |
| **抵赖** | 无需真实密码 |
| **文件格式** | 抵赖后字节级结构完全一致 |
| **时序安全** | 常量时间比较，无密码 oracle |
| **内存安全** | 零 unsafe，核心密钥 zeroize 清零 |

> 注意：这里的“信息论安全”主要指 OTP 层；完整文件的可否认性还依赖于密码强度、没有旧文件副本、假消息合理性等操作条件。详见[威胁模型](#威胁模型)。

---

## 快速开始

### 安装

#### Rust

```bash
cargo add ephemeris-core
```

#### CLI

```bash
cargo install eph
```

或从源码安装：

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo install --path eph-cli
```

#### Python

```bash
pip install ephemeris
```

Python 绑定基于 PyO3/maturin，目前注意 Python 版本与 PyO3 支持范围的兼容性。

### Rust 使用

```rust
use ephemeris_core::*;

let params = Argon2Params::default();

// 加密
let result = encrypt(b"发射代码: ALPHA-42", b"secret-password", &params);

// 解密
let pt = decrypt(&result.eph_file, b"secret-password", &params).unwrap();
assert_eq!(pt, b"发射代码: ALPHA-42");

// 抵赖 —— 声称是日记（注意等长！）
let fake = repudiate_eph(
    &result.eph_file,
    b"Dear diary: boring day",
    b"diary-password",
    &params,
).unwrap();

// 假密码可以解出假消息
let fake_pt = decrypt(&fake, b"diary-password", &params).unwrap();
assert_eq!(fake_pt, b"Dear diary: boring day");
```

### Python 使用

```python
import ephemeris

# 加密（Chinese 按 UTF-8 bytes 处理）
data = ephemeris.encrypt("发射代码: ALPHA-42".encode("utf-8"), b"secret-password")

# 解密
plaintext = ephemeris.decrypt(data, b"secret-password")
print(plaintext.decode("utf-8"))

# 抵赖：假消息必须与真消息字节等长
fake_data = ephemeris.repudiate_eph(
    data,
    b"Dear diary: boring day",
    b"diary-pw",
)

assert ephemeris.decrypt(fake_data, b"diary-pw") == b"Dear diary: boring day"
```

### CLI 快速示例

```bash
# 基本操作
eph encrypt secret.txt secret.eph                 # 加密文件
eph decrypt secret.eph output.txt                 # 解密文件
eph repudiate secret.eph cover.eph fake.txt       # 抵赖：生成假版本
eph info secret.eph                               # 查看元数据

# 高级功能
eph encrypt secret.txt secret.eph --armor         # base64 armor 输出
eph encrypt secret.txt secret.eph --shred         # 加密后安全擦除原文
eph gen-pass -n 6 -e                              # 生成强密码（6 词，显示熵值）
eph decrypt msg.asc output.txt                    # 自动识别二进制/armor 格式

# 分离密钥/密文 + base64 文本输出
eph encrypt secret.txt --key-file key.b64 --cipher-file cipher.b64 --text
eph decrypt cipher.b64 output.txt --split --key-file key.b64 --text
```

---

## 详细使用指南

### 1. 中文与 UTF-8 支持

Ephemeris 不区分“文本”和“二进制”，它只处理字节。中文会按 UTF-8 编码成字节后参与加密，因此天然支持中文。

```bash
# 写入中文文件
printf '中文测试消息 Chinese message' > msg.txt

# 加密
eph encrypt msg.txt msg.eph -p 'your-password'

# 解密
eph decrypt msg.eph out.txt -p 'your-password'
cat out.txt
# 中文测试消息 Chinese message
```

### 2. 输出“字符密文”而不是文件

如果想得到可直接复制、粘贴、发邮件/聊天的密文，可以使用 `--armor` 或 `--text`。

#### 输出到 stdout / 从 stdin 读取

```bash
# 从 stdin 读明文，向 stdout 输出 ASCII armor 字符密文
printf '中文测试消息 Chinese message' | eph encrypt - - -p 'your-password'
```

输出示例：

```text
-----BEGIN EPHEMERIS-----
RVBIMe5vbVeqYAitYIzNXHaCtugAIgAAAPxxNUh1dIUTdSfhDP5Cs3EwseuM/5DD
FjDwalzSQ5Tvb3P8dXtJLyD/vGAXBdKohETZOtTaRD0QJ/Dr6s8Ubh62OrKP
-----END EPHEMERIS-----
```

加密日志输出到 stderr，stdout 只会输出密文文本。

解密 armor 并输出明文到 stdout：

```bash
eph decrypt out.asc - -p 'your-password'
```

#### 保存为 Base64 文本文件

```bash
# 组合文件：纯 base64 文本（无 armor 头）
eph encrypt msg.txt msg.b64 --text

# 解密 base64 文本
eph decrypt msg.b64 out.txt --text
```

#### Python 输出 Base64 字符串

```python
import base64
import ephemeris

data = ephemeris.encrypt("中文消息".encode("utf-8"), b"password")

# 转成字符密文
cipher_text = base64.b64encode(data).decode("ascii")

# 从字符密文解密
plain = ephemeris.decrypt(base64.b64decode(cipher_text), b"password")
print(plain.decode("utf-8"))
```

### 3. 密码输入方式

CLI 支持三种密码输入：

```bash
# 交互式输入（默认，会二次确认）
eph encrypt msg.txt msg.eph

# 命令行参数（适合脚本，但会出现在进程列表，谨慎使用）
eph encrypt msg.txt msg.eph -p 'your-password'

# 从文件读取（适合自动化）
eph encrypt msg.txt msg.eph -P password.txt
```

> 当前 `--password-file` 的实现是读取整个文件内容作为密码；如果文件末尾有换行符，换行也会算入密码。建议文件中不保留多余空白/换行。

### 4. Argon2 参数

默认参数：

| 参数 | 默认值 |
|------|--------|
| 算法 | Argon2id |
| time cost | 2 |
| memory cost | 37888 KiB（约 37 MiB） |
| parallelism | 1 |

CLI 可通过 `-t/--time-cost`、`-m/--memory-cost`、`-j/--parallelism` 调整：

```bash
eph encrypt msg.txt msg.eph -t 3 -m 65536 -j 2
```

> 注意：Argon2 参数目前不会写入 `.eph` 文件头。解密时必须使用与加密时相同的参数，否则会得到乱码。

### 5. 抵赖（Repudiate）详细说明

抵赖的输入输出：

```bash
eph repudiate secret.eph cover.eph fake.txt
```

要求：

- `fake.txt` 的**字节长度必须与原密文长度一致**；
- 假消息越自然越好；
- 抵赖会生成一个新的 `.eph` 文件，不会原地修改原文件；
- 原文件如果仍存在，攻击者通过新旧文件对比可以发现抵赖痕迹，因此实际操作中应销毁原始文件。

查长度：

```bash
eph info secret.eph
# Message length: N bytes
# fake.txt 也必须是 N 字节
```

支持 armor 输出：

```bash
eph repudiate secret.eph cover.asc fake.txt --armor
```

### 6. 分离密钥与密文

适合“密钥和密文分开保存/传输”的场景：

```bash
# 加密：只输出 cipher 和 key，不输出组合 .eph
eph encrypt msg.txt --key-file key.bin --cipher-file cipher.bin

# base64 文本形式
eph encrypt msg.txt --key-file key.b64 --cipher-file cipher.b64 --text

# 解密分离格式
eph decrypt cipher.b64 out.txt --split --key-file key.b64 --text
eph decrypt cipher.bin out.txt --split --key-file key.bin
```

> `--key-file` 也可以与 `.eph` 组合输出同时使用：既生成 `secret.eph`，又额外导出一份独立 key 文件。

### 7. 查看文件信息

```bash
eph info secret.eph
eph info key.bin
```

输出包含：

- 文件类型：`.eph` 或 `.key`
- 文件尺寸
- Salt
- 消息长度
- KeyBlob 长度
- 文件膨胀率

### 8. 生成强密码

```bash
# 生成 6 个 Diceware 单词
eph gen-pass

# 指定数量并显示熵值
eph gen-pass -n 8 -e
```

### 9. 安全擦除原文件

```bash
eph encrypt secret.txt secret.eph --shred
```

`--shred` 会在加密成功后对原文件进行多次随机覆写再删除。

> 注意：现代 SSD、日志文件系统、快照、备份/云同步下，“覆写后删除”并不能保证 100% 不可恢复。它属于“尽力擦除”，敏感场景仍建议使用全盘加密和物理销毁。

### 10. 常见命令参数速查

| 参数 | 作用 |
|------|------|
| `-p, --password` | 命令行提供密码（进程列表可见） |
| `-P, --password-file` | 从文件读取密码 |
| `--armor` | 输出/输入 ASCII armor base64 文本 |
| `--text` | 输出/输入纯 base64 文本 |
| `--key-file` | 输出或读取独立 key 文件 |
| `--cipher-file` | 输出独立密文文件 |
| `--split` | 解密时使用分离的 cipher + key |
| `--shred` | 加密后安全擦除原文件 |
| `-f, --force` | 覆盖已存在的输出文件 |
| `-t, --time-cost` | Argon2id 迭代次数 |
| `-m, --memory-cost` | Argon2id 内存 KiB |
| `-j, --parallelism` | Argon2id 并行度 |

---

## 文件格式

```
.eph 文件：                     .key 文件：
┌──────────────────────┐        ┌──────────────────────┐
│ Magic: "EPH1"   (4B) │        │ Magic: "EPHk"   (4B) │
│ Salt:  随机      (16B)│        │ Salt:  随机      (16B)│
│ Flags: 0x00      (1B) │        │ Flags: 0x00      (1B) │
│ KeyLen: u32 LE   (4B) │        │ KeyLen: u32 LE   (4B) │
│ KeyBlob          (NB) │        │ KeyBlob          (NB) │
│ Ciphertext       (NB) │        └──────────────────────┘
└──────────────────────┘
      25 + 2N bytes                  25 + N bytes
```

详见 [`docs/file-format.md`](docs/file-format.md)

---

## 威胁模型

详见 [`docs/threat-model.md`](docs/threat-model.md)

### 受保护

- 对 `.eph` 的密码学分析
- 通过错误提示猜密码（不存在 oracle）
- 胁迫交出密码（可给假密码）

### 不受保护

- **弱密码**：< 50 位熵可被暴力破解
- **多次审讯**：反复改口供会被识破
- **键盘记录器/恶意软件**
- **物理胁迫**（橡胶软管攻击）
- **内存取证**：冷启动、DMA、crash dump（`zeroize` 缓解但无法根除）
- **长度泄露**：密文长度 = 明文长度（OTP 固有限制）
- **密文篡改**：无 MAC/认证标签，OTP 密文可被逐位翻转并影响对应明文位；Ephemeris 不提供完整性保护
- **旧文件副本**：如果攻击者保留抵赖前的旧 `.eph`，可以通过对比 KeyBlob 发现抵赖

### 操作建议

1. **胁迫前执行抵赖** —— 提前准备假文件
2. **销毁原文件** —— 抵赖后安全擦除原始 `.eph`
3. **强密码** —— 5+ Diceware 单词（约 65 位熵）
4. **隐藏文件名** —— 混入普通文档
5. **配合全盘加密** —— VeraCrypt 隐藏卷纵深防御

---

## 性能优化

- **分块 XOR**：OTP 加解密使用 8 字节（`u64`）分块处理，降低循环开销并便于编译器自动向量化。
- **原地解密**：`decrypt` 直接复用解包出的 OTP key 缓冲区作为明文缓冲区，减少一次消息长度的堆分配。
- **原地抵赖**：`repudiate` 通过 `wrap_key_inplace` 原地完成 AES-CTR 包装，避免额外的 `key.to_vec()` 拷贝。

> 注：整体耗时仍主要由 Argon2id KDF 决定，上述优化主要降低大文件场景下的内存占用与峰值压力。

---

## 从源码构建

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo build --release -p ephemeris-core -p eph
cargo test --workspace --exclude ephemeris

# Python
cd ephemeris-python && pip install maturin && maturin develop && pytest
```

> 注意：Python 包的 crate 名是 `ephemeris`，因此排除 Python 包时应使用 `--exclude ephemeris`，而不是 `--exclude ephemeris-python`。

---

## 算法原创性与相关研究

### 结论

**核心密码学思想不是全新的，但当前工程实现具有一定原创性。**

Ephemeris 的组合方式是：

- OTP 保证“给定密文，任意等长明文都存在对应密钥”；
- AES-256-CTR 无认证标签封装密钥，实现“非承诺式密钥封装”；
- 抵赖时直接由 `C ⊕ P_fake` 计算假密钥。

其中“可否认加密”和“非承诺加密”都是学术界早已建立的概念，OTP 也被此前文献用于构造可否认加密方案。

### 相关公开研究

- **Deniable Encryption**
  - Canetti, Dwork, Naor, Ostrovsky, *Deniable Encryption*, CRYPTO 1997.
  - 这是可否认加密的奠基性工作之一。

- **Non-Committing Encryption**
  - 与自适应安全多方计算相关，由 Canetti、Feige、Goldreich、Naor 等工作引入。
  - 非承诺加密允许密文在揭示时可以“解释”为不同的消息，与 Ephemeris 的目标一致。

- **Deniable Encryption using One Time Pads**
  - Amrutiya, Baskaran, Iyengar, AICTC '16.
  - 该论文明确提出使用 One Time Pad 从密文生成假消息，思路与 Ephemeris 的消息级 OTP 抵赖非常接近。

- **Sender-Deniable / Receiver-Deniable Encryption**
  - 后续有大量公钥、交互式、量子等方向的研究，但 Ephemeris 采用更简单的对称密码 + 口令封装路径。

### Ephemeris 的原创部分

- 将 OTP 抵赖思想落地为可操作的单文件格式 `.eph` / `.key`；
- 使用 Argon2id 派生 AES-256-CTR 的密钥与 nonce，构造“无认证标签”的非承诺密钥封装；
- 提供 Rust API、CLI、Python 绑定；
- 明确讨论长度泄露、多次审讯、旧文件副本等现实威胁模型。

> 本说明基于公开文献与网络检索，属于项目层面的技术来源说明，不构成专利或法律意见。

---

## 安全审计

经过三维度安全审计（密码学设计审查 + 代码漏洞扫描 + 实际攻击尝试），发现的问题已全部修复。

---

## 对比

| 系统 | 可否认 | 安全级别 | 存储 | Oracle |
|------|--------|---------|------|--------|
| **Ephemeris** | 消息级 | 信息论（OTP 层） | 单文件 | 无 |
| VeraCrypt | 卷级 | 计算安全 | 磁盘 | 无 |
| Age / GPG | 无 | 计算安全 | 单文件 | 有 |

---

## 许可证与免责声明

MIT — [LICENSE](LICENSE)

⚠ 免责声明：Ephemeris 提供密码学可否认性，非法律保护。部分司法管辖区可能限制可否认加密工具的使用。
