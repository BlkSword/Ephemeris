# Ephemeris

**消息级可否认加密库 —— 信息论安全。**

加密一条消息。被胁迫时，证明它解密为另一份无害内容。任何数学手段都无法区分真假。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)

*English version: [README_EN.md](README_EN.md)*

## 原理

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
- **非承诺密钥封装**：AES-256-CTR 无认证标签 —— 所有密码都产生"有效"输出，无法通过报错区分密码正确性。
- **抵赖无需真密码**：`repudiate` 直接从密文算出假密钥，胁迫场景下无需输入真实密码。

## 快速开始

### Rust

```bash
cargo add ephemeris-core
```

```rust
use ephemeris_core::*;

let params = Argon2Params::default();

// 加密
let result = encrypt(b"发射代码: ALPHA-42", b"secret-password", &params);

// 解密
let pt = decrypt(&result.eph_file, b"secret-password", &params).unwrap();

// 抵赖 —— 声称是日记（注意等长！）
let fake = repudiate_eph(
    &result.eph_file,
    b"Dear diary: boring day",
    b"diary-password",
    &params,
).unwrap();
```

### Python

```bash
pip install ephemeris
```

```python
import ephemeris

data = ephemeris.encrypt(b"发射代码: ALPHA-42", b"secret-password")
plaintext = ephemeris.decrypt(data, b"secret-password")
fake_data = ephemeris.repudiate_eph(data, b"Dear diary: boring day", b"diary-pw")
```

### CLI

```bash
cargo install eph

eph encrypt secret.txt secret.eph      # 加密
eph decrypt secret.eph output.txt      # 解密
eph repudiate secret.eph cover.eph fake.txt  # 抵赖
eph info secret.eph                    # 查看元数据
```

## 安全属性

| 属性 | 保证 |
|------|------|
| **可否认性** | 信息论级别：C 可解密为任意等长 P' |
| **密钥封装** | 非承诺式：所有密码都产生有效输出 |
| **抵赖** | 无需真实密码 |
| **文件格式** | 抵赖后字节级结构完全一致 |
| **时序安全** | 常量时间比较，无密码 oracle |
| **内存安全** | 零 unsafe，密钥 zeroize 清零 |

## 密码学原语

| 组件 | 算法 | 参数 |
|------|------|------|
| 加密 | One-Time Pad (XOR) | 密钥长度 = 消息长度 |
| KDF | Argon2id | t=2, m=37888 KiB, p=1 |
| 密钥封装 | AES-256-CTR | 128-bit 大端计数器, 无 MAC |
| 盐 | OS CSPRNG | 128 bits |
| 随机数 | getrandom / BCryptGenRandom | OS 级 |

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

### 操作建议

1. **胁迫前执行抵赖** —— 提前准备假文件
2. **销毁原文件** —— 抵赖后安全擦除原始 `.eph`
3. **强密码** —— 5+ Diceware 单词（~65 位熵）
4. **隐藏文件名** —— 混入普通文档
5. **配合全盘加密** —— VeraCrypt 隐藏卷纵深防御

## 项目结构

```
├── ephemeris-core/        # Rust 核心库
│   ├── src/               # otp, keywrap, repudiate, format, params, error
│   ├── tests/             # deniability(proptest), integration, security_audit
│   └── benches/           # Criterion benchmarks
├── eph-cli/               # CLI 工具 (encrypt/decrypt/repudiate/info)
├── ephemeris-python/      # Python 绑定 (PyO3 + maturin)
└── docs/                  # 威胁模型 + 格式规范
```

## 从源码构建

```bash
git clone https://github.com/BlkSword/Ephemeris.git
cd Ephemeris
cargo build --release -p ephemeris-core -p eph
cargo test --workspace --exclude ephemeris-python

# Python
cd ephemeris-python && pip install maturin && maturin develop && pytest
```

## 安全审计

经过三维度安全审计（密码学设计审查 + 代码漏洞扫描 + 实际攻击尝试），发现的问题已全部修复。

## 对比

| 系统 | 可否认 | 安全级别 | 存储 | Oracle |
|------|--------|---------|------|--------|
| **Ephemeris** | 消息级 | 信息论 | 单文件 | 无 |
| VeraCrypt | 卷级 | 计算安全 | 磁盘 | 无 |
| Age / GPG | 无 | 计算安全 | 单文件 | 有 |

## 许可证

MIT — [LICENSE](LICENSE)

---

⚠ 免责声明：Ephemeris 提供密码学可否认性，非法律保护。部分司法管辖区可能限制可否认加密工具的使用。
