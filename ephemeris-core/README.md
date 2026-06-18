# ephemeris-core

消息级可否认加密 Rust 核心库。基于 OTP（一次性密码本）+ 非承诺 AES-256-CTR 密钥封装，提供信息论安全的可否认加密。

## 快速使用

```rust
use ephemeris_core::*;

// 加密
let result = encrypt(b"私密消息", b"密码", &Argon2Params::default());

// 解密
let pt = decrypt(&result.eph_file, b"密码", &params).unwrap();

// 抵赖 —— 声称是另一条消息
let fake = repudiate_eph(&result.eph_file, b"无害消息", b"假密码", &params).unwrap();
```

## 安全特性

- OTP 信息论安全 —— 密文可解密为任意等长明文
- 非承诺密钥封装 —— AES-256-CTR 无 MAC，无密码 oracle
- 零 unsafe 代码，密钥 zeroize 清零
- 常量时间比较，无时序侧信道
- Argon2id KDF，OWASP 2024 标准参数

详细文档：https://github.com/BlkSword/Ephemeris
