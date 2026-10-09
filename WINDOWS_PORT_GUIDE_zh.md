# Freer Windows 移植简明指南

写给准备把 Freer 移植到 Windows 的朋友。这是一份整体介绍，帮你决定先看什么、用什么技术栈、哪些坑要提前知道。

## 1. 三个仓库

都在 https://github.com/nobodyoffc 下：

| 仓库 | 内容 | 对你的用途 |
|---|---|---|
| [freer-mac](https://github.com/nobodyoffc/freer-mac) | Mac 客户端（Swift） | **主要参考实现** |
| [Freeverse](https://github.com/nobodyoffc/Freeverse) | 协议文档（`Protocols/`）+ 服务端（Java，`FC-JDK`） | 协议规范；线上行为的最终依据 |
| [Freer](https://github.com/nobodyoffc/Freer) | Android 客户端（Java，核心库 `FC-AJDK`） | 第二参考，用来对照 |

## 2. 参考优先级

**协议文档说"是什么"，Mac 代码说"怎么做"，服务端代码说"线上到底收什么"。**

1. **Mac 客户端为主。** 它是目前最新、修正最多的实现，而且同为桌面应用，窗口布局、文件处理等可以直接借鉴。它分层清楚，可以逐层移植、逐层验证：
   - `Packages/FCCore`：密码学、密钥、地址、交易构造与签名（约 9k 行）
   - `Packages/FCTransport`：FUDP 传输、FAPI 客户端（约 14k 行）
   - `Packages/FCStorage`：加密存储
   - `Packages/FCDomain`：业务逻辑——钱包、IM、邮件、Secret、HAT、评价、服务发现等（约 9 万行，最大的一块）
   - `Packages/FCVoice`：语音（Opus 编解码 + 抖动缓冲）
   - `Sources/FreerForMac`：界面（SwiftUI），只需参考交互，不必照搬
2. **协议文档作为规范。** `Freeverse/Protocols/` 下：
   - `FEIP`：链上 OP_RETURN 数据协议（CID、Service、Home、Contact、Secret、Reputation…）
   - `FAPI`：服务接口（BASE、DISK、DOCK、MAP、ROAD、CALL…），另见 `Docs/FAPI-API-Reference.md`
   - `FUDP`：加密 UDP 传输
   - `FTSP`：密码算法规范，`FTSP/vectors/` 里有**测试向量**，务必用来做单元测试
   - `IM`：即时通讯（FIMP），同一协议有多个版本时以最高版本为准，并对照 Mac 代码确认
   - `FVEP`：通用概念（ID、时间、货币、币天、HAT 等）
3. **服务端代码是最终裁判。** 文档和客户端对不上时，看 `Freeverse/FC-JDK/src/main/java/` 下的 `fapi`、`fudp` 实际怎么处理。
4. **Android 作为对照。** Mac 某处看不懂时，看 Android 怎么写的。但注意 Android 有个别已知问题在 Mac 上已修正，两者冲突时以 Mac 为准。

## 3. 技术栈建议

**Electron 可行，推荐 Electron + TypeScript。** 需要的能力 Node 都有：UDP（`dgram`）、文件系统、原生加密库，界面用 Web 技术也最省事。

关键原则：**私钥、加密、网络、存储全部放在主进程（或 utility process），渲染进程只做界面**，通过 `contextBridge` + IPC 通信，开启 `contextIsolation`、关闭 `nodeIntegration`。这是钱包应用，渲染进程被 XSS 不能等于私钥泄露。

推荐库：

| 用途 | 库 |
|---|---|
| secp256k1、x25519、ed25519 | `@noble/curves` |
| SHA-256、RIPEMD-160、HKDF、Argon2id | `@noble/hashes` |
| AES-GCM、ChaCha20-Poly1305 | `@noble/ciphers` |
| 本地数据库 | `better-sqlite3` |
| 加密主密钥的系统级保护 | Electron `safeStorage`（Windows 上即 DPAPI） |
| 语音 Opus | 原生模块或 WASM 版 Opus |

noble 系列是纯 JS、经过审计，可以避免 Windows 上编译原生加密模块的麻烦。

**其他选择（仅供参考）：**
- **Tauri + Rust**：安装包小得多、内存占用低，核心逻辑用 Rust 也更稳。如果你熟悉 Rust，这是更好的选择；不熟的话学习成本较高。
- **Kotlin + Compose Desktop**：可以部分复用 `FC-JDK` / `FC-AJDK` 的 Java 代码，省掉重写密码学和交易层。但这些库带有服务端和 Android 依赖，需要裁剪。

如果没有特别偏好，就用 Electron。

## 4. 建议的开发顺序

1. **FCCore 层**：密钥、地址（FID）、签名、加解密。全部用 `FTSP/vectors` 和 Mac 单元测试的数据对拍，结果一字节不差再往下走。
2. **交易**：构造并广播一笔 FCH 转账，上主网验证。
3. **FUDP + FAPI**：连上服务器，完成握手，调通 BASE 查询（余额、身份、服务）。
4. **钱包 + 身份**：导入/创建身份、主 FID、收发 FCH。
5. **IM**：一对一聊天，然后群组。
6. **其他服务**：DISK（文件）、Mail、Secret、HAT、评价等。
7. **语音**：最后做。

每一步都能和 Mac/Android 客户端互通，就是最好的验收方式。

## 5. 文档里没写清楚、但必须知道的坑

- **FCH 的 P2PKH 签名必须用 BCH-Schnorr。** 用 ECDSA-DER 签名会被主网拒绝，而且报错是误导性的 `CHECKMULTISIG` 错误。BCH-Schnorr 和比特币的 BIP340 Schnorr **不是一回事**，不能直接用 `@noble/curves` 的 schnorr，要按 `FCCore/Crypto/BchSchnorr.swift` 自己实现。
- **FEIP16（Reputation 评价）的被评价人在 `data.fid` 字段里**，不是交易输出。旧版文档写错过。
- **评价分数范围 0–5，`cause` 字段可选。**
- **应用索引从不写 `closed` 字段。** 查询时用 `closed=false` 会什么都查不到，要用"排除 `closed=true`"。
- **查服务要用 `base.getByIds`，参数 `entity: "service"`。** 旧的 `base.serviceByIds` 已不存在，服务端返回 404，而 404 往往被当成"没有记录"，导致静默失败。
- **FUDP 客户端的"发送→等回复"必须串行。** 多个请求同时进行时，回复会被别的请求吃掉，表现为莫名其妙的超时。Mac 端在 `FudpClient` 里加了先进先出的锁。
- **主 FID 跟随 Home（FEIP9）里的 BASE 选择服务器**，切换前要校验服务商密钥。详见 Mac 端相关代码。
- **界面上显示 ID 时，从中间省略**（头部…尾部），不要只留前缀，否则用户无法核对尾号。

## 6. 遇到问题

先在 Mac 代码里搜同名类型或函数；文档与代码冲突时看服务端；仍有疑问直接联系我们。欢迎在 GitHub 上提 issue。
