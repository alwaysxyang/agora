# Agora

Agora 是一个 Rust workspace，包含可组合的 agent/channel daemon、公共运行时组件，以及面向 macOS 的进程级沙箱。

## 目录

- `crates/agora-core`：生命周期、日志等公共能力。
- `crates/agora-node`：agent、channel 与 daemon 编排。
- `crates/agora-server`：服务端入口。
- `crates/agora-sandbox`：macOS hook、加密 COW 文件系统、SMB 远程文件系统、网络与 TLS 代理。
- `spec/`：架构、配置和运行时行为规范。

## 构建

需要 Rust 2024 edition 工具链。macOS 沙箱还需要 Xcode Command Line Tools。

```bash
cargo build --workspace
cargo build --release -p agora-sandbox
```

## 运行沙箱

创建 `sandbox.json`：

```json
{
  "workdir": "~/.agora-sandbox",
  "tls": "auto",
  "filesystem": {
    "local": {
      "encrypt": "encrypted",
      "key": "请替换为高强度密钥"
    },
    "nfs": []
  },
  "log": {
    "file": "runtime/logs/sandbox.log"
  }
}
```

启动 shell：

```bash
./target/release/agora-sandbox run -c ./sandbox.json -e '/bin/bash'
```

`workdir`、`tls`、本地文件系统、NFS 列表和日志路径均有默认行为，具体语义以 [沙箱架构规范](spec/architecture/sandbox.md) 为准。加密 workspace 不自动兼容旧的密文格式；格式发生不兼容变化时应使用新的 `workdir`。

## 验证

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --jobs 16 -- -D warnings
cargo test --workspace --all-targets --jobs 16
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

更多设计说明见 [spec/README.md](spec/README.md)。
