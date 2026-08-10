# macOS 沙箱兼容性修复交接

## 当前状态

- 分支：`dev`
- 基线提交：`3499a7988034af2df9bd9c6bd7bb4771da8e0f34`
- 当前内容是未完成的 WIP 检查点，不应视为已发布修复。
- 当前生产代码不包含 Codex、SQLite、可执行文件名、数据库路径或域名特化逻辑。
- 本轮在提交前按用户要求停止继续实现和验证。

## 原始问题

### 复现方式

在 macOS 上编译 release 版本，并以加密本地文件系统配置进入沙箱：

```bash
./target/release/agora-sandbox run -c sandbox.json -e '/bin/bash'
```

在沙箱里的 shell 中启动 Codex，例如让它读取项目的 `AGENTS.md`、生成中文翻译并创建一个简单的 `README.md`。

### 可见症状

1. Codex 偶发无法初始化本地 SQLite 状态库，典型错误为：

   ```text
   failed to initialize sqlite local db at $CODEX_HOME/state_5.sqlite
   failed to initialize state runtime at $CODEX_HOME
   failed to open queue DB at $CODEX_HOME/queue_1.sqlite
   error returned from database: (code: 1032) attempt to write a readonly database
   ```

   错误可能重复嵌套出现，也可能表现为 SQLite `DBMOVED`、`IOERR` 或类似数据库损坏的报错。

2. Codex 启动明显偏慢。
3. Codex 正常退出也明显偏慢，有时需要等待较长时间才能回到外层 shell。
4. Codex 尝试执行 shell 工具时会提示默认 shell 不可用，或者子命令直接失败。进一步复现时观察到：

   ```text
   agora-sandbox: failed to adopt the inherited sandbox control lock: Bad file descriptor (os error 9)
   ```

5. 问题具有偶发性；同一命令并非每次都能稳定触发 readonly 或 shell 执行错误。

### 当时确认的原因方向

- macOS SQLite 会使用 `guarded_open_np`、guarded write 和 `guarded_close_np`。这些 API 未被 Hook 时，主数据库、WAL、SHM 可能分别落入 overlay 与宿主文件视图，文件身份也可能不一致。
- 加密文件首次打开需要解密到匿名明文文件；每次独立 open 都可能重复创建和解密快照。SQLite 会频繁打开 DB、WAL、SHM，因此成本被放大。
- 每次小写入原先至少经历 `BeginWrite`、`FinishWrite`、`Sync` 三次 Broker 请求，并立即加密回写。SQLite 初始化期间的大量小块写入会放大启动耗时。
- 退出阶段可能同时经过子进程 atexit 同步、显式 close 同步、Broker `Close` 同步和 `flush_all()`，导致同一批文件重复加密、重复 durable flush 和重复 fsync。
- clean 文件在部分路径中仍会执行 `sync_all()`，进一步放大退出耗时。
- Codex 的子进程会启用内层 macOS Seatbelt，并可能使用 `POSIX_SPAWN_CLOEXEC_DEFAULT`。内层策略会禁止新建内部 loopback/Unix 连接；CLOEXEC-default spawn 还会关闭未显式保留的控制 fd。如果环境中仍保留旧 fd 编号，Hook 恢复 execution、audit 或 filesystem 控制流时会得到 `EBADF`，最终表现为 shell 启动或命令执行失败。

### 原始修复要求

- 修复必须面向通用加密文件 I/O 和嵌套沙箱行为，不能添加 Codex 特化逻辑。
- 保持 macOS 普通 open 的独立 offset/flags、guarded fd 语义以及 `fsync`、`msync`、close 的同步语义。
- 同一 backing inode 的明文视图必须保持一致；dirty range 应由 Broker 合并并短时批量回写。
- clean 文件跳过 durable flush；退出阶段只保留一个最终刷新责任方，避免重复加密和 fsync。
- 长期打开文件需要定期写回，不能依赖进程 close 后密文才更新。
- 保持现有分层和模块职责清晰，改动应兼容现有工作负载并易于独立验证、回滚。
- 验证必须覆盖 SQLite WAL、真实 Codex 状态库初始化、启动/退出耗时，以及内层 Seatbelt/CLOEXEC 场景下的 shell 实际执行。

## 当前已改内容

### 1. macOS guarded 文件 API

- Hook `guarded_open_np`、`guarded_open_dprotected_np`、`guarded_close_np`。
- Hook `guarded_write_np`、`guarded_pwrite_np`、`guarded_writev_np`。
- 原生透传继续调用对应 guarded API；加密文件沿用现有打开、写入和关闭管线，并保留调用方 fd guard。
- 增加 C variadic shim、Rust ABI 声明及相关回归测试。

目的：避免 SQLite 主库、WAL、SHM 在 guarded 与普通文件调用之间落入不同文件视图。

### 2. 加密文件稳定身份

- VFS 在提交加密打开后读取密文 backing 文件的 device/inode。
- Hook 对已注册的加密明文描述符修正用户可见 `fstat` 身份。
- dup、fork/exec 恢复的描述符携带逻辑 backing 身份。
- 增加 path `stat` 与 fd `fstat` 身份一致性覆盖。

目的：避免匿名明文描述符身份变化触发 SQLite 的 `SQLITE_READONLY_DBMOVED` 或 I/O 错误。

### 3. Local Broker 写回与 durable flush

- `FinishWrite` 接管已完成 dirty range，不再由客户端每次写入后额外发送一次 `Sync`。
- 单一快照的写入在 10 ms 窗口内合并；存在 live peer 时仍在回复前同步，保持多次独立 open 的可见性。
- 同一密文 inode 共享同步及 durability 状态，同时保留各 open 独立的匿名描述符、offset 和 flags。
- close 请求携带最后的 hook-side ranges，减少重复同步。
- clean durable sync 跳过无意义的 `sync_all()`。
- Broker 最终 flush 先收集 live handle，再按 backing identity 去重 durable flush。
- idle Broker 通过 `writeback_pending` 避免无 dirty range 时持续创建 blocking 扫描任务。
- 添加 writeback 合并、peer visibility、clean durable sync、close 和最终 flush 回归测试。

目的：降低 SQLite 大量小写入时的 Broker 往返、重复加密和重复 fsync 放大。

### 4. 内层 macOS 沙箱控制通道兼容

- 新增 `platform/macos/hook/control.rs`，集中建立、认证、继承和恢复内部控制流。
- audit、execution、local filesystem Broker、remote filesystem Broker 增加认证 `Ping`，允许一条预认证流保持为多请求 fallback。
- 普通请求仍优先使用新短连接；仅连接级失败时回退到继承流。
- `ipc.rs` 增加匿名 lock descriptor、进程间 byte-range lock 和进程内 mutex，序列化共享流。
- fork 后只重置进程内 mutex；不同服务使用独立 lock slot。
- 如果 `POSIX_SPAWN_CLOEXEC_DEFAULT` 清除了继承 fd，Hook 会先安全复制/认证现有 fd，失败后再尝试从配置端点重建完整控制流。
- 增加内层 `sandbox-exec` 禁止新网络连接，以及 CLOEXEC-default spawn 的回归覆盖。
- execution、audit、local Broker、NFS 协议版本已相应递增。

目的：Codex 只是复现负载；实际修复针对任何会启用内层 Seatbelt 或使用 CLOEXEC-default spawn 的工作负载。

### 5. 测试与规范

- 增加 SQLite WAL 初始化、提交、checkpoint 和重新打开的集成测试。
- 更新 `spec/architecture/modules.md`、`sandbox-network.md`、`sandbox.md`，描述 guarded API、稳定身份、写回语义和继承控制通道。

## 已从本次工作树移除

- `agora-core` 生命周期并行清理改动。
- CLI/Sandbox shutdown handle 和信号终止流程改动。
- 独立的 interposed-fork 精确快照竞态修复及其测试。
- 两份过程性设计/实施计划文档。

这些内容与当前 SQLite 只读和普通启停性能问题没有直接因果关系，不应混入检查点。

## 已运行过的检查

以下检查曾在较早的工作树状态通过：

- `cargo check -p agora-sandbox --all-targets`
- `cargo check -p agora-core --all-targets`
- `cargo clippy -p agora-sandbox --all-targets --all-features -- -D warnings`
- `cargo test -p agora-core --all-targets`
- `cargo test -p agora-sandbox --lib`（当时 685 tests passed）
- `cargo test -p agora-sandbox --test runner`（当时 70 tests passed）
- callback、cli、fork_guard 集成测试
- `cargo build --release -p agora-sandbox`
- CLOEXEC-default 控制流重建聚焦测试

注意：上述结果早于最后的控制流重建和范围清理，不能作为当前提交的最终验证结论。

`just spec-check` 未执行成功：本机没有 `just`，仓库中也没有发现等价的 Justfile 或 spec-check 脚本。

## 未完成项

1. 对当前检查点重新运行 `cargo fmt --check`。
2. 对当前检查点重新运行 agora-sandbox 聚焦测试和完整 crate 测试。
3. 运行 workspace tests 和 workspace Clippy，确保零 warning、零 error。
4. 运行覆盖率：

   ```bash
   cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
   ```

5. 重新构建 release 二进制。
6. 重新运行真实 Codex 端到端验证。
7. 在隔离 `CODEX_HOME` 下检查：
   - 初始化及退出不再出现 readonly database、DB moved 或 I/O error。
   - state、queue、WAL、SHM 的 `PRAGMA integrity_check` 通过。
   - 启动和退出耗时相较基线明显下降。
   - Codex 触发内层只读 Seatbelt 后仍能执行 shell 工具。
   - 不再出现默认 shell 不可用、控制 lock `EBADF` 或控制服务连接失败。
8. 当前 CLOEXEC 回归和内层 network-deny 回归是两个独立测试；需要确认真实 Codex 的组合路径也通过。
9. 清理 CLOEXEC helper 中临时保留的诊断输出。
10. 做一次逐 hunk 范围审计。当前检查点仍同时包含“SQLite/加密 I/O”与“内层控制通道”两组改动；正式合并前建议拆为两个可独立编译、测试和回滚的提交。
11. 检查并清理验证期间遗留的 `/private/tmp/agora-phase1-*` 临时目录和忽略的本地验证配置，不能把认证信息或本机路径加入 Git。
12. WebSocket 问题尚未开始诊断或实现，必须作为后续独立改动处理。

## 建议继续顺序

1. 先确认当前 WIP 可以格式化和编译。
2. 将 SQLite/加密 I/O 与继承控制通道拆成两个独立提交。
3. 分别运行聚焦测试，再运行 workspace tests、Clippy 和覆盖率。
4. 做真实 Codex 端到端验证。
5. 两组修复稳定并推送后，再单独复现和处理 WebSocket。

## Spec consistency

当前代码和三份已修改的 `spec/architecture/` 文档按现有 WIP 设计保持一致；如果拆分提交，必须同步拆分相应规范段落。
