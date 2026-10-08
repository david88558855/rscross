# rscross 总体架构与技术选型

> 版本：0.1.0 ｜ 适用代码：本仓库 `main` 分支
> 本文回答三件事：**两个传输库各干什么**、**进程内部长什么样**、**出错与并发怎么处理**。

---

## 1. 技术选型说明

### 1.1 为什么是两个传输库而不是一个

| 库 | 它真正解决的问题 | 它不解决的问题 |
|---|---|---|
| **FerroTunnel** (`ferro-labs/ferrotunnel` 1.5) | 「内网节点如何被公网访问」：客户端**主动外连**到公网服务端，天然穿透 NAT；把多条逻辑隧道多路复用到一条连接；按 `Host` 做 HTTP 路由；内置 token 握手、限速、连接池、Prometheus/OTel | 不提供点对点直连。**所有流量都必须经服务端**，服务端出口带宽即成瓶颈与隐私单点 |
| **Iroh** (`n0-computer/iroh` 1.3) | 「两个节点如何直连」：按**公钥**寻址，QUIC + 打洞，失败自动落到 Relay；同时提供密钥交换与节点发现 | 不提供「按 Host 路由到某个内网服务」这种业务语义；没有配置下发、鉴权、审计、控制台 |

两者不是竞争关系，而是「**直连优先 + 中继兜底**」的两条腿：

```
                        ┌──────────── rscross-server（公网） ─────────────┐
                        │ 控制面: axum API + 内嵌 Web 控制台 + SQLite      │
                        │ 数据面: FerroTunnel Server (控制端口 + HTTP 入口)│
                        │ 直连面: Iroh Endpoint（打洞协调 / 探测 / 投递）  │
                        └────────────────┬───────────────────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │ 路径 A：P2P 直连（Iroh） │ 路径 B：中继（FerroTunnel）│
              │ 流量不过服务端           │ 流量经服务端              │
              ▼                          ▼                          ▼
       ┌─────────────────────────────────────────────────────────────┐
       │ rscross-client（内网）                                       │
       │  Iroh Endpoint + ALPN_DATA 处理器  ／ 每隧道一个 Ferry Client │
       └─────────────────────────────────────────────────────────────┘
```

### 1.2 需求 1 要求的四项能力，分别由谁承担

| 能力 | 承担者 | 在本仓库中的落点 |
|---|---|---|
| **打洞** | **Iroh** | `crates/rscross-transport/src/p2p.rs::P2pNode::bind`。底层是 QUIC over UDP + QAD（QUIC Address Discovery）+ 双向打洞；`net_report` 负责探测 NAT 类型与公网映射。客户端与服务端都用 `presets::N0` 建节点 |
| **中继** | **两条腿都有** | ① Iroh Relay：打洞失败时由 Iroh 自己无缝回退，应用层无感知；`relay_mode` 支持 `n0`（官方公共中继）/ `custom`（**自建 iroh-relay**，配置 `p2p.relay_urls`）/ `disabled`。② FerroTunnel Server：`bind`（控制面）+ `http_bind`（HTTP 入口），是「一定能通」的兜底路径 |
| **密钥交换** | **Iroh** | 每个节点一把 Ed25519 `SecretKey`，其公钥即 `EndpointId`，同时充当 QUIC/TLS 1.3 的证书身份 —— 连接的加密与**双向认证**是协议内建的，不依赖 CA。私钥持久化在 `state_dir/node.key`（0600），因此 EndpointId 稳定、可作为节点指纹展示。FerroTunnel 那一侧另有一层 rustls TLS 1.3（`tunnel.tls_enabled`），并且它的握手 token 只作为**传输层凭证** |
| **节点发现** | **Iroh** | `presets::N0` 会挂载 `PkarrPublisher` + `PkarrResolver` + `DnsAddressLookup`：把自己的 `EndpointAddr`（Relay URL + 直连地址 + 端口映射结果）发布到 DNS/Pkarr，对端**只凭 EndpointId** 即可解析寻址。是否启用由 `p2p.address_lookup` 控制；`Endpoint::addr()` 的结果也会随心跳上报控制面，作为第二条发现通道（自建场景下不依赖公网 DNS） |

> **实现细节**：`EndpointAddr` 的 JSON 形态在注册响应里下发给客户端（`server_endpoint_addr`），
> 因此即便 `address_lookup = false`（纯内网/离线环境），双方仍能通过控制面交换寻址信息。

### 1.3 其余技术选型

| 领域 | 选择 | 理由 |
|---|---|---|
| 异步运行时 | **tokio**（multi-thread） | Iroh 与 FerroTunnel 都基于 tokio，别无选择 |
| HTTP/控制台 API | **axum 0.8** | 与 tokio/hyper 同源；`State` + `Router` 心智负担低 |
| 持久化 | **rusqlite（bundled）** | 单文件、零外部依赖，静态二进制友好；WAL 提供读并发 |
| 密码学 | **argon2**(Argon2id) + **sha2** | 密码用内存硬 KDF；token 只存 SHA-256 摘要 |
| 前端 | **零构建步骤的原生 HTML/CSS/JS** + `rust-embed` | 保证「服务端 = 单一二进制」，同时让 CI 不需要 Node 工具链（见 `docs/BUILD.md` §3） |
| 日志 | **tracing** + 自研 `Layer`（`logbus.rs`） | 控制台「日志」页需要结构化的 `(level, target, message)`，`tracing-appender` 只给文本行 |
| 配置 | **TOML** + `serde`（全部字段 `#[serde(default)]`） | 部分配置也能加载，升级不炸旧文件；`deny_unknown_fields` 让拼写错误在启动时报出 |

---

## 2. 目录结构与模块划分

```
rscross/
├── Cargo.toml                     # workspace：统一版本、依赖与 release profile
├── rust-toolchain.toml            # channel = stable（CI 与本地一致）
├── Cross.toml                     # cross-rs 的 musl 交叉编译配置
├── Cargo.lock                     # 提交（二进制项目应锁定依赖）
├── web/                           # 前端源码（被 rust-embed 打进服务端二进制）
│   ├── index.html
│   ├── app.css
│   └── app.js
├── crates/
│   ├── rscross-common/            # ① 共享层：Error / Result、ID、协议常量、控制面 DTO
│   ├── rscross-config/            # ② 配置：ServerFile / ClientFile、校验、读写
│   ├── rscross-store/             # ③ 持久化：SQLite schema、DAO、统计聚合
│   ├── rscross-auth/              # ④ 鉴权原语：Argon2、token、会话、登录限流
│   ├── rscross-transport/         # ⑤ 传输层：Iroh 适配 + FerroTunnel 适配 + 路径选择
│   │   ├── p2p.rs                 #    Iroh：绑定/拨号/ALPN 处理器/流首部协议/私钥
│   │   ├── relay.rs               #    FerroTunnel：Server 与 per-tunnel Client 封装
│   │   ├── path.rs                #    路径选择器（原子量，读路径无锁）
│   │   └── forward.rs             #    双向字节搬运 + 人类可读字节数
│   ├── rscross-server/            # ⑥ 服务端（lib + bin）
│   │   ├── bootstrap.rs           #    启动编排、任务监督、优雅关停
│   │   ├── state.rs               #    AppState：所有子系统的共享句柄
│   │   ├── logbus.rs              #    tracing Layer → 环形缓冲 + broadcast
│   │   ├── console.rs             #    rust-embed 静态资源与 SPA 回落
│   │   └── api/{mod,auth,client,agent,misc}.rs
│   └── rscross-client/            # ⑦ 客户端（lib + bin）
│       ├── agent.rs               #    注册/心跳/隧道收敛/日志上报
│       ├── api.rs                 #    控制面 HTTP 客户端（DTO 镜像）
│       ├── identity.rs            #    状态目录：身份、节点私钥、一次性令牌
│       └── logsink.rs             #    WARN/ERROR 采集，批量上报
├── tests/e2e/e2e.py               # 两个真实二进制的端到端验收
└── .github/workflows/{ci,release}.yml
```

### 依赖方向（严格单向，无环）

```
rscross-common  ←  rscross-config  ←  rscross-server
      ↑                  ↑                ↑
      │            rscross-store          │
      │                  ↑                │
      ├────────  rscross-auth ────────────┤
      │                                   │
      └── rscross-transport ──────────────┘
                      ↖
                 rscross-client
```

两条刻意维持的边界：

1. **`rscross-client` 不依赖 `rscross-store`。** 客户端只需要 `DesiredTunnel` 这个 DTO
   （定义在 `rscross-common`），不该把 `rusqlite` 打进去 —— 静态二进制每 MB 都要付快递费。
2. **`rscross-common` 不依赖 iroh / ferrotunnel / rusqlite。** 外部库错误统一经
   `Error::transport(..)` / `Error::store(..)` 降级为字符串，换取「错误类型在任意层可用」。
   `rscross-transport` 则把 Iroh 的用法**收敛在 `p2p.rs` 一个文件**，上游 API 变动时改动面可见。

---

## 3. 并发模型

### 3.1 服务端任务拓扑

`#[tokio::main]` 多线程运行时，进程内**六条长生命周期任务**，全部挂在同一个
`CancellationToken` 上：

| 任务 | 数量 | 说明 |
|---|---|---|
| HTTP（axum） | 1 | 控制台 + `/api/v1/*`；`with_graceful_shutdown` 绑定关停令牌 |
| FerroTunnel Server | 1 | 内部控制面 + HTTP 入口由库自身的后台任务承载，本任务只负责 start/stop |
| Iroh 节点 | 0 | 服务端只做**拨号方**，不注册 accept 循环，因此不额外占任务 |
| 内务循环 | 1 | 15 秒一 tick：离线判定、清理过期会话、清扫登录限流；每 240 tick 做保留期清理 |
| 日志落库 | 0 或 1 | `log.persist = true` 时订阅 `LogBus` 的 `broadcast` 频道并写库 |
| 信号监听 | 1 | SIGINT/SIGTERM → `cancel()` |

关停顺序刻意设计为：**先停 HTTP**（不再接受新请求），再把其余任务按 `shutdown_grace_secs`
逐个 `timeout` 等待，最后 `P2pNode::close()`。任何任务在宽限期内没退出只记 warn，不阻塞退出。

### 3.2 共享状态的同步策略

| 数据 | 同步原语 | 理由 |
|---|---|---|
| SQLite 连接 | `Arc<std::sync::Mutex<Connection>>` + `spawn_blocking` | rusqlite 是**同步阻塞** API。全程在 `spawn_blocking` 里持锁，绝不在 async 线程上做 I/O；WAL 模式让读路径由 SQLite 自己并发化。锁中毒时取回内部值继续服务（记录 error 日志），不因一次 panic 让整个进程失能 |
| 运行期配置 | `tokio::sync::RwLock<ServerFile>` | 读写都在 async 上下文；写路径 = 校验 → 落盘 → 换内存，顺序固定，避免「内存生效了但磁盘没写入」 |
| 隧道本地目标表 | `std::sync::RwLock<HashMap>` | 纯内存查表、临界区无 `await`，用 std 锁更省（不会被 async 调度器放大） |
| 路径选择器状态 | `AtomicBool` / `AtomicU32` | 读多写极少的标志位；选路时不取锁 |
| 登录限流 | `std::sync::Mutex<HashMap>` | 同上，临界区极短 |
| 日志分发 | `std::sync::Mutex<VecDeque>` + `broadcast::Sender` | 环形缓冲给首屏、broadcast 给增量；`Lagged` 时显式记录丢弃条数而不是静默 |

### 3.3 客户端并发模型

客户端只三条任务：**主任务**（信号/收尾）、**心跳循环**、**日志上报循环**。
Iroh 的 accept 循环由 `Router` 自己持有的任务承载；每条隧道由 FerroTunnel 库内部的
后台任务承载。业务侧没有「每隧道一线程/一任务」的手写代码 —— 隧道的收敛是
**声明式**的：心跳响应给出「期望配置」，`TunnelManager::reconcile` 做差集，启动缺失的、
停止多余的、重建变了的。

这条设计的关键收益：**控制面不需要推送**。改一条隧道只要改数据库，客户端在下一个心跳
周期（默认 15 秒）自动收敛。代价是收敛有延迟，所以控制台在创建隧道时会明确提示
「客户端下次心跳（≤15 秒）生效」。

---

## 4. 错误处理

### 4.1 分层

```
rscross-common::Error          # 全工程唯一错误类型（thiserror）
  ├── Io / Json                # 有 #[from]，可直接 ?
  ├── Config / Auth / Api      # 语义类，带稳定错误码 code()
  ├── Transport / Store        # 外部库降级包装（transport() / store()）
  └── Internal                 # 兜底
```

- **库层**：一律返回 `rscross_common::Result<T>`；外部库错误在边界处降级，
  因此 `rscross-common` 不需要依赖任何一方。
- **API 层**：`ApiError` 实现 `IntoResponse`，把 `Error` 映射为
  `{code, message}` + 合适的 HTTP 状态码（`Auth → 401`、`Config/Api → 400`、
  `Transport → 502`、`Io/Store/Internal → 500`）。**内部错误细节不会泄漏到响应体之外**
  的日志里 —— 响应给出的是可操作的信息，堆栈留在服务端。
- **客户端**：控制面/中继/直连三类外部依赖全部按「本地退避重试 + 不退出进程」处理。
  指数退避 1→2→4→…→60 秒封顶（`backoff_delay`），且**可被关停信号打断**
  （`sleep_or_cancel`），不会让 Ctrl+C 等半分钟。
  唯一的例外是**鉴权类失败**（HTTP 401）：重试无意义，直接带操作提示退出
  （"请在控制台重新签发令牌"）。

### 4.2 明确的「不吞异常」约定

- `let _ = ...` 只用于**确实无关紧要**的收尾动作（关流、删临时文件、写审计）。
  凡是有语义的分支都至少 `tracing::warn!`。
- `unwrap()`/`expect()` 只允许出现在「编译期常量保证成立」的位置
  （如 `Params::new(常量…).expect("argon2 参数是常量且合法")`），
  或者锁中毒恢复（`poisoned.into_inner()` + error 日志）。
- 客户端侧 `Router` 的 `ProtocolHandler::accept` **不构造 `AcceptError`**，
  而是内部记录并在必要时 `close()` 连接 —— 避免把协议错误升级成「拒绝服务」。
- 隧道建立失败**不作为心跳失败**：单个隧道起不来只 warn 并等下一轮重试，
  不影响其它隧道与心跳本身。

---

## 5. 日志方案

### 5.1 三层输出

1. **stdout**：`tracing_subscriber::fmt`，`text` 或 `json`（`log.format`）。
   交给 systemd/journald/docker 收集。**不内置文件轮转** —— 进程管理器已经做得更好，
   自己实现只会多一份依赖和一份坑（这也是 `tracing-appender` 被裁掉的原因）。
2. **内存环形缓冲**：`LogBus`，容量 `log.ring_capacity`（默认 2000）。
   控制台「日志」页首屏直接读它，零 I/O 延迟。
3. **持久化（可选）**：`log.persist = true` 时由 `logbus` 的 `broadcast` 频道
   异步落库，可跨重启检索。

### 5.2 关键约定

- **日志级别语义**：`ERROR` = 需要人工介入；`WARN` = 已自动降级/重试；
  `INFO` = 状态变更（注册、隧道建立、配置更新）；`DEBUG` = 每次心跳、每条流的归属。
- **日志里出现结构化字段**：`tunnel=`, `local=`, `route=`, `peer=`, `skipped=` …，
  前端「日志」页与 `journalctl` 都能直接 grep。
- **敏感值绝不进日志**：初始管理员密码只走 `eprintln!`（标准错误），
  **不经过 tracing**，因此不会进入环形缓冲或数据库 —— 否则任何已登录用户都能从
  「日志」页读到它。数据库里的 token 全部只存 SHA-256 摘要。
- 日志中出现的 `tunnel`/`route` 值来自控制面配置，属于管理员输入；
  前端渲染时统一走 `esc()` 转义，防止管理员自己把自己 XSS 掉。

---

## 6. 已知边界（诚实清单）

这些是当前实现的真实限制，不是「以后再说」的托辞，每一条都写进了 `docs/ROADMAP.md` 的对应阶段：

1. **FerroTunnel 只支持单一服务端 token。** `ServerBuilder::token` 是单值。
   因此它只作为**传输层握手凭证**，业务身份由 rscross 自己的 per-client `agent_token`
   承担（可单独吊销、可审计）。若握手 token 泄漏，攻击者最多能建立一条隧道，
   但拿不到任何 API 权限；进一步加固见 ROADMAP 阶段 2「按客户端派生 token」。
2. **TCP/UDP 隧道的公网入口依赖 FerroTunnel 的协议支持。** 当前 FerroTunnel 的
   `ServerBuilder` 只暴露 `bind` 与 `http_bind`，HTTP 类隧道（按 Host 路由）开箱可用；
   原始端口映射需要在阶段 3 用「rscross 自建 ingress + Iroh 直连投递」补齐。
   路由键的统一计算已经在 `DesiredTunnel::route_key()` 里固化，两条路径不会各算一套。
3. **`p2p.relay_mode = custom` 需要自建 `iroh-relay`。** 代码路径已实现
   （`RelayMap::try_from_iter` → `RelayMode::Custom`），但仓库不提供 relay 部署编排。
4. **多副本部署时登录限流是进程内的。** 需要共享存储（Redis 等）才能跨副本生效。
5. **控制台配置是「整份替换 + token 掩码保护」**，不是字段级 PATCH。
   监听地址类变更需要重启进程（控制台会提示）。
