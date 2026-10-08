# rscross 总体架构与技术选型

> 版本：0.1.0 ｜ 对应代码：本仓库 `main` 分支
> 本文回答四件事：**控制台与节点怎么分工**、**两个传输库各干什么**、
> **进程内部长什么样**、**出错与并发怎么处理**。

---

## 1. 部署形态：一个控制台，两种跑法

rscross 把系统拆成三个角色，**同一个控制面代码服务两种部署形态**：

| 角色 | 二进制 | 职责 |
|---|---|---|
| **控制台**（Console） | `rscross-console`（独立）/ `rscross-server --embedded`（内嵌） | 唯一的管理入口：Web UI + 管理 API + 数据库 + 配置下发 |
| **服务端节点**（Node） | `rscross-server` | 数据面：FerroTunnel 中继 + Iroh 节点；向控制台注册并心跳 |
| **客户端**（Client） | `rscross-client` | 内网侧：把本地服务通过反向隧道暴露出去；向控制台注册并心跳 |

### 方式 A：中央控制台（多节点汇聚）

```
                 ┌──────────────────────────────────────────┐
                 │ rscross-console（独立二进制）             │
   浏览器 ──────▶│  Web 控制台 + 管理 API + SQLite           │
                 │  ├── POST /api/v1/node/*   节点注册/心跳  │
                 │  └── POST /api/v1/agent/*  客户端注册/心跳│
                 └───────┬──────────────────────────┬───────┘
                         │ 注册 + 心跳               │ 注册 + 心跳
             ┌───────────▼──────────┐      ┌────────▼─────────┐
             │ rscross-server #1    │      │ rscross-client   │
             │  --managed（公网）    │◀─────┤  数据面：反向隧道 │
             │  FerroTunnel + Iroh  │      │  （内网）         │
             └──────────────────────┘      └──────────────────┘
                      … N 个节点，每个节点承载若干客户端
```

> 端口约定：**独立中央控制台默认 7700**，**内嵌控制台默认 7800**。
> 两种形态可能同时存在于一台机器（先内嵌自测、再起中央控制台），端口分开既不抢占，
> 也让人从地址栏就能判断连的是哪一套。

### 方式 B：单机内嵌（自用）

```
    浏览器 ──▶ rscross-server --embedded
                ├── 内嵌控制台（同一个 Web UI / 同一套 API，端口 7800）
                ├── FerroTunnel 中继 + Iroh 节点（数据面）
                └── 自动把自己注册成「本机节点」
                        ▲
                        │ 客户端直连这台服务端的控制台地址
                rscross-client --console http://<服务端IP>:7800
```

**两条路径的差别只有三处**，其余代码完全共用：

| | 方式 A | 方式 B |
|---|---|---|
| 控制面进程 | 独立 | 与节点同进程 |
| 节点如何注册 | HTTP + `rsn_` 令牌 | 进程内函数调用（无令牌概念） |
| 客户端 `--console` | 指向控制台 | 指向服务端地址 |

控制面的代码在 `crates/rscross-control`，被 `rscross-console` 与 `rscross-server`
两个二进制同时依赖 —— 这也是「内嵌」不是「另一套实现」的原因。

> **为什么内嵌模式不走 HTTP**：自己给自己发一个令牌再拿去鉴权，只是把
> 复杂度从一个函数调用搬到一个网络往返上。`ControlPlane::ensure_node` /
> `ControlPlane::heartbeat` 让内嵌节点直接调进程内函数，同时仍然写同一张 `nodes` 表，
> 因此 UI 与审计行为完全一致。

---

## 2. 技术要求里的四项能力，分别由谁承担

| 能力 | 承担者 | 在本仓库中的落点 |
|---|---|---|
| **打洞** | **Iroh** | `crates/rscross-transport/src/p2p.rs::P2pNode::bind`。底层是 QUIC over UDP + QAD（QUIC Address Discovery）+ 打洞；`net_report` 探测 NAT 类型与公网映射。节点与客户端都用 `presets::N0` 建节点 |
| **中继** | **两条腿都有** | ① Iroh Relay：打洞失败时由 Iroh 自动回退，应用层无感知；`relay_mode` 支持 `n0`（官方公共中继）/ `custom`（**自建 iroh-relay**）/ `disabled`。② FerroTunnel Server：`bind`（控制面）+ `http_bind`（HTTP 入口），是「一定能通」的兜底路径 |
| **密钥交换** | **Iroh** | 每个节点一把 Ed25519 `SecretKey`，其公钥即 `EndpointId`，同时充当 QUIC/TLS 1.3 的证书身份 —— 加密与**双向认证**是协议内建的，不依赖 CA。私钥持久化在 `state_dir/node.key`（0600），所以 EndpointId 稳定、可作为节点指纹展示。FerroTunnel 那一侧另有一层 rustls TLS 1.3（`tunnel.tls_enabled`） |
| **节点发现** | **Iroh** | `presets::N0` 挂载 `PkarrPublisher` + `PkarrResolver` + `DnsAddressLookup`：把自己的 `EndpointAddr` 发布出去，对端**只凭 EndpointId** 即可寻址。此外控制台会把节点的 `EndpointAddr`（JSON）下发给客户端（`NodeEndpoint.endpoint_addr`），保证不依赖公网 DNS 的自建场景也能直连 |

### 两个传输库分别解决什么

| 库 | 它真正解决的问题 | 它不解决的问题 |
|---|---|---|
| **FerroTunnel** (`ferro-labs/ferrotunnel` 1.5) | 「内网节点如何被公网访问」：客户端**主动外连**，天然穿透 NAT；多条逻辑隧道多路复用到一条连接；按 `Host` 路由到具体隧道；内置 token 握手、限速、连接池、Prometheus/OTel | 不提供点对点直连。**所有流量都必须经服务端节点** |
| **Iroh** (`n0-computer/iroh` 1.3) | 「两个节点如何直连」：按公钥寻址，QUIC + 打洞，失败自动落 Relay；同时提供密钥交换与地址发现 | 不提供「按 Host 路由到内网服务」这种业务语义；没有配置下发、鉴权、审计、控制台 |

两者组合成「**直连优先 + 中继兜底**」；控制面负责把两边的坐标对齐。

---

## 3. 三位一体的三种身份与鉴权

| 身份 | 认证头 | 令牌前缀 | 谁签发 | 存什么 |
|---|---|---|---|---|
| 管理员 | `Authorization: Bearer` 或 Cookie | — | 控制台（会话） | `sessions` 表只存 SHA-256 摘要 |
| 服务端节点 | `X-Rscross-Node` | `rsn_` | 控制台「服务端节点」页 | `nodes.node_token_hash` |
| 内网客户端 | `X-Rscross-Agent` | `rsa_` | 控制台「客户端管理」页（一次性 `rse_` 令牌换取） | `clients.agent_token_hash` |

**一次完整的接入流程**（方式 A）：

```
① 控制台签发节点令牌 rsn_xxx  →  在公网机器执行：
     rscross-server --managed --console http://<ctrl>:7700 --enroll-token rsn_xxx
② 节点注册：POST /api/v1/node/enroll          → 拿到 tunnel_token（FerroTunnel 握手凭证）
③ 节点心跳：POST /api/v1/node/heartbeat       → 上报 EndpointId / 隧道端口 / 出口 IP
④ 控制台签发客户端令牌 rse_xxx → 在内网机器执行：
     rscross-client --console http://<ctrl>:7700 --enroll-token rse_xxx
⑤ 客户端注册：POST /api/v1/agent/enroll       → 拿到 agent_token + 归属节点坐标
                                                （tunnel_server / tunnel_token / EndpointAddr）
⑥ 客户端心跳：POST /api/v1/agent/heartbeat    → 拉取期望隧道，收敛本地 FerroTunnel 客户端
```

**配置下发是「拉」而不是「推」**：控制台不需要长连接，改一条隧道只改数据库，
客户端在下一个心跳周期（默认 15 秒）自动收敛。代价是收敛有延迟，所以控制台在
新建隧道时会明确提示「客户端下次心跳（≤15 秒）生效」。心跳也是**双向**的：
控制台可以在响应里改归属节点（把客户端迁到另一台节点），客户端据此重建全部隧道。

---

## 4. 目录结构与模块划分

```
rscross/
├── Cargo.toml / rust-toolchain.toml / Cross.toml / Cargo.lock
├── web/                           # 前端源码（rust-embed 编进控制面）
├── crates/
│   ├── rscross-common/            # ① 共享层：Error/Result、ID、协议常量、控制面 DTO
│   ├── rscross-config/            # ② 三份配置模型：ConsoleFile / NodeFile / ClientFile
│   ├── rscross-store/             # ③ 持久化：SQLite schema、DAO、统计聚合
│   ├── rscross-auth/              # ④ 鉴权原语：Argon2id、四类令牌、会话、失败限流
│   ├── rscross-transport/         # ⑤ 传输层：Iroh 适配 + FerroTunnel 适配 + 路径选择 + 转发
│   │   ├── p2p.rs                 #    Iroh：绑定/拨号/ALPN 处理器/流首部协议/私钥/P2P 探测
│   │   ├── relay.rs               #    FerroTunnel：Server 与 per-tunnel Client 封装
│   │   ├── path.rs                #    路径选择器（原子量，读路径无锁）
│   │   └── forward.rs             #    双向字节搬运
│   ├── rscross-control/           # ⑥ 控制面（**两种形态共用**）
│   │   ├── plane.rs               #    ControlPlane facade：serve / ensure_node / heartbeat
│   │   ├── bootstrap.rs           #    装配：开库、建初始管理员、日志、信号
│   │   ├── state.rs               #    AppState
│   │   ├── logbus.rs              #    tracing Layer → 环形缓冲 + broadcast
│   │   ├── console.rs             #    rust-embed 静态资源 + SPA/JSON 404 分流
│   │   ├── node_client.rs         #    节点侧 HTTP 客户端（feature = http-client）
│   │   └── api/{mod,auth,nodes,client,agent,misc}.rs
│   ├── rscross-console/           # ⑦ 独立控制台二进制（薄壳）
│   ├── rscross-server/            # ⑧ 服务端节点二进制
│   │   ├── node.rs                #    启动编排、心跳循环、优雅关停
│   │   ├── link.rs                #    ControlLink：embedded（进程内）/ http（远端）
│   │   └── identity.rs            #    状态目录：节点身份、Iroh 私钥
│   └── rscross-client/            # ⑨ 内网客户端二进制
│       ├── agent.rs               #    注册/心跳/TunnelManager/P2P 探测/日志上报
│       ├── api.rs                 #    控制面 HTTP 客户端（DTO 镜像）
│       ├── identity.rs            #    状态目录
│       └── logsink.rs             #    WARN/ERROR 采集，批量上报
├── tests/e2e/e2e.py               # 两种部署形态的真实二进制端到端验收
└── .github/workflows/{ci,release}.yml
```

### 依赖方向（严格单向，无环）

```
rscross-common ──┬─ rscross-config ──┐
                 ├─ rscross-store  ──┼─ rscross-control ──┬─ rscross-console
                 ├─ rscross-auth   ──┘                    └─ rscross-server
                 └─ rscross-transport ──────────────────────┘   and  rscross-client
```

三条刻意维持的边界：

1. **`rscross-control` 不依赖 `rscross-transport`。** 控制面只做编排与记录，
   数据面完全建立在节点与客户端之间 —— 因此独立控制台二进制里没有 iroh / ferrotunnel，
   也没有 rustls/ring。这让它保持在几 MB 量级。
2. **`rscross-client` 不依赖 `rscross-control` / `rscross-store`。**
   客户端只需 `DesiredTunnel` 等 DTO（定义在 `rscross-common`），
   不该把 axum / rusqlite 打进静态二进制。代价是协议结构体写了两份 ——
   这份重复由 `tests/e2e/e2e.py` 用真实二进制兜住。
3. **`rscross-common` 不依赖任何外部库。** 外部错误统一经
   `Error::transport(..)` / `Error::store(..)` 降级为字符串，换取「错误类型在任意层可用」。
   `rscross-transport` 则把 Iroh 的用法**收敛在 `p2p.rs` 一个文件**，上游 API 变动时改动面可见。

---

## 5. 并发模型

### 5.1 控制面任务拓扑

| 任务 | 数量 | 说明 |
|---|---|---|
| HTTP（axum） | 1 | 控制台静态资源 + `/api/v1/*`；`with_graceful_shutdown` 绑定关停令牌 |
| 内务循环 | 1 | 15 秒一 tick：节点/客户端离线判定、清理过期会话、清扫失败限流；每 240 tick 做保留期清理 |
| 日志落库 | 0 或 1 | `log.persist = true` 时订阅 `LogBus` 的 `broadcast` 并写库 |
| 信号监听 | 1 | 独立控制台：SIGINT/SIGTERM → `cancel()`；内嵌模式由节点进程统一监听 |

### 5.2 服务端节点任务拓扑

| 任务 | 说明 |
|---|---|
| 内嵌控制台 HTTP | 仅 `--embedded`：直接复用控制面的 `serve` |
| FerroTunnel 中继 | 库自身的后台任务承载；本任务只负责 start / shutdown |
| Iroh accept 循环 | `Router`，注册 `ALPN_CONTROL`（P2P 直连探测的应答端） |
| 心跳循环 | 上报运行时可观测信息，感知 `tunnel_token` 变化 |
| 信号监听 | 取消令牌 → 按顺序收敛 |

关停顺序：**先 cancel 令牌**（HTTP 停止接新请求、心跳跳出循环），
再按 `shutdown_grace_secs` 逐个 `timeout` 等待任务，最后关 Iroh 节点。

### 5.3 共享状态的同步策略

| 数据 | 同步原语 | 理由 |
|---|---|---|
| SQLite 连接 | `Arc<std::sync::Mutex<Connection>>` + `spawn_blocking` | rusqlite 是**同步阻塞** API。全程在 `spawn_blocking` 里持锁，绝不在 async 线程上做 I/O；WAL 让读路径由 SQLite 自行并发。锁中毒时取回内部值继续服务（记录 error），不因一次 panic 让整个进程失能 |
| 运行期配置 | `tokio::sync::RwLock<ConsoleFile>` | 写路径 = 校验 → 落盘 → 换内存，顺序固定，避免「内存生效了但磁盘没写入」 |
| 隧道本地目标表 | `std::sync::RwLock<HashMap>` | 纯内存查表、临界区无 `await` |
| 路径选择器状态 | `AtomicBool` / `AtomicU32` | 读多写极少的标志位；选路时不取锁 |
| 失败限流 | `std::sync::Mutex<HashMap>` | 临界区极短；登录与访问密钥校验共用同一原语，key 不同 |
| 日志分发 | `std::sync::Mutex<VecDeque>` + `broadcast::Sender` | 环形缓冲给首屏、broadcast 给增量；`Lagged` 时显式记录丢弃条数 |

---

## 6. 错误处理

```
rscross-common::Error          # 全工程唯一错误类型（thiserror）
  ├── Io / Json                # 有 #[from]，可直接 ?
  ├── Config / Auth / Api      # 语义类，带稳定错误码 code()
  ├── Transport / Store        # 外部库降级包装（transport() / store()）
  └── Internal                 # 兜底
```

- **API 层**：`ApiError` 实现 `IntoResponse`，把 `Error` 映射为 `{code, message}` +
  合适的 HTTP 状态码（`Auth → 401`、`Config/Api → 400`、`Transport → 502`、
  `Io/Store/Internal → 500`）。
- **节点 / 客户端**：控制面、中继、直连三类外部依赖全部按「本地退避重试 + 不退出进程」处理。
  指数退避 1→2→4→…→60 秒封顶，且**可被关停信号打断**（`sleep_or_cancel`），
  Ctrl+C 不必等半分钟。唯一的例外是**鉴权类失败**（HTTP 401）：重试无意义，
  直接带操作提示退出（"请在控制台重新签发令牌"）。
- **单调性约定**：`let _ = ...` 只用于确实无关紧要的收尾（关流、删临时文件、写审计）；
  凡是有语义的分支至少 `tracing::warn!`。`unwrap()/expect()` 只允许出现在
  编译期常量保证成立的位置，或锁中毒恢复。
- **隧道失败不等于心跳失败**：单条隧道起不来只 warn 并等下一轮重试。

### 真实竞态与它的修法（值得单独记一笔）

节点注册完成、但**第一次心跳还没落地**时，控制台里该节点的 `tunnel_port` 仍是
`NULL` → `NodeRecord::tunnel_server()` 会回落到默认端口 `7835`。
若这时恰好有客户端注册，它就会拿到错误的地址。

修法是在节点注册成功后**立刻同步发一次心跳**（`node.rs` 里那段），
把数据面端口 / EndpointId / 出口 IP 落库，再去启动心跳循环。
这个问题单测发现不了，是 e2e 里「节点端口必须与控制台一致」那条断言逼出来的。

---

## 7. 日志方案

1. **stdout**：`tracing_subscriber::fmt`，`text` 或 `json`（`log.format`）。
   交给 systemd/journald/docker 收集。**不内置文件轮转** —— 进程管理器做得更好，
   自己实现只会多一份依赖和一份坑（这也是 `tracing-appender` 被裁掉的原因）。
2. **内存环形缓冲**：`LogBus`，容量 `log.ring_capacity`（默认 2000）。
   控制台「日志」页首屏直接读它，零 I/O 延迟。
3. **持久化（可选）**：`log.persist = true` 时由 `broadcast` 频道异步落库。

约定：

- 级别语义：`ERROR` = 需人工介入；`WARN` = 已自动降级/重试；
  `INFO` = 状态变更（注册、隧道建立、配置更新）；`DEBUG` = 每次心跳、每条流。
- **敏感值绝不进日志**：初始管理员密码只走 `eprintln!`（标准错误），
  **不经过 tracing**，因此不会进入环形缓冲或数据库 —— 否则任何已登录用户都能从
  「日志」页读到它。数据库里的 token 只存 SHA-256 摘要。
- 前端渲染统一走 `esc()`，防止管理员把自己 XSS 掉。

---

## 8. 已知边界（诚实清单）

1. **FerroTunnel 只支持单一服务端 token**（`ServerBuilder::token` 是单值）。
   因此每个**节点**一份 `tunnel_token`（存在 `nodes.tunnel_token`），
   只作为该节点与其客户端之间的**传输层握手凭证**；业务身份由 per-client
   `agent_token` 承担。`nodes.tunnel_token` 以可读回的形式存库（否则无法下发给客户端）
   —— 这是当前唯一的明文密钥，仅管理员接口可见，加固方案见 ROADMAP 阶段 2。
2. **TCP/UDP 隧道的公网入口依赖 FerroTunnel 的协议支持。** 当前
   `ServerBuilder` 只暴露 `bind` 与 `http_bind`：HTTP 类隧道（按 Host 路由）开箱可用，
   原始端口映射需要阶段 3 的「自建 ingress + Iroh 直连投递」补齐。
   路由键的统一计算已经固化在 `DesiredTunnel::route_key()`，两条路径不会各算一套。
3. **`p2p.relay_mode = custom` 需要自建 `iroh-relay`**：代码路径已实现
   （`RelayMap::try_from_iter` → `RelayMode::Custom`），仓库不提供 relay 的部署编排。
4. **节点的 `tunnel_token` 轮换需要重启节点**：FerroTunnel 的 relay 只在
   启动时读取 token。控制台目前只对 `node_token` 提供轮换，心跳发现 token 不一致时
   会明确提示重启。
5. **多副本控制台时限流是进程内的**（登录 + 访问密钥校验共用 `Throttle`），
   跨副本生效需要共享存储。
6. **隧道访问密钥是 16 位十六进制（64 bit）**，刻意短到人能抄对；配套的
   失败限流是这套设计的一部分，不是可选项 —— 改长改短时必须一起看。
6. **`detect_public_host()` 只是启发式**：用 UDP `connect` 读本地路由地址。
   多网卡 / 沙箱环境请显式配置 `node.public_host`。
