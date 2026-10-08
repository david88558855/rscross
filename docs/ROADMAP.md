# rscross 分阶段实现计划与验收标准

> 总原则：**每个阶段结束时仓库必须是可编译、可运行、可回归的状态**，
> 不允许「一半的抽象层躺在那里等下一个阶段接」。
>
> 验收标准写成**语义断言**而不是形态断言：
> 「HTTP 入口按 Host 路由到了客户端本地服务」而不是「日志里出现了某个字符串 N 次」。

---

## 阶段 0：工程地基

| 项 | 内容 |
|---|---|
| 交付物 | Cargo workspace（9 crate / 3 二进制）、`rscross-common` 错误与 DTO、`rscross-config` 三份配置模型、`.github/workflows/{ci,release}.yml`、`Cross.toml` |
| 验收标准 | ① `cargo check --workspace --all-targets` 通过；② 每个 crate 的单测通过；③ 两个 musl 目标产出三个静态二进制且 `ldd` 断言「不是动态可执行文件」；④ `--print-default-config` / `--version` 在产物上可执行 |

---

## 阶段 1：控制台 / 节点 / 客户端三体拆分

**目标**：让「一个控制台管多个节点」与「单机内嵌控制台」用**同一份控制面代码**成立。

### 交付物

| 文件 | 职责 |
|---|---|
| `crates/rscross-control/` | 控制面全部代码（API + Web 资源 + 持久化 + 装配），供两个二进制复用 |
| `crates/rscross-control/src/plane.rs` | `ControlPlane` facade：`serve`（起 HTTP）+ `ensure_node` / `heartbeat`（内嵌形态的进程内通道） |
| `crates/rscross-console/` | 独立控制台二进制（薄壳，只调 `run_console`） |
| `crates/rscross-server/src/link.rs` | `ControlLink`：`Embedded`（进程内调用）/ `Http`（远端中央控制台）两种实现 |
| `crates/rscross-server/src/node.rs` | 节点启动编排：内嵌控制台 / 远端注册 / 中继 / Iroh / 心跳 |
| `crates/rscross-client/src/agent.rs` | `TunnelManager` 支持**归属节点变化**（换节点 = 全部隧道重建） |

### 验收标准

- [x] **A1 内嵌形态可用**：e2e「单机内嵌」场景断言
      服务端启动后**自动注册为本机节点**、控制台可探活、可登录、节点上报了隧道端口。
- [x] **A2 汇聚形态可用**：e2e「多节点汇聚」场景断言
      独立控制台启动 → 创建节点 → 服务端 `--managed` 接入 → 节点转为 online 且端口与控制台一致。
- [x] **A3 形态可区分**：e2e 断言独立控制台 `/health` 的 `embedded = false`。
- [x] **A4 客户端只认控制台**：e2e 断言客户端接入命令里出现 `--console` 且**不出现节点地址**
      —— 这是「迁移客户端不需要改客户端配置」的前提。
- [x] **A5 归属变化要重建**：`agent::tests::node_change_is_detected_on_any_field` 守
      「节点地址、token、或解绑，任一变化都必须触发隧道重建」。
- [x] **A6 换端口不失联**：`NodeRecord::tunnel_server()` 单测 + e2e 的端口一致性断言。
- [x] **A7 删除节点不误删客户端**：`deleting_node_detaches_clients_instead_of_dropping_them`。
- [x] **A8 首次心跳竞态**：节点注册后立即同步发一次心跳（`node.rs`），
      否则客户端可能拿到默认端口。这条是 e2e 端口断言逼出来的修复。
- [x] **A9 令牌可分型**：`token_prefixes_are_distinguishable` 守 `rsa_ / rsn_ / rse_` 三类前缀。
- [x] **A10 凭据唯一**：`node_names_and_tokens_are_unique`、`enroll_token_can_only_be_used_once`。

### 已知缺口

- `ALPN_CONTROL` 目前只用于「P2P 直连探测 + 节点信息应答」，尚未承载配置推送
  （配置仍走 HTTP 心跳，见阶段 4）。

---

## 阶段 2：打洞与中继链路

**目标**：把 Iroh 与 FerroTunnel 两条数据面真正接通，并让路径选择可观测。

### 交付物

| 文件 | 职责 |
|---|---|
| `transport/src/p2p.rs` | Iroh 节点绑定（`presets::N0` + 私钥持久化）、`RelayMode` 三态、`EndpointAddr` 序列化、`ALPN_DATA` 数据处理器、`ALPN_CONTROL` 节点信息处理器 + `probe_control` 直连探测、长度前缀流首部协议 |
| `transport/src/relay.rs` | FerroTunnel `Server` 封装（bind/http_bind/limits/rate_limits/tls）与 per-tunnel `Client` 封装 |
| `transport/src/path.rs` | `PathSelector`：`auto` / `p2p-only` / `relay-only`，连续 3 次失败才降级（防抖） |
| `transport/src/forward.rs` | TCP↔TCP 与 TCP↔QUIC 两种形态的双向搬运 |

### 验收标准

- [x] **B1 路径防抖**：`auto_falls_back_when_unhealthy` 守「直连不健康时必须选中继」；
      `needs_three_failures_to_downgrade` 守「一次抖动不得降级」。
- [x] **B2 私钥即身份**：`secret_key_file_roundtrip` 守「重启后 EndpointId 不变」。
- [x] **B3 寻址可交换**：`addr_json_roundtrip` 守「EndpointAddr 能序列化/反序列化且 id 一致」。
- [x] **B4 首部协议自洽**：越界长度被拒绝而不是 panic。
- [x] **B5 中继可构建**：空 token 必须被拒绝；limits/rate 映射自配置。
- [x] **B6 端到端数据面**：e2e 两种形态都断言
      **「经公网入口 + `Host: e2e.local` 的 HTTP 请求返回了客户端本地服务的响应体」**。
- [x] **B7 Iroh 真的被用上**：e2e 断言节点与客户端各自上报了 64 位十六进制的 EndpointId。
- [x] **B8 直连可判真**：客户端周期性 `probe_control` 真建一条 QUIC 连接，
      结果喂给 `PathSelector` 并写日志（e2e 中作为信息输出打印）。

### 已知缺口（转阶段 3）

- FerroTunnel 官方 `http_bind` 只处理 HTTP 类路由；原始 TCP/UDP 端口映射需要
  「rscross 自建 ingress + Iroh 直连投递」。
- P2P 直连目前用于「探测 + 节点信息通道」，大流量仍走 FerroTunnel 中继。

---

## 阶段 3：认证鉴权

### 交付物

- `rscross-auth`：Argon2id 原始 KDF（`v1$salt$hash`）、常数时间比较、
  三类令牌（`rsa_`/`rsn_`/`rse_`）、会话签发与校验、进程级登录限流。
- 控制面 `api/auth.rs`（登录/登出/当前用户/改密）、`api/nodes.rs` 与 `api/agent.rs`
  的 `X-Rscross-Node` / `X-Rscross-Agent` 鉴权、`AppState::require_user/require_admin`、审计落库。
- 一次性接入令牌：消费即失效 + **注册失败回滚已建客户端**（避免孤儿记录）。

### 验收标准

- [x] **C1 密码不可逆**：`password_hash_is_salted` 守「同密码两次哈希不同且都能通过」；
      `malformed_hash_is_rejected_not_panicking` 守「任何畸形存储值都返回 false 而不 panic」。
- [x] **C2 令牌不落明文**：`token_hash_is_stable_and_opaque`。
- [x] **C3 限流有效**：`throttle_locks_after_threshold`。
- [x] **C4 会话生命周期**：`session_issue_and_verify`。
- [x] **C5 端到端鉴权**：e2e 断言错误密码 → 401、无凭证访问 → 401、
      无效接入令牌 → 401、无效节点令牌 → 401、正确凭证 → 200。
- [x] **C6 审计可追溯**：e2e 断言审计里同时存在 `create_node` 与 `issue_enroll_token`。

### 下一轮加固

- [ ] **C7 按节点派生 FerroTunnel token**：把「一节点一 token」收敛为
      「服务端向 FerroTunnel 注册钩子表」，让 token 泄漏影响面收敛到单节点，
      并去掉 `nodes.tunnel_token` 的明文存储（改为进程内派生）。
- [ ] **C8 多副本登录限流**：抽 `LoginThrottle` 为 trait，提供 Redis 实现。
- [ ] **C9 角色细化**：`viewer`（只读）/ `operator`（可管隧道，不可管用户）/ `admin`。
- [ ] **C10 会话列表与踢下线**：`sessions` 表已存 `user_agent`，补一个管理页即可。

---

## 阶段 4：配置与持久化

### 交付物

- `rscross-config`：`ConsoleFile` / `NodeFile` / `ClientFile`，**每字段 `#[serde(default)]`**
  + `deny_unknown_fields` + `Option` 字段 `skip_serializing_if`，`validate()` 是唯一语义校验入口。
- `rscross-store`：SQLite schema（users / sessions / **nodes** / clients / enroll_tokens /
  tunnels / traffic_samples / logs / audit），WAL、`busy_timeout`、外键、
  `spawn_blocking` 封装、`overview()` 与 `traffic_series()` 聚合、保留期清理。
- 内务循环：节点与客户端的离线判定、会话清理、登录限流清扫、保留期清理。

### 验收标准

- [x] **D1 部分配置可加载**：`partial_toml_falls_back_to_defaults`。
- [x] **D2 默认配置可序列化**：`default_configs_roundtrip_through_toml`
      （守 `--print-default-config` 与 `save()` 不会因 `None` 字段失败）。
- [x] **D3 语义校验有效**：`offline_threshold_must_exceed_heartbeat`、
      `custom_relay_requires_urls`、`managed_mode_requires_http_console_url`、
      `embedded_mode_does_not_require_console_url`、`unknown_control_mode_rejected`。
- [x] **D4 数据一致性**：`tunnels_are_cascaded_on_client_delete`、
      `deleting_node_detaches_clients_instead_of_dropping_them`。
- [x] **D5 状态机正确**：`node_lifecycle_and_heartbeat`、`stale_nodes_are_marked_offline`、
      `clients_are_grouped_by_node`、`disabling_node_marks_status`。
- [x] **D6 统计口径**：`overview_counts_nodes_and_clients`、
      `tunnels_of_node_follow_client_ownership`。
- [x] **D7 热更新闭环**：e2e 断言 GET→PUT→GET 闭环 + 非法配置被 400 拒绝。
- [x] **D8 客户端不依赖 store**：`rscross-client` 的依赖树里没有 `rusqlite`
      （由 CI 编译期保证：一旦引入就无法通过 `cargo check`）。

### 下一轮补充

- [ ] **D9 schema 迁移框架**：当前 `user_version = 1` + `CREATE TABLE IF NOT EXISTS` 只够 0→1，
      加 `migrations/` 目录与按版本顺序执行。
- [ ] **D10 流量采样写入路径**：表与聚合已就绪，但**尚无代码往里写**（数据面还没接计数）。
      阶段 3 收尾时在 `forward` 的返回值上打点，并在 `clients` 表加 `path` 列以展示当前路径偏好。

---

## 阶段 5：控制台后端 API 与前端

### 交付物

- `rscross-control/src/api/`：`auth.rs` / `nodes.rs`（管理 + 节点侧）/ `client.rs`（客户端 + 隧道）
  / `agent.rs` / `misc.rs` / `mod.rs`，统一 `ApiError → {code,message}`，
  `console.rs` 负责静态资源与 SPA/JSON 404 分流。
- `web/`：仪表盘、服务端节点、客户端管理、隧道管理（域名解析 / 端口转发 / 私有隧道 / P2P 隧道）、日志、配置。

### 验收标准

- [x] **E1 路由不重叠**：同一路径的多方法写在同一个 `MethodRouter` 上。
- [x] **E2 未匹配 API 返回 JSON 404**：e2e 断言。
- [x] **E3 隧道创建校验**：协议白名单、`local_addr` 合法、TCP/UDP 端口在端口池内且不冲突、
      HTTP 类必须有 Host 或默认域名；名称在客户端内唯一；受 `max_tunnels_per_client` 约束。
- [x] **E3b 隧道四分类校验**：域名解析（http/https + Host）、端口转发（tcp/udp + 端口）、
      私有隧道（tcp/udp + 自动签发访问密钥、**拒绝**公网端口）、P2P 隧道（**仅 TCP** + 中继回退开关）；
      `kind` 缺省时按协议推导以兼容老调用；访问密钥可轮换且旧密钥立即失效（e2e 逐条断言）。
- [x] **E3c 控制台端口分离**：`rscross-console --print-default-config` 为 7700、
      内嵌仍是 7800：配置层单测 + e2e 的 `--check` 生成文件与真实监听断言。
- [x] **E4 端口自动分配**：`port_allocation_skips_used`。
- [x] **E5 命令可执行**：`node_command_mentions_managed_mode`、
      `enroll_command_targets_console_not_node` + e2e 的两条命令断言。
- [x] **E6 概览完整**：e2e 断言 `/overview` 同时返回节点、客户端、隧道统计。
- [x] **E7 单一产物**：`rust-embed` 把控制台打进控制面产物，部署只需拷文件。
- [x] **E8 无 XSS**：所有插值经 `esc()`；`data-*` 属性里的 id/name 同样转义。
- [x] **E9 会话过期自愈**：任意请求 401 → 清本地 token → 跳登录页。
- [x] **E11 端口转发数据面**：节点侧自建 TCP ingress（`PortIngress`）按配置动态增删监听；
      e2e 直接连公网端口并断言拿到经 Iroh 投递回来的响应。
- [x] **E12 私有 / P2P 数据面**：访问端（`rscross-client access`）凭访问密钥在本机建入口，
      经节点中继到达客户端本地服务；`/api/v1/access/resolve` 免鉴权换坐标，
      无效密钥统一 401；e2e 起真实访问端进程跑通全链路。
- [x] **E13 状态如实标注**：`data_plane_ready()` 与 `proto_ready()` 区分「分类」与「分类+协议」，
      端口转发 UDP 未实现这类差异有单测守着（`udp_port_forwarding_is_declared_unavailable`）。
- [x] **E10 危险操作有确认**：删除节点/客户端/隧道、轮换令牌均二次确认；令牌只展示一次。

### 下一轮增强

- [ ] **E11 SSE 替换轮询**（`/api/v1/stream`，日志 + 统计）。
- [ ] **E12 分页与排序**：列表接口当前一次性返回。
- [ ] **E13 请求体大小限制与超时**：给 axum 挂 `RequestBodyLimit` 与超时中间件。
- [ ] **E14 主题切换**：CSS 变量已就位（`:root`），加 `[data-theme=dark]` 覆盖块。

---

## 里程碑与依赖关系

```
阶段0 地基 ──→ 阶段1 三体拆分 ──┬─→ 阶段2 打洞/中继 ──┐
                               ├─→ 阶段3 认证鉴权 ───┼─→ 阶段4 配置/持久化 ──→ 阶段5 API/前端
                               └─────────────────────┘
```

阶段 2/3/4 之间**没有**互相阻塞：它们分别在 `transport` / `auth` / `config+store`
三个 crate 里推进，唯一交汇点是阶段 5 的 API 与页面。

## 回归门槛（每个阶段都必须满足）

1. `cargo check --workspace --all-targets` 通过。
2. 全部 `cargo test -p <crate>` 通过（CI 按 crate 并行 + 硬超时）。
3. `e2e` job 通过：**两种部署形态**各跑一遍完整链路。
4. 两个 musl 目标的三个二进制均通过静态链接断言。
5. 新增的每条验收标准都有对应断言；**断言写在它失败时想知道的语义上**。
