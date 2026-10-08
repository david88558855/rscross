# rscross 分阶段实现计划与验收标准

> 总原则：**每个阶段结束时仓库必须是可编译、可运行、可回归的状态**，
> 不允许「一半的抽象层躺在那里等下一个阶段接」。
>
> 验收标准写成**语义断言**而不是形态断言：
> 「HTTP 入口按 Host 路由到了客户端本地服务」而不是「日志里出现了某个字符串 N 次」。

---

## 阶段 0：工程地基（已完成）

| 项 | 内容 |
|---|---|
| 交付物 | Cargo workspace（7 crate / 2 二进制）、`rscross-common` 错误与 DTO、`rscross-config` 配置模型与校验、`.github/workflows/ci.yml` + `release.yml`、`Cross.toml` |
| 验收标准 | ① `cargo check --workspace --all-targets` 通过；② 每个 crate 的单测通过；③ 两个 musl 目标产出静态二进制且 `ldd` 断言「不是动态可执行文件」；④ `--print-default-config` / `--version` 在产物上可执行 |

---

## 阶段 1：打洞与中继链路（已完成，v0.1.0 核心）

**目标**：把 Iroh 与 FerroTunnel 两条数据面真正接通，并让路径选择可观测。

### 交付物

| 文件 | 职责 |
|---|---|
| `crates/rscross-transport/src/p2p.rs` | Iroh 节点绑定（`presets::N0` + 私钥持久化）、`RelayMode` 三态、`EndpointAddr` 序列化、`ALPN_DATA` 处理器、长度前缀流首部协议、连通性探测 |
| `crates/rscross-transport/src/relay.rs` | FerroTunnel `Server` 封装（bind/http_bind/limits/rate_limits/tls）与 per-tunnel `Client` 封装 |
| `crates/rscross-transport/src/path.rs` | `PathSelector`：`auto` / `p2p-only` / `relay-only`，连续 3 次失败才降级（防抖） |
| `crates/rscross-transport/src/forward.rs` | TCP↔TCP 与 TCP↔QUIC 两种形态的双向搬运 |
| `crates/rscross-client/src/agent.rs` | `TunnelManager`：声明式收敛隧道集合 |

### 验收标准

- [x] **A1 静态与单元**：`cargo test -p rscross-transport` 通过。其中
      `path::tests::auto_falls_back_when_unhealthy` 守「直连不健康时必须选中继」，
      `needs_three_failures_to_downgrade` 守「一次抖动不得降级」。
- [x] **A2 私钥即身份**：`secret_key_file_roundtrip` 守「重启后 EndpointId 不变」。
- [x] **A3 寻址可交换**：`addr_json_roundtrip` 守「EndpointAddr 能序列化/反序列化并保持 id 一致」，
      即控制面可以承担第二条节点发现通道。
- [x] **A4 首部协议自洽**：`write_stream_key`/`read_stream_key` 成对；越界长度被拒绝而不是 panic。
- [x] **A5 中继可构建**：`relay_server_builds_with_valid_config` / `relay_tunnel_client_builds_with_valid_config`；
      空 token 必须被拒绝（`empty_token_is_rejected`）。
- [x] **A6 端到端（CI `e2e` job，真实二进制）**：
      `e2e.py` 断言 **「经公网入口 + `Host: e2e.local` 的 HTTP 请求返回了客户端本地服务的响应体」**
      —— 这条同时覆盖了「客户端建立反向隧道」「服务端路由键与客户端路由键一致」「字节确实被搬运」三件事。
- [x] **A7 Iroh 真的被用上了**：`e2e.py` 断言客户端上报的 `endpoint_id` 是 64 位十六进制
      —— 由 Iroh `SecretKey` 派生，不是硬编码占位符。

### 已知缺口（转下一阶段）

- FerroTunnel 官方 `http_bind` 只处理 HTTP 类路由；原始 TCP/UDP 端口映射需要
  阶段 3 的「rscross 自建 ingress + Iroh 直连投递」。
- 服务端当前只作为 Iroh **拨号方**；`ALPN_CONTROL`（服务端→客户端的配置推送）已预留常量但未注册。

---

## 阶段 2：认证鉴权（已完成基础，含加固项）

**目标**：控制台与管理 API 有完整的身份体系；Agent 与业务身份解耦。

### 交付物

- `crates/rscross-auth`：Argon2id 原始 KDF（`v1$salt$hash`）、常数时间比较、
  `rsa_`/`rse_` 前缀的双类 token、会话签发与校验、进程级登录限流。
- 服务端：`api/auth.rs`（登录/登出/当前用户/改密）、`api/agent.rs` 的
  `X-Rscross-Agent` 鉴权、`AppState::require_user/require_admin`、
  `audit` 落库。
- 一次性接入令牌：`enroll_tokens` 表 + 消费即失效 + **注册失败回滚已建客户端**（避免孤儿记录）。

### 验收标准

- [x] **B1 密码不可逆**：`password_hash_is_salted` 守「同一密码两次哈希不同且都能验证通过」；
      `malformed_hash_is_rejected_not_panicking` 守「任何畸形存储值都返回 false 而不 panic」。
- [x] **B2 令牌不落明文**：`token_hash_is_stable_and_opaque` 守「库里存的不是明文」。
- [x] **B3 限流有效**：`throttle_locks_after_threshold` 守「达阈值后拒绝、成功后解锁」。
- [x] **B4 会话生命周期**：`session_issue_and_verify` 守「签发即可验证、伪造 token 无效」。
- [x] **B5 端到端鉴权**：`e2e.py` 断言
      ① 错误密码 → 401；② 无凭证访问受保护接口 → 401；
      ③ 无效接入令牌注册 → 401；④ 正确凭证 → 200 且 `/auth/me` 返回 admin。
- [x] **B6 令牌一次性**：`enroll_token_can_only_be_used_once`。
- [x] **B7 审计可追溯**：`e2e.py` 断言 `/api/v1/audit` 中存在 `login` 记录。

### 下一轮加固（尚未实现，明确列为待办）

- [ ] **B8 按客户端派生 FerroTunnel token**：改为「服务端向 FerroTunnel 注册一张
      `agent_token → 隧道权限` 的钩子表」，让握手 token 泄漏的影响面收敛到单节点。
- [ ] **B9 多副本登录限流**：抽 `LoginThrottle` 为 trait，提供 Redis 实现。
- [ ] **B10 角色细化**：`viewer`（只读）/ `operator`（可管隧道，不可管用户）/ `admin`。
      当前 `require_admin` 已就位，只需给 PATCH/POST 路由换门。
- [ ] **B11 会话列表与踢下线**：`sessions` 表已存 `user_agent`，补一个管理页即可。

---

## 阶段 3：配置与持久化（已完成）

**目标**：所有状态可持久、可迁移、可清理；配置改动可热生效（监听地址除外）。

### 交付物

- `crates/rscross-config`：`ServerFile` / `ClientFile`，**每个字段 `#[serde(default)]`**
  + `deny_unknown_fields`，`validate()` 是唯一语义校验入口。
- `crates/rscross-store`：SQLite schema（users / sessions / clients / enroll_tokens /
  tunnels / traffic_samples / logs / audit），WAL、`busy_timeout`、外键、
  `spawn_blocking` 封装、`overview()` 与 `traffic_series()` 聚合、保留期清理。
- `bootstrap.rs`：首次启动自动生成配置与初始管理员；内务循环做离线判定与清理。

### 验收标准

- [x] **C1 部分配置可加载**：`partial_toml_falls_back_to_defaults` 守
      「只写 `[server].admin_bind` 和 `[tunnel].token` 时，其余字段回落默认且校验通过」
      —— 这是「升级不炸旧配置」的保证。
- [x] **C2 语义校验有效**：`offline_threshold_must_exceed_heartbeat` 守
      「离线上限 ≤ 心跳间隔时必须拒绝启动」（否则节点会持续抖动）；
      `custom_relay_requires_urls` 守「声明自建 Relay 却没给地址必须拒绝」；
      `port_range_parsing` 守端口池格式。
- [x] **C3 数据一致性**：`tunnels_are_cascaded_on_client_delete` 守
      「删客户端必须连带清掉它的隧道与流量采样」。
- [x] **C4 状态机正确**：`client_crud_roundtrip` 守「心跳把 pending 变成 online」；
      `stale_clients_are_marked_offline` 守「超过阈值后自动置 offline」。
- [x] **C5 统计口径**：`overview_reflects_inserted_traffic` 守
      「直连/中继按 path 分别累计」。
- [x] **C6 日志过滤**：`logs_are_filtered_by_level_and_keyword` 守
      「按级别与关键字过滤的回调数量与语义一致」。
- [x] **C7 热更新闭环**：`e2e.py` 断言
      ① GET 配置时 token 被掩码为 `****`；② PUT 后 GET 能读到新值；
      ③ **保存后隧道 token 未被掩码回写覆盖**；④ 非法配置被 400 拒绝。

### 下一轮补充

- [ ] **C8 schema 迁移框架**：当前 `PRAGMA user_version = 1` + `CREATE TABLE IF NOT EXISTS`
      只够 0→1。加 `migrations/` 目录与按版本号顺序执行。
- [ ] **C9 流量采样的写入路径**：表与聚合查询已就绪，但**尚无代码往里写**
      （数据面还没接计数）。阶段 3 收尾时在 `forward` 的返回值上打点。

---

## 阶段 4：控制台后端 API（已完成）

### 交付物

`crates/rscross-server/src/api/`：`auth.rs` / `client.rs` / `agent.rs` / `misc.rs` / `mod.rs`，
统一 `ApiError → {code,message}`，`console.rs` 负责静态资源与 SPA/JSON 404 分流。

### 验收标准

- [x] **D1 路由不重叠**：同一路径的多方法写在同一个 `MethodRouter` 上
      （axum 对重复 `.route()` 会在启动时 panic，属于「一跑就发现」的问题）。
- [x] **D2 未匹配 API 返回 JSON 404**：`e2e.py` 断言 `/api/v1/does-not-exist` 返回 404
      而不是被 SPA 首页吞掉 —— 否则前端会把「接口路径写错」误判成「页面正常但数据空」。
- [x] **D3 隧道创建校验**：协议白名单、`local_addr` 必须是合法 socket 地址、
      TCP/UDP 端口必须在 `ingress.port_range` 内且不冲突、HTTP 类必须有 Host 或默认域名；
      隧道名在客户端内唯一；受 `limits.max_tunnels_per_client` 约束。
- [x] **D4 端口自动分配**：`port_allocation_skips_used` 守「跳过已占用端口而不是返回冲突」。
- [x] **D5 接入命令可执行**：`enroll_command_contains_endpoint_and_token` +
      `e2e.py` 断言命令里同时含服务端地址与令牌。
- [x] **D6 概览完整**：`e2e.py` 断言 `/overview` 同时返回统计、`p2p`、`path` 三块。
- [x] **D7 日志接口可用**：`e2e.py` 断言 `/logs` 返回非空事件列表。
- [x] **D8 免鉴权探活**：`/api/v1/health` 无需凭证即可返回版本与 uptime（供 LB/探针使用）。

### 下一轮补充

- [ ] **D9 SSE 实时通道**：`/api/v1/stream`（日志 + 统计），替代前端的 3 秒轮询。
- [ ] **D10 分页与排序**：列表接口当前一次性返回，客户端数上千时需要 `?page=&size=`。
- [ ] **D11 请求体大小限制与超时**：给 `axum` 挂 `RequestBodyLimit` 与超时中间件。

---

## 阶段 5：前端页面（已完成基础，含增强项）

### 交付物

`web/index.html` + `web/app.css` + `web/app.js`，经 `rust-embed` 编入服务端二进制。
页面与组件构成见 `docs/CONSOLE.md` §2。

### 验收标准

- [x] **E1 单一二进制**：`e2e.py` 断言 `GET /` 返回含 `rscross` 的 HTML
      —— 即控制台确实被打进了服务端产物，部署时不需要额外分发静态目录。
- [x] **E2 路由回落**：任意非 `/api/*` 路径都回落 SPA（hash 路由刷新不 404）。
- [x] **E3 无 XSS**：所有插值经 `esc()`；`data-*` 属性里的 id/name 同样转义。
- [x] **E4 会话过期自愈**：任意请求收到 401 → 清本地 token → 跳登录页。
- [x] **E5 危险操作有确认**：删除客户端/隧道需二次确认；令牌只在签发那一刻展示一次。
- [x] **E6 降级可用**：概览页在「P2P 未启用」「直连不可用」时给出明确徽章而非空白。

### 下一轮增强

- [ ] **E7 SSE 替换轮询**（配合 D9）。
- [ ] **E8 隧道/客户端详情抽屉**：按路径拆分的流量、最近连接来源、错误率。
- [ ] **E9 亮/暗主题**：CSS 变量已就位（`:root`），只需加一个 `[data-theme=dark]` 覆盖块 + 切换开关。
- [ ] **E10 构建链路升级（可选）**：切 Vite + Vue/React 时，
      在 `build-musl` 之前增加 `web-build` job 产出 `web/dist`，`rust-embed` 改指向它。

---

## 里程碑与依赖关系

```
阶段0 地基 ──┬─→ 阶段1 打洞/中继 ──┬─→ 阶段4 后端 API ──→ 阶段5 前端
             │                     │
             ├─→ 阶段2 认证鉴权 ───┤
             │                     │
             └─→ 阶段3 配置/持久化 ┘
```

阶段 1/2/3 之间**没有**互相阻塞：它们分别在 `transport` / `auth` / `config+store`
三个 crate 里推进，唯一的交汇点是阶段 4 的 API 层与阶段 5 的页面。
这也是目录划分刻意做到「一个阶段 ≈ 一两个 crate」的原因。

## 回归门槛（每个阶段都必须满足）

1. `cargo check --workspace --all-targets` 通过。
2. 全部 `cargo test -p <crate>` 通过。
3. `e2e` job 通过（两个真实二进制跑完整链路）。
4. 两个 musl 目标的静态链接断言通过。
5. 新增的每条验收标准都有对应断言；**断言写在它失败时想知道的语义上**，
   不写「某个字符串出现 N 次」这类形态断言。
