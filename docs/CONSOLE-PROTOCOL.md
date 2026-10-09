# 控制台连接协议与自建节点配置

两件事：客户端 `--console` 的地址解析（主协议由 HTTP 改为 WebSocket），
以及中央控制台「新增自建节点」的五个配置项。

---

## 一、客户端 `--console`

### 1.1 四种写法

| 写法 | 行为 |
|---|---|
| `ws://host:port/path` | **不做任何解析**，直接建立连接。路径与查询串原样保留 |
| `wss://…` | 同上（TLS） |
| `http://…` / `https://…` | 作为**发现入口**：请求它，跟随 `307`/`308` 的 `Location` 得到真实地址 |
| `txt://example.com` | 查该域名的 **TXT 记录**，记录内容须为 `ws://` 或 `wss://` 地址 |

无论用哪种写法，**日志都会输出最终实际连接的地址**：

```
控制台地址已解析  spec=http://c.example.com:7700 scheme=Https
                  authority=c.example.com:7700 hops=1
                  discovered=/api/v1/control/ws
控制面走 WebSocket（主协议）  url=wss://c.example.com/api/v1/control/ws
控制面 WebSocket 已建立       url=wss://c.example.com/api/v1/control/ws
```

排障时第一眼要看的就是这三行：`spec` 是用户写的，`discovered` 是发现结果，
`ws_url` 是真正连的那个。三者不一致时问题就在发现这一步。

### 1.2 几个刻意的选择

**`ws://` 不自动补控制台路径。** 用户写了完整地址，悄悄改成
`/api/v1/control/ws` 只会让他在别处花更多时间排查。要追加路径应该是显式开关。

**`http(s)://` 只跟随 307/308。** 301/302/303 在 Web 语境下通常是
「这个资源换了位置，请重新 GET」，不是「WebSocket 端点在那边」。

**TXT 多条时挑第一条可用的，并把被跳过的内容也打出来。** TXT 里常见的问题是
写了 `https://` 或漏了端口，只说「没找到」的话用户得自己再查一遍 DNS。

**每种失败给各自可操作的提示**，不共用一句「连接失败」：

```
控制台地址应以 scheme:// 开头（支持 wss / ws / https / http / txt）：127.0.0.1:7700
连接控制面 ws://127.0.0.1:9 失败：Connection refused
控制台入口 http://x/ 返回 200 OK，期望 307/308 重定向到 WebSocket 地址。
  请改用 ws:// 或 wss:// 直接填写
查询 rscross-e2e-no-such-domain.invalid 的 TXT 记录失败：…
  请确认控制台管理员已在该域名下添加 TXT 记录
```

### 1.3 超时与重试

| 阶段 | 超时 | 说明 |
|---|---|---|
| `http(s)` 入口探测 | 8s | 只为拿一个 307，不值得让启动卡几十秒 |
| DNS TXT 查询 | 10s | 超时提示里会说明「当前网络是否允许 DNS 查询」 |
| WebSocket 建连 | 10s | |
| 单个请求等应答 | 30s | 超时即返回 `Err`，绝不让它挂住 |
| 静默断连 | 120s | TCP 连接可以看起来还在但对端进程已经没了 |
| 重连退避 | 1s → 60s | 带抖动 |

**退避必须带抖动**：没有抖动的话控制台重启后所有客户端同时涌上来，
能把它刚起来的连接数又打满。

### 1.4 兼容性

`http://` 入口**保留**，语义变为「发现入口 → 307 → 真实 ws 地址」，
但仍可作为 REST 兼容路径使用（见下表）。控制台前端仍走 HTTP，
老版本二进制仍能注册。

| scheme | 传输 |
|---|---|
| `ws://` `wss://` `txt://` | 控制面 WebSocket（主协议） |
| `http://` `https://` | REST（兼容路径） |

由 scheme **唯一**决定传输，不额外加开关 —— 省掉一个需要和地址保持同步、
迟早会配错的选项。

---

## 二、控制面 WebSocket

端点：`GET /api/v1/control/ws`（路径常量 `CONTROL_WS_PATH`）。

### 2.1 帧

请求带 `id`，响应带回同一个 `id`，因此**一条连接上可以并发多个请求**
（心跳与日志上报交错），不必为每种交互各开一条连接。

```
--→ {"type":"hello","id":1,"version":1}
←-- {"type":"welcome","id":1,"version":1}
--→ {"type":"enroll","id":2,"token":"rsx_…","name":"office-pc","runtime":{…}}
←-- {"type":"enrolled","id":2,"client_id":"…","agent_token":"…","tunnels":[…]}
--→ {"type":"heartbeat","id":3,"token":"…","runtime":{…}}
←-- {"type":"heartbeat","id":3,"heartbeat_secs":15,"node":{…},"tunnels":[…]}
--→ {"type":"push_logs","id":4,"token":"…","entries":[…]}
←-- {"type":"logs_accepted","id":4,"accepted":12}
```

支持客户端（`Role::Agent`）与服务端节点（`Role::Node`）两种角色。

### 2.2 三条设计约束

**版本协商必须是首帧。** 版本不同则帧语义可能完全不同，后续所有请求都建立在
它达成一致之上。版本不符直接关连接。

**业务逻辑不重写。** 每个 `ControlRequest` 变体都转成对应的 `*_inner` 调用
（`agent::enroll_inner` / `heartbeat_inner` / `push_logs_inner`、
`nodes::node_enroll_inner` / `node_heartbeat_inner` / `node_self_inner`），
REST handler 退化成薄壳转调同一份。两边行为一旦分叉，就会出现
「REST 能注册、WS 注册不了」这类极难定位的问题，所以宁可多一层转发。

**鉴权从 header 挪到帧载荷。** 浏览器与部分代理不会给 WS 握手带自定义 header。
错误码复用 HTTP 侧的（`unauthorized` / `forbidden` / `bad_frame` / …），
同一类错误在两条路径上必须能被客户端用同一段逻辑识别。

### 2.3 REST 路由全部保留

| 路由 | 说明 |
|---|---|
| `/api/v1/agent/{enroll,heartbeat,tunnels,logs}` | 客户端（REST） |
| `/api/v1/node/{enroll,heartbeat,self}` | 服务端节点（REST） |
| `/api/v1/control/ws` | 控制面 WebSocket |

---

## 三、新增自建节点

### 3.1 四个配置项

| 配置项 | 数据库列 | 类型 | 默认 | 说明 |
|---|---|---|---|---|
| 名称 | `name` | text | 必填 | 仅字母、数字、`-`、`_`、`.`，≤64 字符 |
| 介绍 | `description` | text | 空 | 纯展示，≤200 字（按字符数算） |
| **服务端地址** | `public_addr` | text | 空 | **控制台地址**，客户端据此连控制台 |
| 传输协议 | `transport` | text | `tcp` | `tcp` / `quic` / `kcp` / `ws` / `wss` |
| P2P 中继 | `allow_relay` | bool | `true` | 直连失败时是否回退中继 |

### 3.2 服务端地址：控制台地址，不是反向隧道地址

形态是完整的 `ws://` / `wss://` URL，例如：

```
ws://203.0.113.9:7800
wss://node1.example.com/api/v1/control/ws
```

端口约定：**内嵌控制台 7800，独立中央控制台 7700**。

**只接受 ws/wss**，`http://` 不行 —— `http://` 入口虽然能跟随 307 发现，
但那是命令行填法的便利（让用户少抄一个前缀）。配置里应该存**最终**那个地址，
不再依赖一次重定向：否则这个字段的值依赖于控制台那一刻的状态，
过几个月再看已经不明白它当初指向哪里了。

### 3.3 两类地址不能混用

| 字段 | 形态 | 端口 | 谁用 |
|---|---|---|---|
| `public_addr`（服务端地址） | `ws://host:port` | 7800 / 7700 | 客户端连**控制台** |
| `tunnel_server`（推导得出） | `host:port` | 7835 | 客户端连**反向隧道控制面** |

`tunnel_server()` 由代码推导（`public_host` > 观测到的 `public_ip` > `127.0.0.1`，
端口取节点上报值），**刻意不使用 `public_addr`** —— 协议不同、端口不同，
混用会让客户端拿 7800 去连 7835 的服务。store 里有单测钉住这个边界。

### 3.4 传输协议不含 udp

UDP 入口需要内核层面的端口转发，在 NAT 后基本不可用；配上去只会得到一个
「节点在线但 UDP 隧道全不通」的状态。穿透工具本来就是为 TCP 设计的，
TCP 侧的行为对 UDP 业务已经足够。

数据库迁移


`user_version` 逐版本递进，`add_missing_columns()` 幂等追加，老库直接升级不丢数据。

**v2 → v3**（服务端节点的地址与传输配置）：

```sql
ALTER TABLE nodes ADD COLUMN description TEXT;
ALTER TABLE nodes ADD COLUMN public_addr TEXT;
ALTER TABLE nodes ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp';
ALTER TABLE nodes ADD COLUMN allow_relay INTEGER NOT NULL DEFAULT 1;
```

**v3 → v4**（接入命令可复制 + 节点级端口池）：

```sql
ALTER TABLE nodes ADD COLUMN port_range TEXT;
ALTER TABLE nodes ADD COLUMN node_token_plain TEXT;
ALTER TABLE enroll_tokens ADD COLUMN id TEXT;
ALTER TABLE enroll_tokens ADD COLUMN token_plain TEXT;
```

v4 的两列明文（`nodes.node_token_plain`、`enroll_tokens.token_plain`）是为了让
「复制接入命令 / 复制接入令牌」在**创建之后**仍然可用 —— 这两个 token 一个是节点每次
心跳用的长期凭据、一个是一次性接入凭据，只留摘要就等于把「复制命令」做成了「重建凭据」，
而重建会让在线节点立刻掉线。明文仅管理员可读，且只经**专用接口按需返回**
（`GET /api/v1/nodes/{id}/command`、列表里的 `command` 字段），不出现在任何常规列表响应中
（`#[serde(skip_serializing)]`）。

`enroll_tokens.id` 与 `token_hash` 分离：摘要只用于比对，业务标识另有其字段，
否则「撤销某条令牌」就得拿摘要当主键，语义上说不通。v4 迁移末尾会为老库里
`id` 为空的行**回填一个随机 id**，而不是让前端去处理 `id` 为 `NULL` 的条目 ——
后者意味着老令牌在界面上永远是灰的、点不动，用户只能删库重来。

---

## 四、代码改动点

### 新增文件

| 文件 | 职责 |
|---|---|
| `crates/rscross-common/src/console.rs` | scheme 解析（纯逻辑、无 IO，可完全单测） |
| `crates/rscross-common/src/control.rs` | 控制面帧协议（请求 / 应答 / 推送） |
| `crates/rscross-control/src/api/ws.rs` | WebSocket 端点与帧循环 |
| `crates/rscross-client/src/discover.rs` | 地址发现（307 探测 + DNS TXT） |
| `crates/rscross-client/src/wsclient.rs` | 帧编解码 + 请求响应配对 + 退避 |

### 改动文件

| 文件 | 改动 |
|---|---|
| `common/src/lib.rs` | 下沉 `NodeTunnelPlan`；`NodeEndpoint` 加 `public_addr` / `transport` |
| `control/src/api/mod.rs` | 注册 WS 路由 |
| `control/src/api/agent.rs` | `enroll` / `heartbeat` / `push_logs` 拆出 `*_inner` |
| `control/src/api/nodes.rs` | 同上；新增 `TRANSPORTS` 白名单与 `NodeExtras`；`node_endpoint` 补新字段 |
| `control/src/error.rs` | `ApiError::into_control_response` |
| `store/src/model.rs` | `NodeRecord` 加 4 列；`tunnel_server()` 优先用 `public_addr` |
| `store/src/lib.rs` | schema 迁移（v3 补节点地址列；v4 补接入命令明文与 `enroll_tokens.id`） |
| `client/src/agent.rs` | 启动时先解析地址，按 scheme 选传输 |
| `client/src/api.rs` | `ApiClient::from_console` |
| `web/app.js` | 「添加自建节点」表单补全五项；列表展示服务端地址与协议 |

### 验证

`tests/e2e/e2e.py` 新增 `scenario_console_addr`：

- 四种写法的**失败路径**提示是否可操作（成功路径靠主场景既有断言覆盖 —— 用户踩的坑几乎都在失败侧）；
- 五个配置项的落库、默认值、非法值被拒、修改与清空；
- **下发给客户端的 `endpoint.public_addr` 就是管理员填的那个**。

最后一条是关键：只断言「保存成功」不够，必须断言这栏配置真的生效了。