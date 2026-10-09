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

### 3.1 五个配置项

| 配置项 | 数据库列 | 类型 | 默认 | 说明 |
|---|---|---|---|---|
| 名称 | `name` | text | 必填 | 仅字母、数字、`-`、`_`、`.` |
| 介绍 | `description` | text | 空 | 纯展示，方便区分多台节点 |
| 对外主机 | `public_host` | text | 空 | 对外怎么访问（DNS 解析用） |
| **服务端地址** | `public_addr` | text | 自动推导 | **客户端据此连接服务端** |
| 传输协议 | `transport` | text | `tcp` | `tcp` / `udp` / `quic` / `kcp` / `ws` / `wss` |
| P2P 中继 | `allow_relay` | bool | `true` | 直连失败时是否回退中继 |

### 3.2 「对外主机」与「服务端地址」为什么必须分开

这是本轮最容易踩的一处：

- **对外主机** = DNS 解析用。用户在外面访问 `node1.example.com:8080` 时解析到哪。
- **服务端地址** = 客户端连接用。内网客户端拿它去连那条反向隧道。

合并成一个字段的后果很具体：**内嵌形态下节点拿不到自己的公网出口 IP**，
自动推导会回落到 `127.0.0.1`，客户端照着连就连到自己本机去了 ——
隧道看起来「建立了」，流量却哪儿也不去，而且日志上完全看不出来。

所以 `public_addr` 单独立列，且优先于 `tunnel_server` 的自动推导：

```
优先级：public_addr（可自带端口）> public_host > 观测到的 public_ip > 127.0.0.1
```

`public_addr` 允许自带端口：服务端监听端口常常不是默认值
（同一个节点上还跑着别的服务），强制覆盖成上报值会让管理员配的地址失效。
只填主机不填端口时才用节点上报的隧道端口补齐。

### 3.3 传输协议为什么用白名单

它会写进配置并影响实际连接方式。拼错一个字符的表现是
「节点上线了但隧道全不通」，而且日志里看不出原因。所以非法值在接口层就
返回 400 并列出可选值，而不是存进去等运行时炸。

### 3.4 数据库迁移

`user_version` 从 2 升到 3，`ADDITIONS` 幂等追加，老库直接升级不丢数据：

```sql
ALTER TABLE nodes ADD COLUMN description TEXT;
ALTER TABLE nodes ADD COLUMN public_addr TEXT;
ALTER TABLE nodes ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp';
ALTER TABLE nodes ADD COLUMN allow_relay INTEGER NOT NULL DEFAULT 1;
```

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
| `store/src/lib.rs` | schema v3 + 迁移 |
| `client/src/agent.rs` | 启动时先解析地址，按 scheme 选传输 |
| `client/src/api.rs` | `ApiClient::from_console` |
| `web/app.js` | 「添加自建节点」表单补全五项；列表展示服务端地址与协议 |

### 验证

`tests/e2e/e2e.py` 新增 `scenario_console_addr`：

- 四种写法的**失败路径**提示是否可操作（成功路径靠主场景既有断言覆盖 —— 用户踩的坑几乎都在失败侧）；
- 五个配置项的落库、默认值、非法值被拒、修改与清空；
- **下发给客户端的 `endpoint.public_addr` 就是管理员填的那个**。

最后一条是关键：只断言「保存成功」不够，必须断言这栏配置真的生效了。