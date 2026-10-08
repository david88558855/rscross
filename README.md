# rscross

基于 **FerroTunnel** + **Iroh** 的内网穿透平台：一个 Web 控制台 + N 个服务端节点 + M 个内网客户端。
所有产物都是 **musl 静态、无依赖、单一二进制**。

## 三种角色，两种用法

| 角色 | 二进制 | 职责 |
|---|---|---|
| **控制台** | `rscross-console`（独立）<br>`rscross-server --embedded`（内嵌） | 唯一管理入口：Web UI + 管理 API + 配置下发 |
| **服务端节点** | `rscross-server` | 数据面：FerroTunnel 中继 + Iroh 节点 |
| **内网客户端** | `rscross-client` | 把内网服务通过反向隧道暴露出去 |

### 方式 A：中央控制台（多节点汇聚）

```
                    ┌── rscross-console（独立控制台 / Web UI） ──┐
   浏览器 ─────────▶│  管理 API · 节点注册 · 客户端注册 · 配置下发 │
                    └───────┬──────────────────────────┬───────┘
                            │ rsn_ 令牌                 │ rse_ 令牌
                 ┌──────────▼──────────┐       ┌───────▼────────┐
                 │ rscross-server      │◀──────┤ rscross-client │
                 │ --managed（公网）    │ 数据面 │ （内网）        │
                 └─────────────────────┘       └────────────────┘
```

### 方式 B：单机自用（内嵌控制台）

```
   浏览器 ──▶ rscross-server --embedded  ──▶ 内嵌控制台 + 数据面（同一进程）
                        ▲
                        └── rscross-client --console http://<该机器>:7800
```

两种方式**共用同一份控制面代码与同一套 UI**，区别只在控制台进程跑在哪里。

> 端口刻意分开：**独立中央控制台默认 7700**，**内嵌控制台默认 7800**。
> 这样同一台机器上可以先内嵌自测、再起一个中央控制台汇聚多节点，互不抢占；
> 从浏览器地址栏的端口号也能一眼看出连的是哪一套。

## 两个传输库的分工

| 能力 | 承担者 | 说明 |
|---|---|---|
| NAT 打洞 | **Iroh** | QUIC over UDP + QAD + 打洞；`net_report` 探测 NAT 类型 |
| 中继 | **Iroh Relay** / **FerroTunnel** | 打洞失败 → Iroh 自动落 Relay（可用自建 `iroh-relay`）；FerroTunnel 提供「客户端主动外连」的稳定反向隧道 |
| 密钥交换 | **Iroh** | Ed25519 `SecretKey`，公钥即 `EndpointId`，同时是 QUIC/TLS 1.3 身份，天然双向认证 |
| 节点发现 | **Iroh** | `presets::N0` 的 Pkarr/DNS address lookup；控制台另有一条 `EndpointAddr` 下发通道 |
| 反向隧道 / Host 路由 / 限速 / 连接池 | **FerroTunnel** | `Server` 的 `bind`(控制面) + `http_bind`(HTTP 入口)；`Client` 按 `tunnel_id` 映射本地服务 |
| 鉴权、配置下发、审计、持久化、控制台 | rscross 自身 | 见 `crates/rscross-{control,console,server,client,auth,store,config}` |

## 文档

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 部署形态、技术选型、目录与模块划分、**并发模型 / 错误处理 / 日志方案**、已知边界 |
| [docs/CONSOLE.md](docs/CONSOLE.md) | 控制台**功能清单与页面结构**、两种形态的操作流程、API 契约 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 分阶段实现计划与**逐条验收标准** |
| [docs/BUILD.md](docs/BUILD.md) | musl 静态编译、**依赖裁剪方案**、交叉编译配置、**CI 方案**与发版流程 |

## 快速开始

### 方式 B：单机自用

先在**本机**跑通（无需公网、无需令牌，用于验证程序本身是否正常）：

```powershell
# Windows：解压 CI 产物 rscross-x86_64-pc-windows-msvc 后
.\rscross-server.exe --embedded
# 浏览器打开 http://127.0.0.1:7800
# 首次启动的管理员密码打印在启动输出里（stderr）
```

```bash
# Linux：公网机器，一个进程同时提供数据面与控制台
./rscross-server --embedded --config rscross-server.toml
```

默认监听：

| 用途 | 默认地址 |
|---|---|
| 内嵌控制台 / 管理 API | `0.0.0.0:7800`（首次启动的密码打印在标准错误输出） |
| FerroTunnel 反向隧道控制面 | `0.0.0.0:7835` |
| 公网 HTTP 入口 | `0.0.0.0:8081` |

浏览器打开 `http://<公网IP>:7800/` → 「客户端管理」签发令牌 → 复制命令：

```bash
./rscross-client --console http://<公网IP>:7800 --name office-nas --enroll-token rse_xxxx
```

再到「隧道管理」新建隧道指向内网服务的 `127.0.0.1:xxxx`，≤15 秒自动生效。

> 从本机跑到公网访问打不开时，请对照[「浏览器打不开控制台？」](#浏览器打不开控制台按这个顺序查)排查。

### 方式 A：多节点汇聚

```bash
# ① 控制台机器
./rscross-console --config rscross-console.toml

# ② 在控制台「服务端节点」页添加节点，复制命令到公网机器执行：
#    中央控制台默认 7700（内嵌控制台才是 7800）
./rscross-server --managed --console http://<控制台IP>:7700 \
                 --name hk-1 --enroll-token rsn_xxxx

# ③ 在「客户端管理」页签发令牌（选择归属节点），复制命令到内网机器执行：
./rscross-client --console http://<控制台IP>:7700 --name office-nas --enroll-token rse_xxxx
```

> 客户端命令里**不含节点地址**：归属由令牌决定，之后还能在控制台改派。
> 因此把客户端迁到另一台节点不需要动客户端机器上的任何文件。

## 四类隧道怎么选

| 分类 | 适用场景 | 访问方式 | 数据面 |
|---|---|---|---|
| **域名解析** | Web 服务、API（有域名） | 直接访问 `https://app.example.com` | FerroTunnel 自带的 HTTP 入口，按 `Host` 路由 |
| **端口转发** | 数据库、SSH、RDP 等非 HTTP | 访问 `<节点IP>:<公网端口>` | 节点侧自建 **TCP** ingress → Iroh → 客户端本地服务 |
| **私有隧道** | 不想暴露任何公网端口 | 访问端在本机监听，流量经节点中继 | 访问密钥 + 节点中继 |
| **P2P 隧道** | 同私有隧道，且希望低延迟 | 访问端在本机监听，优先点对点直连 | 访问密钥 + 打洞直连（可配失败回退中继） |

> 为什么后两类要单独做一套：**FerroTunnel 的服务端只提供控制面与 HTTP 入口**，
> 给不了「任意端口监听」，也做不到「访问端凭密钥自建本地入口」。
> 所以端口转发与访问端这两条路径是 rscross 自己实现的（见 `docs/ARCHITECTURE.md`）。
>
> 端口转发的入口当前只实现了 **TCP**：选 UDP 可以保存配置，但暂时不会真正转发。

### 访问端：私有不暴露端口（私有 / P2P 隧道）

这两类隧道**不向公网开任何端口**——入口建在访问者自己那台机器上。
在控制台「隧道管理」创建后复制访问密钥，再在需要访问内网服务的机器上执行：

```bash
./rscross-client access \
    --console http://<控制台IP>:7700 \
    --key rsv_xxxxxxxxxxxxxxxx \
    --listen 127.0.0.1:8080
```

之后访问 `http://127.0.0.1:8080` 就等于访问内网服务；内网那台机器不需要任何入站端口。
P2P 隧道会先尝试与客户端直连，直连失败且允许回退时自动走节点中继（不会中断连接）。

## 从源码构建

**本仓库禁止本地编译**。所有验证与产物都在 GitHub Actions 完成：

- 推送任意分支 → `.github/workflows/ci.yml`：`fmt → check → (test×8 | clippy | musl×2 | windows) → e2e`
- 推送 `v*` tag → `.github/workflows/release.yml`：Linux musl ×2 架构 + Windows x86_64 的二进制包与 sha256 + Release

`e2e` 会用**真实二进制**把两种部署形态各跑一遍完整链路。

## 仓库结构

```
crates/
├── rscross-common/      共享错误、ID、协议常量、控制面 DTO
├── rscross-config/      三份配置模型：ConsoleFile / NodeFile / ClientFile
├── rscross-store/       SQLite 持久化（nodes / clients / tunnels / …）
├── rscross-auth/        Argon2id、三类令牌、会话、登录限流
├── rscross-transport/   Iroh + FerroTunnel 适配、路径选择、字节转发
├── rscross-control/     控制面（API + Web + 持久化），两种形态共用
├── rscross-console/     独立控制台二进制
├── rscross-server/      服务端节点二进制（可单机内嵌控制台）
└── rscross-client/      内网客户端二进制
web/                     前端源码（rust-embed 内嵌进控制面）
tests/e2e/e2e.py         两种部署形态的真实二进制端到端验收
```

## 浏览器打不开控制台？按这个顺序查

「界面显示不出来」有且只有三种原因，前两种在服务器上一条命令就能排除。

> 先对齐端口：**内嵌控制台（`rscross-server --embedded`）默认 7800**，
> **独立中央控制台（`rscross-console`）默认 7700**。
> 下面的命令以内嵌控制台为例，用中央控制台时把端口换掉即可。

**① 端口没监听**（进程挂了 / 端口被占 / 绑定了非预期地址）

```bash
ss -lntp | grep 7800            # 老系统用 netstat -lntp | grep 7800
./rscross-server --check        # 打印配置 + 内嵌前端自检
```

正常应显示 `0.0.0.0:7800`（不是 `127.0.0.1:7800`，那样只能本机访问）。
若启动日志里有 `控制台绑定 0.0.0.0:7800 失败: Address already in use`，就是端口被占了。

**② 网络不通**（占了这类问题的大头）

```bash
curl -i http://127.0.0.1:7800/api/v1/health   # 服务器本机：通不通
curl -i http://<公网IP>:7800/                 # 从外部机器：通不通
```

本机通、外网不通 → **云服务器安全组 / 系统防火墙没放行 7800**：

```bash
# 系统防火墙（按实际使用的工具二选一）
firewall-cmd --add-port=7800/tcp --permanent && firewall-cmd --reload   # firewalld
ufw allow 7800/tcp && ufw reload                                        # ufw
# 云厂商控制台里，还要在「安全组 / 防火墙」放行 TCP 7800 入方向
```

顺便确认浏览器地址是 `http://` 而不是 `https://`——控制台默认不带 TLS，用 https 会一直转圈。

**③ 页面本身有问题**

若 `curl -i http://127.0.0.1:7800/` 返回 200 且 `Content-Type: text/html`，但浏览器仍是空白，
就是前端渲染出错：打开浏览器开发者工具看 Console 的红色报错。这时请把这台服务器的
`--check` 输出与浏览器报错一起反馈。

> `--check` 会打印 `内嵌控制台前端: 前端资源已内嵌（3 个文件），控制台页面可用`。
> 若这里显示「前端资源缺失」，说明二进制构建时没带上仓库根的 `web/` 目录——重新下载 CI 产物即可。

## 已知边界

见 [docs/ARCHITECTURE.md §8](docs/ARCHITECTURE.md)。摘要：

1. FerroTunnel 只用单一服务端 token，故它只作**传输层握手凭证**，业务身份由
   per-client `agent_token` 承担。
2. 原始 TCP/UDP 的公网入口依赖「自建 ingress + Iroh 直连投递」，规划在阶段 3。
3. `p2p.relay_mode = custom` 需要自建 `iroh-relay`，仓库不提供部署编排。
4. 节点的 `tunnel_token` 轮换需要重启节点（FerroTunnel 只在启动时读 token）。
5. 登录限流目前是进程内的，多副本控制台需接共享存储。

## 许可

MIT，见 [LICENSE](LICENSE)。
