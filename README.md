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

```bash
# 公网机器：一个进程同时提供数据面与控制台
./rscross-server --embedded --config rscross-server.toml
```

默认监听：

| 用途 | 默认地址 |
|---|---|
| 控制台 / 管理 API | `0.0.0.0:7800`（首次启动的密码打印在标准错误输出） |
| FerroTunnel 反向隧道控制面 | `0.0.0.0:7835` |
| 公网 HTTP 入口 | `0.0.0.0:8081` |

浏览器打开 `http://<公网IP>:7800/` → 「客户端管理」签发令牌 → 复制命令：

```bash
./rscross-client --console http://<公网IP>:7800 --name office-nas --enroll-token rse_xxxx
```

再到「隧道列表」新建隧道指向内网服务的 `127.0.0.1:xxxx`，≤15 秒自动生效。

### 方式 A：多节点汇聚

```bash
# ① 控制台机器
./rscross-console --config rscross-console.toml

# ② 在控制台「服务端节点」页添加节点，复制命令到公网机器执行：
./rscross-server --managed --console http://<控制台IP>:7800 \
                 --name hk-1 --enroll-token rsn_xxxx

# ③ 在「客户端管理」页签发令牌（选择归属节点），复制命令到内网机器执行：
./rscross-client --console http://<控制台IP>:7800 --name office-nas --enroll-token rse_xxxx
```

> 客户端命令里**不含节点地址**：归属由令牌决定，之后还能在控制台改派。
> 因此把客户端迁到另一台节点不需要动客户端机器上的任何文件。

## 从源码构建

**本仓库禁止本地编译**。所有验证与产物都在 GitHub Actions 完成：

- 推送任意分支 → `.github/workflows/ci.yml`：`fmt → check → (test×8 | clippy | musl×2) → e2e`
- 推送 `v*` tag → `.github/workflows/release.yml`：两个架构三个二进制的 `.tar.gz` + sha256 + Release

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
