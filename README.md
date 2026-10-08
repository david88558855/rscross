# rscross

基于 **FerroTunnel** + **Iroh** 的内网穿透服务端 / 客户端，含内嵌 Web 控制台。
产物是 **musl 静态、无依赖、单一二进制**。

```
内网服务 ──┬── Iroh（QUIC 打洞直连，流量不过服务端）
           └── FerroTunnel（反向隧道中继，一定能通）
                                    ↓
                         rscross-server（公网）
                     控制面 API + Web 控制台 + SQLite
```

## 两个传输库的分工

| 能力 | 承担者 | 说明 |
|---|---|---|
| NAT 打洞 | **Iroh** | QUIC over UDP + QAD + 打洞；`net_report` 探测 NAT 类型 |
| 中继 | **Iroh Relay** / **FerroTunnel** | 打洞失败 → Iroh 自动落 Relay（可用自建 `iroh-relay`）；FerroTunnel 提供「客户端主动外连」的稳定反向隧道 |
| 密钥交换 | **Iroh** | Ed25519 `SecretKey`，公钥即 `EndpointId`，同时是 QUIC/TLS 1.3 身份，天然双向认证 |
| 节点发现 | **Iroh** | `presets::N0` 的 Pkarr/DNS address lookup；控制面亦交换 `EndpointAddr` 作为第二条通道 |
| 反向隧道 / Host 路由 / 限速 / 连接池 | **FerroTunnel** | `Server` 的 `bind`(控制面) + `http_bind`(HTTP 入口)；`Client` 按 `tunnel_id` 映射本地服务 |
| 鉴权、配置下发、审计、持久化、控制台 | rscross 自身 | 见 `crates/rscross-{server,client,auth,store,config}` |

## 文档

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 总体架构与技术选型、目录与模块划分、**并发模型 / 错误处理 / 日志方案**、已知边界 |
| [docs/CONSOLE.md](docs/CONSOLE.md) | 控制台**功能清单与页面结构**、API 契约、前端技术选择说明 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 分阶段实现计划（打洞与中继 → 鉴权 → 配置与持久化 → 后端 API → 前端）与**逐条验收标准** |
| [docs/BUILD.md](docs/BUILD.md) | musl 静态编译、**依赖裁剪方案**、交叉编译配置、**CI 方案**与发版流程 |

## 快速开始

### 服务端

```bash
./rscross-server --config rscross-server.toml
```

首次运行会自动生成配置与初始管理员，**密码打印在标准错误输出**（不写日志、不进数据库）。
默认监听：

| 用途 | 默认地址 |
|---|---|
| 控制台 / 管理 API | `0.0.0.0:7800` |
| FerroTunnel 反向隧道控制面 | `0.0.0.0:7835` |
| 公网 HTTP 入口 | `0.0.0.0:8081` |

浏览器打开 `http://<IP>:7800/` 即为控制台。

### 客户端

在控制台「客户端管理」页点「添加客户端」→ 复制生成的命令 → 到目标内网机器上执行：

```bash
./rscross-client \
  --server http://<服务端IP>:7800 \
  --tunnel-server <服务端IP>:7835 \
  --name office-nas \
  --enroll-token rse_xxxxxxxx
```

随后在「隧道列表」新建隧道指向该客户端的 `127.0.0.1:xxxx`，
最多 15 秒（下一次心跳）后自动生效。

## 从源码构建

**本仓库禁止本地编译**（需求约束）。所有构建都在 GitHub Actions 完成：

- 推送任意分支 → `.github/workflows/ci.yml`：`fmt → check → (test | clippy | musl×2) → e2e`
- 推送 `v*` tag → `.github/workflows/release.yml`：产出两个架构的 `.tar.gz` + sha256 并创建 Release

## 仓库结构

```
crates/
├── rscross-common/      共享错误、ID、协议常量、控制面 DTO
├── rscross-config/      配置模型与校验（TOML）
├── rscross-store/       SQLite 持久化
├── rscross-auth/        Argon2、token、会话、登录限流
├── rscross-transport/   Iroh + FerroTunnel 适配、路径选择、字节转发
├── rscross-server/      服务端（lib + bin）：API、控制台、任务编排
└── rscross-client/      客户端（lib + bin）：注册、心跳、隧道收敛
web/                     前端源码（rust-embed 内嵌进服务端）
tests/e2e/e2e.py         两个真实二进制的端到端验收
```

## 已知边界

见 [docs/ARCHITECTURE.md §6](docs/ARCHITECTURE.md)。摘要：

1. FerroTunnel 只用单一服务端 token，故它只作**传输层握手凭证**，业务身份由 per-client
   `agent_token` 承担。
2. 原始 TCP/UDP 的公网入口依赖「自建 ingress + Iroh 直连投递」，规划在阶段 3。
3. `p2p.relay_mode = custom` 需要自建 `iroh-relay`，仓库不提供部署编排。
4. 登录限流目前是进程内的，多副本部署需接共享存储。

## 许可

MIT，见 [LICENSE](LICENSE)。
