# rscross

基于 Rust **完全自研**的内网穿透管理平台，支持多用户、多节点、中心化配置、网页实时生效。

这是一个全新项目，不基于 gostc / frp / 任何 Go 项目，协议与内核均为独立实现。
**仅在前端 UI、连接方式与使用流程上高仿 gostc**，方便熟悉 gostc 的用户快速上手；
rscross 与 gostc 之间不存在任何协议兼容性，两者无法互连。

前端沿用 Vue 3 + Naive UI 管理界面，**服务端、节点/客户端、内核穿透协议全部由 Rust 从零实现**，
不依赖任何 Go 运行时。

## 特性

| 能力 | 说明 |
|------|------|
| 域名映射 | 自定义域名 / 子域名，HTTP 与 HTTPS 转发 |
| 端口转发 | TCP / UDP，外部端口映射到内网服务 |
| 私有隧道 | STCP / SUDP，需访客密钥方可访问 |
| P2P 打洞 | XTCP 直连，失败自动回退 STCP 中继 |
| 代理隧道 | SOCKS5 等协议代理 |
| 限速加密 | 带宽限制、AES 加密、压缩 |
| 流量统计 | 按用户 / 客户端 / 节点 / 隧道维度聚合 |

## 架构

```text
rscross/
├── crates/
│   ├── rscross-common/   # 公共库：配置、加密、RPC 传输、工具
│   ├── rscross-tunnel/     # 自研穿透内核：HubServer(节点侧) + AgentService(客户端侧) + NAT 打洞
│   ├── rscross-server/   # 服务端：axum API + sqlx 数据层 + 调度引擎
│   └── rscross-client/   # 节点/客户端运行时
├── web/                  # 前端（Vue 3 + Naive UI）
├── configs/              # 配置样例
└── .github/workflows/    # CI：push 交叉编译
```

### 通信协议

rscross 有两套自研协议：

- **控制面**：服务端与节点/客户端之间跑 RPC over WebSocket，
  承载注册、心跳、配置下发、流量上报。
- **数据面**：`rscross-tunnel` 实现的穿透协议。控制流为
  「8 字节大端长度前缀 + JSON」，数据流按工作连接复用转发，
  支持按需加密、压缩与限速。

## 编译

项目通过 GitHub Actions 编译，推送即触发交叉编译，**产出无依赖单文件二进制**。

服务端（musl 全静态，`ldd` 无任何输出）：

| 目标 | 说明 |
|------|------|
| `x86_64-unknown-linux-musl` | x86_64 Linux |
| `aarch64-unknown-linux-musl` | ARM64 Linux |
| `armv7-unknown-linux-musleabihf` | ARMv7 Linux |

客户端：

| 目标 | 说明 |
|------|------|
| `x86_64-unknown-linux-musl` | x86_64 Linux |
| `aarch64-unknown-linux-musl` | ARM64 Linux |
| `armv7-unknown-linux-musleabihf` | ARMv7 Linux |
| `x86_64-pc-windows-msvc` | Windows x64 |
| `aarch64-pc-windows-msvc` | Windows ARM64 |

Linux 产物为全静态链接，拷贝到任意同架构机器即可运行，无需安装运行时或系统库。
前端资源已通过 `include_dir` 打包进服务端二进制，单文件即包含管理界面。

本地编译需要 Rust 1.82+：

```bash
# 编译前端
cd web && npm install && npm run build && cd ..

# 嵌入前端资源
./scripts/embed-web.sh

# 编译（默认本机目标）
cargo build --release

# 交叉编译静态版本
cargo build --release --target x86_64-unknown-linux-musl
```

产物位于 `target/release/`。

## 部署

### 服务端

```bash
# 配置
cp configs/config.yaml configs/config.yaml.local
# 生成 JWT 密钥
openssl rand -hex 32
# 写入 jwt_secret 后启动
./rscross-server --config configs/config.yaml.local
```

默认端口 `8080`，默认账号密码 `admin / admin`（请立即修改）。

数据目录：`data/`（SQLite 数据库）
日志目录：`logs/`

### 节点 / 客户端

```bash
# 节点
./rscross-client --tls=false -addr 127.0.0.1:8080 -s -k <节点密钥>

# 客户端
./rscross-client --tls=false -addr 127.0.0.1:8080 -k <客户端密钥>
```

`--tls` 需与服务端是否启用 SSL 一致，`-addr` 为服务端地址。

### 访问私有隧道

```bash
./rscross-client -a 127.0.0.1:8080 visit -t 127.0.0.1:80 -k <访客密钥> -l 127.0.0.1:6000
```

随后访问 `127.0.0.1:6000` 即可。

## 环境变量

服务端：

| 变量 | 说明 |
|------|------|
| `RSC_ADDRESS` | 监听地址 |
| `RSC_MODE` | `dev` / `prod` |
| `RSC_LOG_LEVEL` | 日志级别 |
| `RSC_DB_TYPE` | `sqlite` / `mysql` |
| `RSC_SQLITE_PATH` | SQLite 文件路径 |
| `RSC_MYSQL_DSN` | MySQL DSN |
| `RSC_JWT_SECRET` | JWT 签名密钥 |
| `RSC_ALLOW_REGISTER` | 是否开放注册 |

客户端：

| 变量 | 说明 |
|------|------|
| `RSC_ADDR` | 服务端地址 |
| `RSC_KEY` | 连接密钥 |
| `RSC_TLS` | 是否启用 TLS |
| `RSC_NODE` | 是否节点模式 |
| `RSC_LOG_LEVEL` | 日志级别 |

## License

Apache-2.0
