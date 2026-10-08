# rscross 编译与 CI 方案

> 需求落地说明：**musl 静态无依赖单一二进制** + **禁止本地编译，全部走 GitHub Actions**。

---

## 1. 产物定义

三个二进制，每个都是 musl 静态、无动态依赖：

| 产物 | 角色 | 依赖面 |
|---|---|---|
| `rscross-console` | 独立控制台（多节点汇聚） | axum + rusqlite + rust-embed。**不含** iroh / ferrotunnel / reqwest |
| `rscross-server` | 服务端节点（可单机内嵌控制台） | 控制面 + iroh + ferrotunnel |
| `rscross-client` | 内网客户端 | iroh + ferrotunnel + reqwest。**不含** axum / rusqlite |

目标三元组：`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`。

**「无依赖」的具体含义**：不依赖 glibc、不依赖系统 OpenSSL、不依赖 SQLite 动态库、
不依赖 Node.js 运行时。前端资源经 `rust-embed` 编译期内嵌进控制面，
所以部署时只需要拷文件。

### 为什么是 musl 而不是 gnu + 静态

glibc 的静态链接在 `getaddrinfo` / `dlopen` / NSS 上有已知坑（运行期警告、
容器里 DNS 解析失效）。musl 的静态链接是真正自洽的，也是 `rustls` + `ring`
这类组合的标准目标。

---

## 2. 静态化的关键技术选择

| 依赖 | 静态化处理 | 说明 |
|---|---|---|
| TLS / 加密 | `rustls` + **`ring`** | Iroh 默认 feature `tls-ring` 已选中；`ring` 支持 musl。显式**不启用** `tls-aws-lc-rs`（它需要额外的 CMake/Go 工具链，交叉编译易碎） |
| DNS | `hickory-resolver`（Iroh 内建） | 纯 Rust，读 `/etc/resolv.conf`，不经过 glibc 的 NSS，静态链接下不会「DNS 莫名失效」 |
| SQLite | `rusqlite` 的 **`bundled`** feature | 把 SQLite C 源码一起编进来，避免 `libsqlite3.so` 依赖 |
| 前端 | `rust-embed`（编译期内嵌） | 无运行时文件依赖 |
| 日志文件轮转 | **不使用** `tracing-appender` | 交给 systemd/journald/docker |

---

## 3. 依赖裁剪方案

「静态」不等于「小」。以下是本仓库已经做的与建议做的裁剪。

### 3.1 已落实

| 措施 | 收益 |
|---|---|
| **`rscross-console` 不启用 `rscross-control/http-client`** | 独立控制台产物里**没有 reqwest / hyper / h2 / tower** 这一整棵子树 |
| **`rscross-control` 不依赖 `rscross-transport`** | 控制面产物里没有 iroh / ferrotunnel / rustls / ring |
| **`rscross-client` 不依赖 `rscross-control` / `rscross-store`** | 客户端不含 axum 与 SQLite 的 C 代码 |
| **客户端不依赖 `axum`** | 控制台只在服务端与控制面 |
| `[profile.release]`：`opt-level=3`、`lto="thin"`、`codegen-units=1`、`strip=true` | 体积与跨 crate 内联优化 |
| Iroh 只启用默认 feature（`tls-ring` / `metrics` / `portmapper` / `fast-apple-datapath`） | 不启用 `http3` / `qlog`（后者会拖进 trace 序列化） |
| `reqwest` 用 `default-features = false` + `rustls-tls` | 不拖 `native-tls` / `openssl-sys`，否则静态链接立刻破功 |

依赖方向（决定了产物边界）：

```
rscross-common ──┬─ rscross-config ──┐
                 ├─ rscross-store  ──┼─ rscross-control ──┬─ rscross-console
                 ├─ rscross-auth   ──┘                    └─ rscross-server
                 └─ rscross-transport ──────────────────────┘   and  rscross-client
```

### 3.2 如需进一步瘦身（按收益排序）

1. **把 `reqwest` 换成 ~200 行的极简 HTTP/1.1 客户端。**
   客户端只需要 4 个 POST + 1 个 GET，控制面地址通常在内网/HTTP。
   收益：可去掉整棵 hyper/h2/tower 子树（估计 −1.5~2 MB）。
   代价：要自己处理 chunked、超时、TLS —— **只在明确需要压体积时再做**。
2. **Iroh 关闭 `portmapper` feature**（UPnP/NAT-PMP）。
   收益：去掉 `portmapper` + `netwatch` 的一部分。
   代价：家庭路由器场景下直连成功率下降。
   ```toml
   iroh = { version = "1.3", default-features = false, features = ["tls-ring", "metrics"] }
   ```
3. **动态链接 musl**（`-C target-feature=-crt-static`）+ 只发 `.so`。
   与「无依赖单文件」冲突，**不采用**，仅记录备选。
4. **`panic = "abort"`**：release 下可省几十 KB，但会让 `cargo test --release`
   无法捕获 panic，**未启用**。
5. **UPX 压缩**：能压到 1/3，但会被部分杀软误报、且失去清晰堆栈。**不采用**。

### 3.3 体积基线（CI 每次构建都会 `ls -lh` 打印）

| 产物 | 量级 |
|---|---|
| `rscross-console` | 约 6–10 MB |
| `rscross-server` | 约 15–22 MB（含控制面 + 数据面） |
| `rscross-client` | 约 10–15 MB |

> 具体数字以 CI 日志为准。这里的量级判断用于「是否该做 §3.2 裁剪」的决策。

---

## 4. 交叉编译配置

### 4.1 `rust-toolchain.toml`

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

MSRV 声明在 `Cargo.toml` 的 `[workspace.package] rust-version = "1.91"`：
FerroTunnel 1.5 的 MSRV 是 1.91，Iroh 1.3 使用 edition 2024。

> **不要**在 `rust-toolchain.toml` 里钉死具体小版本 —— CI 用的是 `stable`，
> 两边不一致会让「本地能过、CI 挂」的排查成本陡增。

### 4.2 `Cross.toml`

用 [cross-rs](https://github.com/cross-rs/cross) 而不是手配 `musl-gcc`：

```toml
[build]
default-target = "x86_64-unknown-linux-musl"

[target.x86_64-unknown-linux-musl]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-musl:main"
pre-build = [...]
```

为什么用容器：

- `aarch64-unknown-linux-musl` 需要完整的 `aarch64-linux-musl-gcc`，在 runner 上
  要手工下载 musl.cc 的包并处理 `CC_*`/`AR`/`RANLIB`；容器镜像里**已经配好**。
- `ring` 有汇编与 C 组件、`rusqlite` 有 SQLite 的 C 代码 —— 都强依赖正确的交叉工具链。
  容器方案把这类问题从「每晚随机出现」变成「一次配好」。

### 4.3 本仓库不做本地编译

- 仓库里**没有** `Makefile` / `justfile` / `build.sh`，避免「文档说别本地编、
  工具链却鼓励你本地编」的矛盾。
- `Cargo.lock` 由 CI 的 `check` job 生成并以 artifact 形式产出
  （`Cargo.lock` artifact），需要固定依赖时把它提交回仓库即可。
  **因此 CI 里一律不加 `--locked`** —— 加了会在首次构建时因缺少 lock 文件直接失败。

---

## 5. GitHub Actions 工作流

### 5.1 `ci.yml`

```
        ┌────────┐
        │  fmt   │  continue-on-error（首轮不 gate）
        └────────┘
        ┌──────────────────────────────────────────┐
        │  check   cargo check --workspace         │  ← 最快暴露语法/类型错误
        │          --all-targets                   │     并产出 Cargo.lock
        └────┬───────────────┬─────────────────────┘
             │               │
   ┌─────────▼────────────┐  ┌─────▼──────────────────────────┐  ┌──────────────┐
   │ test（8 个 crate     │  │ build-musl (matrix ×2)         │  │ clippy       │
   │  矩阵并行 + 硬超时）  │  │  三个二进制的静态链接断言      │  │ continue-on- │
   └──────────────────────┘  └─────┬──────────────────────────┘  │ error        │
                                   │ needs                       └──────────────┘
                             ┌─────▼──────────────────────────┐
                             │ e2e：两种部署形态全链路        │
                             └────────────────────────────────┘
```

设计要点（都是被真实 CI 事故逼出来的）：

1. **`check` 必须最先跑**，其余 job 都 `needs: check`。否则一轮要等交叉编译跑完，
   才知道有没有一个拼错的字段名。
2. **`test` 用 crate 矩阵 + `timeout -k 10 600` + `--test-threads=1`。**
   有测试死锁时整条流水线会挂到 6 小时上限且拿不到日志；`timeout` 的 124
   能立刻区分「被 kill」和「断言失败」，`--nocapture` 让日志最后一条就是卡住的用例。
3. **`fmt` / `clippy` 首轮 `continue-on-error: true`**，风格项不应掩盖编译错误。
4. **`Swatinem/rust-cache@v2`**，`build-musl` 按 target 分桶，避免矩阵互踩缓存。
5. **静态链接用断言而不是「看起来没问题」**：x86_64 上 `ldd` 要求输出
   「not a dynamic executable」；aarch64 上用 `qemu-aarch64-static --version` 真跑一次。
6. **`e2e` 依赖 `build-musl` 并下载 x86_64 产物**，用真实二进制跑。

### 5.2 `e2e` 覆盖的两种形态与语义

`tests/e2e/e2e.py` 只依赖 Python 标准库，**两种部署形态各跑一遍**。

场景一：**单机内嵌**（`rscross-server --embedded`）

| 编号 | 断言（语义） |
|---|---|
| 1 | 三个二进制都能 `--version` / `--print-default-config`（静态产物真的能跑） |
| 2 | 内嵌控制台可探活、可登录 |
| 3 | **服务端启动后自动注册为本机节点**，且**上报了反向隧道端口**（与配置一致） |
| 4 | 节点上报了 64 位十六进制的 EndpointId |

场景二：**多节点汇聚**（`rscross-console` + `rscross-server --managed`）

| 编号 | 断言（语义） |
|---|---|
| 5 | 独立控制台 `/health` 的 `embedded = false`（形态可区分） |
| 6 | 创建节点后拿到的命令是 `--managed` 且带令牌 |
| 7 | 服务端以节点身份接入后转为 online，**端口与控制台一致** |
| 8 | 无效节点令牌 → 401 |
| 9 | 审计里同时存在 `create_node` 与 `issue_enroll_token` |

两场景共用：

| 编号 | 断言（语义） |
|---|---|
| 10 | 错误密码 → 401；无凭证访问受保护接口 → 401；无效接入令牌 → 401 |
| 11 | 客户端完成注册并 online，被分配了归属节点，上报了 EndpointId |
| 12 | **客户端接入命令里出现 `--console` 且不出现节点地址**（迁移不需要改客户端配置） |
| 13 | **经公网入口 + `Host:` 的请求拿到了客户端本地服务的响应体**（端到端数据面） |
| 14 | 配置 GET→PUT→GET 闭环；非法配置被 400 拒绝 |
| 15 | 未知 API 路径返回 JSON 404（不被 SPA 吞掉） |
| 16 | 所有进程收到 SIGTERM 后退出码为 0（优雅关停真的生效） |

**失败时自动 dump 各进程日志尾部** —— 没有现场的那条失败，下一轮只能靠猜。

> e2e 里把 `p2p.relay_mode` 设为 `disabled` 且 `address_lookup = false`：
> Iroh 节点在**完全离线**的环境下也能绑定成功（我们只断言 EndpointId，
> 不断言能否连上公共中继），保证 CI 结果稳定。

### 5.3 `release.yml`

触发：push `v*` tag，或手动指定 tag。

```
build(matrix ×2)  →  package(.tar.gz + sha256)  →  publish(GitHub Release)
```

- 打包内容：`rscross-console`、`rscross-server`、`rscross-client`、`README.md`、`LICENSE`。
- 发布说明由 **tag 注解正文**拼上产物清单与校验和 —— 说明只有一处来源。
- **先让 `main` 的 CI 绿了再打 tag**：tag 流水线的第一个 job 也是同样的门禁。

```bash
git tag -a v0.1.2 -F tag_msg.txt     # 必须 -a：轻量 tag 没有正文
git push origin v0.1.2
git ls-remote origin refs/tags/v0.1.2   # 复核，不看 push 的输出
```

---

## 6. 部署与运行

### 方式 B：单机自用（内嵌控制台）

```bash
# 公网机器：一个进程同时提供数据面与控制台
./rscross-server --embedded --config rscross-server.toml
#   → 控制台 http://<公网IP>:7800   （首次密码打印在标准错误输出）
#   → 反向隧道控制面  :7835        （由客户端自动连接）
#   → 公网 HTTP 入口  :8081

# 内网机器（令牌在控制台「客户端管理」页签发）
./rscross-client --console http://<公网IP>:7800 --name office-nas --enroll-token rse_xxxx
```

### 方式 A：多节点汇聚（独立控制台）

```bash
# 控制台机器
./rscross-console --config rscross-console.toml
#   → 控制台 http://<控制台IP>:7800

# 公网机器（节点令牌在控制台「服务端节点」页创建时展示）
./rscross-server --managed --console http://<控制台IP>:7800 \
                 --name hk-1 --enroll-token rsn_xxxx \
                 --public-host node1.example.com --config rscross-server.toml

# 内网机器（令牌在控制台「客户端管理」页签发，需选择归属节点）
./rscross-client --console http://<控制台IP>:7800 --name office-nas --enroll-token rse_xxxx
```

systemd 最小单元：

```ini
[Unit]
Description=rscross server node
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rscross-server --managed \
  --console http://panel.example.com:7800 \
  --enroll-token rsn_xxxx --config /etc/rscross/server.toml
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rscross

[Install]
WantedBy=multi-user.target
```

排查用的固定入口：

```bash
./rscross-server --check                          # 只校验配置
./rscross-server --print-default-config           # 参考配置
./rscross-console --check
curl -s localhost:7800/api/v1/health | jq         # 版本 / 形态 / uptime
journalctl -u rscross-server -f                   # 实时日志（等价于控制台「日志」页）
```
