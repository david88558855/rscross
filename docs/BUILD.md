# rscross 编译与 CI 方案

> 需求 3、4 的落地说明：**musl 静态无依赖单一二进制** + **禁止本地编译，全部走 GitHub Actions**。

---

## 1. 产物定义

| 产物 | 目标三元组 | 链接方式 | 预期 |
|---|---|---|---|
| `rscross-server` | `x86_64-unknown-linux-musl` | 静态（musl libc 静态链接） | `ldd` 输出「not a dynamic executable」 |
| `rscross-server` | `aarch64-unknown-linux-musl` | 静态 | 可在 arm64 Linux 直接运行 |
| `rscross-client` | 同上两个目标 | 静态 | 同上 |

**「无依赖」的具体含义**：不依赖 glibc、不依赖系统 OpenSSL、不依赖 SQLite 动态库、
不依赖 Node.js 运行时。前端资源经 `rust-embed` 编译期内嵌进 `rscross-server`，
所以部署时只需要拷一个文件。

### 为什么是 musl 而不是 gnu + 静态

glibc 的静态链接在 `getaddrinfo` / `dlopen` / NSS 上有一系列已知坑（运行期警告、
DNS 解析在容器里失效）。musl 的静态链接是真正自洽的，也是 `rustls` + `ring` 这类
纯 Rust/C 组合的标准目标。

---

## 2. 静态化的关键技术选择

| 依赖 | 静态化处理 | 说明 |
|---|---|---|
| TLS / 加密 | `rustls` + **`ring`** | Iroh 默认 feature `tls-ring` 已选中；`ring` 支持 musl，`aws-lc-rs` 在部分交叉目标上需要额外 CMake/Go，因此**显式不启用** `tls-aws-lc-rs` |
| DNS | `hickory-resolver`（Iroh 内建） | 纯 Rust，读 `/etc/resolv.conf`，不经过 glibc 的 NSS，静态链接下不会出现「DNS 莫名失效」 |
| SQLite | `rusqlite` 的 **`bundled`** feature | 把 SQLite 的 C 源码一起编进来，避免 `libsqlite3.so` 依赖。交叉编译时由 `cross` 容器里的工具链编译 |
| 前端 | `rust-embed`（编译期内嵌） | 无运行时文件依赖 |
| 日志文件轮转 | **不使用** `tracing-appender` | 交给 systemd/journald/docker；少一个依赖、少一份体积 |
| 环境变量/CLI | `clap` 的 `derive` + `env` | 纯 Rust |

---

## 3. 依赖裁剪方案

「静态」不等于「小」。以下是本仓库已经做的与建议做的裁剪。

### 3.1 已落实

| 措施 | 收益 |
|---|---|
| **客户端不依赖 `rscross-store` / `rusqlite`** | 客户端二进制不含 SQLite 的 C 代码（数百 KB + 首次编译时间） |
| **客户端不依赖 `axum`** | 控制台只在服务端 |
| **服务端不做 FerroTunnel 的 TCP ingress** | 不引入额外网络栈 |
| `[profile.release]`：`opt-level=3`、`lto="thin"`、`codegen-units=1`、`strip=true` | 体积与跨 crate 内联优化 |
| Iroh 只启用默认 feature（`tls-ring` / `metrics` / `portmapper` / `fast-apple-datapath`） | 不启用 `http3`、`qlog`（`qlog` 会拖进 trace 序列化） |
| `reqwest` 用 `default-features = false` + `rustls-tls` | 不拖 `native-tls` / `openssl-sys`，否则静态链接立刻破功 |

### 3.2 如需进一步瘦身（按收益排序）

1. **把 `reqwest` 换成 ~200 行的极简 HTTP/1.1 客户端。**
   客户端只需要 3 个 POST + 1 个 GET，且控制面地址通常在内网/HTTP。
   收益：可去掉 `hyper`、`h2`、`http-body`、`tower` 等一整棵子树（估计 −1.5~2 MB）。
   代价：要自己处理 chunked、超时、TLS —— **只在明确需要压体积时再做**。
2. **Iroh 关闭 `portmapper` feature**（UPnP/NAT-PMP）。
   收益：去掉 `portmapper` + `netwatch` 的一部分。
   代价：家庭路由器场景下直连成功率下降。
   ```toml
   iroh = { version = "1.3", default-features = false, features = ["tls-ring", "metrics"] }
   ```
3. **动态链接 musl**（`-C target-feature=-crt-static`）+ 只发一个 `.so`。
   与「无依赖单文件」需求冲突，**不采用**，仅记录备选。
4. **`panic = "abort"`**：release profile 下再加一条可省几十 KB，
   但会让 `cargo test --release` 无法捕获 panic，因此**未启用**。
5. **UPX 压缩**：能把二进制压到 1/3，但会被部分杀软误报、且失去清晰堆栈。**不采用**。

### 3.3 体积基线（CI 每次构建都会 `ls -lh` 打印）

| 产物 | 量级 |
|---|---|
| `rscross-server`（含内嵌控制台 + axum + rusqlite） | 约 12–18 MB |
| `rscross-client`（含 Iroh + FerroTunnel + reqwest） | 约 10–15 MB |

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

> **不要**在 `rust-toolchain.toml` 里钉死一个具体小版本号 —— CI 用的是 `stable`，
> 两边不一致会让「本地能过、CI 挂」的排查成本陡增。

### 4.2 `Cross.toml`

用 [cross-rs](https://github.com/cross-rs/cross) 而不是手配 `musl-gcc`：

```toml
[build]
default-target = "x86_64-unknown-linux-musl"

[target.x86_64-unknown-linux-musl]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-musl:main"
pre-build = [
    "dpkg --add-architecture $CROSS_DEB_ARCH || true",
    "apt-get update && apt-get install --assume-yes --no-install-recommends pkg-config",
]
```

为什么用容器而不是本机 `rustup target add` + `musl-tools`：

- `aarch64-unknown-linux-musl` 需要完整的 `aarch64-linux-musl-gcc` 工具链，
  在 ubuntu runner 上要手工下载 musl.cc 的预编译包、还要处理 `CC_*`/`AR`/`RANLIB` 变量；
  容器镜像里这些**已经配好**。
- `ring` 有汇编与 C 组件，`rusqlite` 有 SQLite 的 C 代码 —— 二者都强依赖正确的交叉工具链。
  容器方案把这类问题从「每晚随机出现」变成「一次配好」。

### 4.3 本仓库不做本地编译

需求 4 明确禁止本地编译，因此：

- 仓库里**没有** `Makefile` / `justfile` / `build.sh` 之类的本地构建入口，
  避免出现「文档说别本地编、但工具链鼓励你本地编」的矛盾。
- `Cargo.lock` 由 CI 的 `check` job 生成并以 artifact 形式产出（`Cargo.lock` artifact），
  需要固定依赖时把它提交回仓库即可。**因此 CI 里的 `cargo` 命令一律不加 `--locked`**
  —— 加了会在首次构建时因缺少 lock 文件直接失败。

---

## 5. GitHub Actions 工作流

### 5.1 `ci.yml` 的作业图

```
        ┌────────┐
        │  fmt   │  continue-on-error（首轮不 gate）
        └────────┘
        ┌──────────────────────────────────────────┐
        │  check   cargo check --workspace         │  ← 最快暴露语法/类型错误
        │          --all-targets                   │     并产出 Cargo.lock
        └────┬───────────────┬─────────────────────┘
             │               │
   ┌─────────▼──────┐  ┌─────▼───────────────────────┐  ┌──────────────┐
   │ test（逐 crate │  │ build-musl (matrix ×2)      │  │ clippy       │
   │  硬超时+串行） │  │  cross build + 静态链接断言 │  │ continue-on- │
   └────────────────┘  │  + 产物可执行冒烟           │  │ error        │
                       └─────┬───────────────────────┘  └──────────────┘
                             │ needs
                       ┌─────▼──────────┐
                       │ e2e（真实二进制）│
                       └────────────────┘
```

设计要点（都是被真实 CI 事故逼出来的）：

1. **`check` 必须最先跑，`build`/`test`/`clippy` 都 `needs: check`。**
   否则一轮要等两个平台的交叉编译跑完，才知道有没有一个拼错的字段名。
2. **`test` 拆成逐 crate + `timeout -k 10 300` + `--test-threads=1`。**
   一旦有测试死锁，整条流水线会挂到 6 小时上限且拿不到日志；
   `timeout` 的退出码 124 能立刻区分「被 kill」和「断言失败」，
   `--nocapture --test-threads=1` 让日志里最后一条就是卡住的那个用例。
3. **`fmt` 与 `clippy` 首轮 `continue-on-error: true`。**
   风格项不应该掩盖编译错误。树稳定后再改成门禁。
4. **`Swatinem/rust-cache@v2`**，`build-musl` 用 `key: musl-<target>` 分桶，
   避免两个矩阵互踩缓存。
5. **静态链接用断言而不是「看起来没问题」**：x86_64 上直接 `ldd` 并要求输出
   「not a dynamic executable」或「statically linked」；aarch64 上用
   `qemu-aarch64-static --version` 真跑一次。
6. **`e2e` 依赖 `build-musl` 并下载 x86_64 产物**，用真实二进制跑全链路。

### 5.2 `e2e` 覆盖的语义

`tests/e2e/e2e.py` 只依赖 Python 标准库。它验证的是**单测结构上无法发现的问题**：

| 编号 | 断言（语义） |
|---|---|
| 1 | 两个二进制都能 `--version` / `--print-default-config`（静态产物真的能跑） |
| 2 | 服务端起来并通过 `/api/v1/health` 探活 |
| 3 | 错误密码 → 401；无凭证访问受保护接口 → 401 |
| 4 | 正确密码可登录，`/auth/me` 是 admin |
| 5 | 无效接入令牌注册 → 401 |
| 6 | 客户端完成注册，状态变 `online` |
| 7 | **客户端上报了 64 位十六进制的 EndpointId**（Iroh 确实参与其中） |
| 8 | 创建 HTTP 隧道后，**经公网入口 + `Host:` 的请求拿到了客户端本地服务的响应体** |
| 9 | 配置 GET→PUT→GET 闭环，且 token 掩码不会被回写覆盖；非法配置被 400 拒绝 |
| 10 | 未知 API 路径返回 JSON 404（不被 SPA 吞掉） |
| 11 | 内嵌控制台首页可访问 |
| 12 | 两个进程收到 SIGTERM 后退出码为 0（优雅关停真的生效） |

**失败时自动 dump 服务端与客户端日志尾部** —— 没有现场的那条失败，下一轮只能靠猜。

> e2e 里把 `p2p.relay_mode` 设为 `disabled` 且 `address_lookup = false`：
> 这样 Iroh 节点在**完全离线**的环境下也能绑定成功（我们只断言 EndpointId，
> 不断言能否连上公共中继），保证 CI 结果稳定。

### 5.3 `release.yml`

触发：push `v*` tag，或手动指定 tag。

```
build(matrix ×2)  →  package(.tar.gz + sha256)  →  publish(GitHub Release)
```

- 打包内容：`rscross-server`、`rscross-client`、`README.md`、`LICENSE`。
- 发布说明由 **tag 注解正文**拼上产物清单与校验和 —— 说明只有一处来源，
  不会和仓库里的副本漂移。
- **先让 `main` 的 CI 绿了再打 tag**：tag 流水线的第一个 job 也是同样的门禁，
  main 红着打 tag 只是多烧一轮。

发版命令：

```bash
git tag -a v0.1.0 -F tag_msg.txt     # 必须 -a：轻量 tag 没有正文
git push origin v0.1.0
git ls-remote origin refs/tags/v0.1.0   # 复核，不看 push 的输出
```

---

## 6. 部署与运行（产物侧）

```bash
# 服务端（首次运行会在标准错误输出打印初始管理员密码）
./rscross-server --config /etc/rscross/server.toml

# 客户端（令牌在控制台「客户端管理」页签发）
./rscross-client \
  --server http://<服务端IP>:7800 \
  --tunnel-server <服务端IP>:7835 \
  --name node-1 \
  --enroll-token rse_xxxxxxxx
```

systemd 最小单元（服务端）：

```ini
[Unit]
Description=rscross server
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rscross-server --config /etc/rscross/server.toml
Restart=on-failure
RestartSec=3
# 日志交给 journald，无需内置文件轮转
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rscross

[Install]
WantedBy=multi-user.target
```

排查用的几个固定入口：

```bash
./rscross-server --check                          # 只校验配置
./rscross-server --print-default-config           # 参考配置
curl -s localhost:7800/api/v1/health | jq         # 版本 / uptime / EndpointId
journalctl -u rscross-server -f                   # 实时日志（等价于控制台「日志」页）
```
