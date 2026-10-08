#!/usr/bin/env python3
"""rscross 端到端测试。

设计意图（为什么必须有这一层）：
    单元测试只能证明「我自己和自己自洽」。协议字段名写错、服务端与客户端的
    路由键不一致、静态二进制在 musl 下起不来 —— 这些**单测全绿也照样漏**。
    所以这里一律用**真实二进制**跑：起服务端 → 起客户端 → 建隧道 → 真发 HTTP 请求。

只依赖 Python 标准库，Linux / macOS / Windows 均可（CI 上跑 Linux musl 产物）。

用法：
    python3 tests/e2e/e2e.py <二进制所在目录>
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

CHECKS = 0
FAILURES: list[str] = []

SERVER_LOG: Path | None = None
CLIENT_LOG: Path | None = None
SERVER_PROC: subprocess.Popen | None = None
CLIENT_PROC: subprocess.Popen | None = None


# --------------------------------------------------------------- 断言工具


def check(name: str, ok: bool, detail: str = "") -> bool:
    global CHECKS
    CHECKS += 1
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail:
        line += f"  |  {detail}"
    print(line, flush=True)
    if not ok:
        FAILURES.append(f"{name} -> {detail}")
    return ok


def check_eq(name: str, expected, actual) -> bool:
    return check(name, expected == actual, f"expected={expected!r} actual={actual!r}")


def wait_until(name: str, predicate, timeout: float, interval: float = 0.5):
    """轮询等待。返回 (ok, last_value)。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
        except Exception as err:  # noqa: BLE001 - 轮询期任何异常都当作「还没好」
            last = f"<{err}>"
        if last:
            return True, last
        time.sleep(interval)
    return False, last


# --------------------------------------------------------------- 网络工具


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_json(method: str, url: str, body=None, token: str | None = None, timeout: float = 10.0):
    """返回 (status, parsed_json_or_text)。"""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            try:
                return response.status, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return response.status, raw
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", "replace")
        try:
            return err.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return err.code, raw


def request_with_host(port: int, host_header: str, path: str = "/", timeout: float = 10.0):
    """显式设置 Host 头（http.client 检测到 Host 会 skip_host，因此可覆盖）。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": host_header})
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        conn.close()


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """固定返回体，便于断言流量确实到达了客户端本地服务。"""

    BODY = b"rscross-e2e-ok"

    def do_GET(self):  # noqa: N802 - 标准库要求的命名
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *_args):  # 静音
        pass


# --------------------------------------------------------------- 进程管理


def spawn(binary: Path, args: list[str], log_path: Path) -> subprocess.Popen:
    log_file = open(log_path, "wb")
    env = dict(os.environ)
    env["RUST_BACKTRACE"] = "1"
    return subprocess.Popen(
        [str(binary), *args],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
        cwd=str(log_path.parent),
    )


def tail(path: Path, lines: int = 60) -> str:
    if not path or not path.exists():
        return "<无日志>"
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as err:
        return f"<读取日志失败: {err}>"
    return "\n".join(content[-lines:])


def dump_diagnostics() -> None:
    print("\n" + "=" * 72, flush=True)
    print("诊断信息（失败时自动打印现场）", flush=True)
    print("=" * 72, flush=True)
    for label, path in (("服务端", SERVER_LOG), ("客户端", CLIENT_LOG)):
        print(f"\n----- {label}日志尾部 -----", flush=True)
        print(tail(path) if path else "<未启动>", flush=True)


def terminate(proc: subprocess.Popen | None, label: str) -> int | None:
    if proc is None or proc.poll() is not None:
        return proc.returncode if proc else None
    proc.send_signal(signal.SIGTERM)
    try:
        return proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        print(f"!! {label} 未在 20 秒内退出，发送 SIGKILL", flush=True)
        proc.kill()
        return proc.wait(timeout=10)


# --------------------------------------------------------------- 主流程


def main() -> int:
    global SERVER_LOG, CLIENT_LOG, SERVER_PROC, CLIENT_PROC

    if len(sys.argv) < 2:
        print("用法: python3 tests/e2e/e2e.py <二进制目录>", file=sys.stderr)
        return 2

    dist = Path(sys.argv[1]).resolve()
    server_bin = dist / "rscross-server"
    client_bin = dist / "rscross-client"
    for binary in (server_bin, client_bin):
        if not binary.exists():
            print(f"找不到二进制: {binary}", file=sys.stderr)
            return 2

    work = Path(tempfile.mkdtemp(prefix="rscross-e2e-"))
    print(f"工作目录: {work}", flush=True)

    admin_port, ingress_port, tunnel_port, echo_port = (
        free_port(),
        free_port(),
        free_port(),
        free_port(),
    )

    server_cfg = work / "server.toml"
    client_cfg = work / "client.toml"
    SERVER_LOG = work / "server.log"
    CLIENT_LOG = work / "client.log"

    server_cfg.write_text(
        f"""[server]
name = "e2e"
admin_bind = "127.0.0.1:{admin_port}"
ingress_bind = "127.0.0.1:{ingress_port}"
tunnel_bind = "127.0.0.1:{tunnel_port}"
heartbeat_secs = 2
offline_after_secs = 30
shutdown_grace_secs = 5

[tunnel]
token = "e2e-shared-token"
auto_reconnect = true
reconnect_delay_ms = 1000
startup_timeout_secs = 15

[admin]
initial_user = "admin"
initial_password = "e2e-password-123"
session_ttl_hours = 1

[database]
path = "{(work / 'rscross.db').as_posix()}"

[auth]
allow_self_enroll = false

[log]
level = "info"
ring_capacity = 500

[p2p]
enabled = true
relay_mode = "disabled"
address_lookup = false
secret_key_file = "{(work / 'server-node.key').as_posix()}"
""",
        encoding="utf-8",
    )

    state_dir = work / "client-state"
    client_cfg.write_text(
        f"""[client]
name = "e2e-node"
server_url = "http://127.0.0.1:{admin_port}"
tunnel_server = "127.0.0.1:{tunnel_port}"
state_dir = "{state_dir.as_posix()}"

[log]
level = "info"

[p2p]
enabled = true
relay_mode = "disabled"
address_lookup = false
secret_key_file = "{(state_dir / 'node.key').as_posix()}"
""",
        encoding="utf-8",
    )

    base = f"http://127.0.0.1:{admin_port}"

    # ---------------- 0. 二进制自检 ----------------
    version = subprocess.run(
        [str(server_bin), "--version"], capture_output=True, text=True, timeout=30
    )
    check("服务端二进制可执行", version.returncode == 0, version.stdout.strip() or version.stderr.strip())

    default_cfg = subprocess.run(
        [str(client_bin), "--print-default-config"], capture_output=True, text=True, timeout=30
    )
    check(
        "客户端可打印默认配置",
        default_cfg.returncode == 0 and "[client]" in default_cfg.stdout,
        f"rc={default_cfg.returncode}",
    )

    # ---------------- 1. 启动服务端 ----------------
    SERVER_PROC = spawn(server_bin, ["--config", str(server_cfg)], SERVER_LOG)
    healthy = False
    for _ in range(120):
        if SERVER_PROC.poll() is not None:
            break
        try:
            status, payload = http_json("GET", base + "/api/v1/health", timeout=2)
            if status == 200 and payload and payload.get("ok"):
                healthy = True
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)

    if not check("服务端启动并通过 /api/v1/health 探活", healthy,
                 f"退出码={SERVER_PROC.poll()}"):
        dump_diagnostics()
        terminate(SERVER_PROC, "服务端")
        return 1

    _, health = http_json("GET", base + "/api/v1/health")
    check("健康检查暴露版本号", bool(health.get("version")), str(health.get("version")))

    # ---------------- 2. 鉴权 ----------------
    status, _ = http_json("POST", base + "/api/v1/auth/login",
                          {"username": "admin", "password": "wrong-password"})
    check_eq("错误密码返回 401", 401, status)

    status, _ = http_json("GET", base + "/api/v1/clients")
    check_eq("未携带凭证访问受保护接口返回 401", 401, status)

    status, login = http_json("POST", base + "/api/v1/auth/login",
                              {"username": "admin", "password": "e2e-password-123"})
    if not check("正确密码可登录", status == 200 and login and login.get("token"),
                 f"status={status}"):
        dump_diagnostics()
        terminate(SERVER_PROC, "服务端")
        return 1
    token = login["token"]

    status, me = http_json("GET", base + "/api/v1/auth/me", token=token)
    check("会话可读取当前用户", status == 200 and me.get("username") == "admin", str(me))

    # ---------------- 3. 签发接入令牌 ----------------
    status, issued = http_json("POST", base + "/api/v1/clients",
                               {"name": "e2e-node", "ttl_minutes": 10}, token=token)
    if not check("可签发接入令牌", status == 200 and issued and issued.get("enroll_token"),
                 f"status={status} body={issued}"):
        dump_diagnostics()
        terminate(SERVER_PROC, "服务端")
        return 1
    enroll_token = issued["enroll_token"]
    check("接入命令包含服务端地址与令牌",
          base in issued["command"] and enroll_token in issued["command"],
          issued["command"])

    # 无效令牌必须被拒绝
    bad = "rse_" + "0" * 64
    status, _ = http_json("POST", base + "/api/v1/agent/enroll",
                          {"token": bad, "name": "bad-node", "runtime": {}})
    check_eq("无效接入令牌被拒绝", 401, status)

    # ---------------- 4. 启动客户端 ----------------
    CLIENT_PROC = spawn(
        client_bin,
        ["--config", str(client_cfg), "--enroll-token", enroll_token],
        CLIENT_LOG,
    )

    def client_online():
        status, clients = http_json("GET", base + "/api/v1/clients", token=token)
        if status != 200 or not clients:
            return None
        for item in clients:
            if item.get("name") == "e2e-node" and item.get("status") == "online":
                return item
        return None

    ok, client = wait_until("客户端上线", client_online, timeout=90)
    if not check("客户端完成注册并心跳为 online", ok, str(client)):
        dump_diagnostics()
        terminate(CLIENT_PROC, "客户端")
        terminate(SERVER_PROC, "服务端")
        return 1

    endpoint_id = client.get("endpoint_id") or ""
    check(
        "客户端上报了 Iroh EndpointId（64 位十六进制，说明 Iroh 已集成）",
        len(endpoint_id) == 64 and all(c in "0123456789abcdef" for c in endpoint_id),
        f"endpoint_id={endpoint_id!r}",
    )
    check_eq("客户端上报了平台信息", True, bool(client.get("os")), )

    # ---------------- 5. 本地服务 + 建隧道 ----------------
    echo_server = http.server.HTTPServer(("127.0.0.1", echo_port), EchoHandler)
    threading.Thread(target=echo_server.serve_forever, daemon=True).start()
    check("本地回显服务已启动", True, f"127.0.0.1:{echo_port}")

    status, tunnel = http_json(
        "POST",
        f"{base}/api/v1/clients/{client['id']}/tunnels",
        {
            "name": "e2e-web",
            "proto": "http",
            "local_addr": f"127.0.0.1:{echo_port}",
            "host": "e2e.local",
        },
        token=token,
    )
    if not check("可创建 HTTP 隧道", status == 200 and tunnel and tunnel.get("id"),
                 f"status={status} body={tunnel}"):
        dump_diagnostics()
        terminate(CLIENT_PROC, "客户端")
        terminate(SERVER_PROC, "服务端")
        return 1

    # ---------------- 6. 客户端应建立隧道 ----------------
    def tunnel_established():
        if CLIENT_LOG.exists() and "隧道已建立" in CLIENT_LOG.read_text(
            encoding="utf-8", errors="replace"
        ):
            return True
        return None

    ok, _ = wait_until("客户端建立隧道", tunnel_established, timeout=90, interval=1.0)
    check("客户端按控制面配置建立了反向隧道", ok, "等待客户端日志出现「隧道已建立」")

    # ---------------- 7. 流量真的通了吗 ----------------
    def ingress_works():
        try:
            status, body = request_with_host(ingress_port, "e2e.local", "/", timeout=8)
        except Exception:  # noqa: BLE001
            return None
        if status == 200 and body.strip() == "rscross-e2e-ok":
            return (status, body)
        return None

    ok, result = wait_until("公网入口可访问隧道", ingress_works, timeout=90, interval=1.0)
    check(
        "经公网入口 + Host 路由到达客户端本地服务（端到端数据面）",
        ok,
        f"结果={result}",
    )

    # ---------------- 8. 配置读写 ----------------
    status, cfg = http_json("GET", base + "/api/v1/config", token=token)
    check("可读取配置", status == 200 and cfg and cfg.get("config"), f"status={status}")
    if status == 200:
        check_eq("配置中的 token 被掩码", "****", cfg["config"]["tunnel"]["token"])

        next_cfg = cfg["config"]
        next_cfg["server"]["heartbeat_secs"] = 3
        status, _ = http_json("PUT", base + "/api/v1/config", next_cfg, token=token)
        check_eq("可保存配置", 200, status)

        status, cfg2 = http_json("GET", base + "/api/v1/config", token=token)
        check_eq("配置修改已生效", 3, cfg2["config"]["server"]["heartbeat_secs"])

        # 关键不变量：GET 返回的 token 是掩码，PUT 若把这串掩码原样写回，
        # 真实 token 就会被冲掉。这里直接查磁盘上的配置文件。
        on_disk = server_cfg.read_text(encoding="utf-8")
        check(
            "掩码未被写进配置文件（真实 token 保留）",
            "e2e-shared-token" in on_disk and "****" not in on_disk,
            on_disk[:200].replace("\n", " / "),
        )

        bad_cfg = dict(cfg2["config"])
        bad_cfg["server"] = dict(bad_cfg["server"])
        bad_cfg["server"]["heartbeat_secs"] = 0
        status, _ = http_json("PUT", base + "/api/v1/config", bad_cfg, token=token)
        check_eq("非法配置被拒绝（400）", 400, status)

    # ---------------- 9. 概览与日志 ----------------
    status, overview = http_json("GET", base + "/api/v1/overview", token=token)
    check(
        "概览返回客户端/隧道统计",
        status == 200 and overview.get("clients_total", 0) >= 1
        and overview.get("tunnels_total", 0) >= 1,
        str(overview)[:200],
    )
    check("概览暴露 Iroh 节点状态", "p2p" in overview and "path" in overview)

    status, logs = http_json("GET", base + "/api/v1/logs?limit=50", token=token)
    check(
        "日志接口返回本进程事件",
        status == 200 and logs.get("entries") is not None and len(logs["entries"]) > 0,
        f"status={status}",
    )

    status, audit = http_json("GET", base + "/api/v1/audit?limit=20", token=token)
    check("审计接口记录了登录与隧道创建",
          status == 200 and any(a.get("action") == "login" for a in audit),
          str(audit)[:200])

    # ---------------- 10. 静态资源与控制台 ----------------
    try:
        with urllib.request.urlopen(base + "/", timeout=10) as response:
            html = response.read().decode("utf-8", "replace")
        check("内嵌控制台首页可访问", response.status == 200 and "rscross" in html)
    except Exception as err:  # noqa: BLE001
        check("内嵌控制台首页可访问", False, str(err))

    status, _ = http_json("GET", base + "/api/v1/does-not-exist")
    check_eq("未知 API 路径返回 JSON 404", 404, status)

    # ---------------- 11. 优雅退出 ----------------
    client_rc = terminate(CLIENT_PROC, "客户端")
    check("客户端收到 SIGTERM 后正常退出", client_rc == 0, f"退出码={client_rc}")

    server_rc = terminate(SERVER_PROC, "服务端")
    check("服务端收到 SIGTERM 后正常退出", server_rc == 0, f"退出码={server_rc}")

    echo_server.shutdown()

    # ---------------- 汇总 ----------------
    print("\n" + "=" * 72, flush=True)
    if FAILURES:
        print(f"失败 {len(FAILURES)}/{CHECKS} 项：", flush=True)
        for item in FAILURES:
            print("  - " + item, flush=True)
        dump_diagnostics()
        return 1
    print(f"全部通过：{CHECKS}/{CHECKS}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        terminate(CLIENT_PROC, "客户端")
        terminate(SERVER_PROC, "服务端")
