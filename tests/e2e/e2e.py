#!/usr/bin/env python3
"""rscross 端到端测试（两种部署形态都跑一遍）。

为什么必须有这一层：
    单元测试只能证明「我自己和自己自洽」。协议字段名写错、控制台与客户端对
    「归属节点」的理解不一致、静态二进制在 musl 下起不来 —— 这些**单测全绿也照样漏**。
    所以这里一律用**真实二进制**跑完整链路。

覆盖的两种形态（需求里的方式 A / 方式 B）：
    ① 单机内嵌  server --embedded   客户端直连服务端内嵌的控制台
    ② 多节点汇聚 console + server --managed   两者都接入独立控制台

只依赖 Python 标准库。

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


class Proc:
    """带日志文件的子进程包装。"""

    def __init__(self, label: str, binary: Path, args: list[str], log_path: Path):
        self.label = label
        self.log_path = log_path
        self._file = open(log_path, "wb")
        env = dict(os.environ)
        env["RUST_BACKTRACE"] = "1"
        self.proc = subprocess.Popen(
            [str(binary), *args],
            stdout=self._file,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(log_path.parent),
        )

    def alive(self) -> bool:
        return self.proc.poll() is None

    def returncode(self):
        return self.proc.poll()

    def log(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def tail(self, lines: int = 60) -> str:
        return "\n".join(self.log().splitlines()[-lines:])

    def stop(self) -> int | None:
        if self.proc.poll() is not None:
            return self.proc.returncode
        self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            print(f"!! {self.label} 未在 20 秒内退出，发送 SIGKILL", flush=True)
            self.proc.kill()
            code = self.proc.wait(timeout=10)
        self._file.close()
        return code


def dump(procs: list[Proc]) -> None:
    print("\n" + "=" * 72, flush=True)
    print("诊断信息（失败时自动打印现场）", flush=True)
    print("=" * 72, flush=True)
    for proc in procs:
        print(f"\n----- {proc.label} 日志尾部 ({proc.log_path}) -----", flush=True)
        print(proc.tail(), flush=True)


# --------------------------------------------------------------- 通用步骤


def login(base: str, password: str) -> str | None:
    status, payload = http_json(
        "POST", base + "/api/v1/auth/login", {"username": "admin", "password": password}
    )
    if status == 200 and payload and payload.get("token"):
        return payload["token"]
    return None


def wait_console_ready(base: str, timeout: float = 60.0) -> bool:
    ok, _ = wait_until(
        "控制台就绪",
        lambda: (lambda r: r[0] == 200 and r[1] and r[1].get("ok"))(
            http_json("GET", base + "/api/v1/health", timeout=2)
        ),
        timeout=timeout,
    )
    return ok


def wait_node_online(base: str, token: str, name: str | None = None, timeout: float = 90.0):
    """等节点 online 且已上报 tunnel_port。"""

    def probe():
        status, nodes = http_json("GET", base + "/api/v1/nodes", token=token)
        if status != 200 or not nodes:
            return None
        for node in nodes:
            if name and node.get("name") != name:
                continue
            if node.get("status") == "online" and node.get("tunnel_port"):
                return node
        return None

    return wait_until("节点上线", probe, timeout=timeout)


def wait_client_online(base: str, token: str, name: str, timeout: float = 90.0):
    def probe():
        status, clients = http_json("GET", base + "/api/v1/clients", token=token)
        if status != 200 or not clients:
            return None
        for item in clients:
            if item.get("name") == name and item.get("status") == "online":
                return item
        return None

    return wait_until("客户端上线", probe, timeout=timeout)


# --------------------------------------------------------------- 场景一：单机内嵌


def write_node_config(
    path: Path,
    *,
    name: str,
    mode: str,
    state_dir: Path,
    tunnel_port: int,
    ingress_port: int,
    console_port: int | None = None,
    public_host: str = "127.0.0.1",
) -> None:
    console_line = (
        f'console_url = "http://127.0.0.1:{console_port}"\n' if mode == "managed" and console_port else ""
    )
    path.write_text(
        f"""[node]
name = "{name}"
control_mode = "{mode}"
{console_line}state_dir = "{state_dir.as_posix()}"
public_host = "{public_host}"
tunnel_bind = "127.0.0.1:{tunnel_port}"
ingress_bind = "127.0.0.1:{ingress_port}"

[tunnel]
auto_reconnect = true
reconnect_delay_ms = 1000
startup_timeout_secs = 15

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


def write_console_config(path: Path, *, bind_port: int, db_path: Path, password: str) -> None:
    path.write_text(
        f"""[console]
name = "e2e-console"
bind = "127.0.0.1:{bind_port}"
heartbeat_secs = 2
offline_after_secs = 30
shutdown_grace_secs = 5

[admin]
initial_user = "admin"
initial_password = "{password}"
session_ttl_hours = 1

[database]
path = "{db_path.as_posix()}"

[auth]
allow_self_enroll = false

[log]
level = "info"
ring_capacity = 500
""",
        encoding="utf-8",
    )


def write_client_config(path: Path, *, name: str, console_port: int, state_dir: Path) -> None:
    path.write_text(
        f"""[client]
name = "{name}"
console_url = "http://127.0.0.1:{console_port}"
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


def run_pipeline(
    dist: Path,
    work: Path,
    *,
    label: str,
    console_base: str,
    password: str,
    console_port: int,
    ingress_port: int,
    token: str,
    procs: list[Proc],
    probe_p2p_ok: bool = False,
) -> None:
    """两种形态共用的后半段：建客户端 -> 建隧道 -> 验证真实转发 -> 优雅退出。"""

    # ---------------- 客户端 ----------------
    status, issued = http_json(
        "POST", console_base + "/api/v1/clients", {"name": "e2e-node", "ttl_minutes": 10}, token=token
    )
    if not check(f"{label}: 可签发客户端接入令牌", status == 200 and issued and issued.get("enroll_token"),
                 f"status={status} body={issued}"):
        return
    enroll_token = issued["enroll_token"]
    check(
        f"{label}: 客户端命令指向控制台（而不是手填节点地址）",
        "--console" in issued["command"] and enroll_token in issued["command"],
        issued["command"],
    )

    status, _ = http_json(
        "POST",
        console_base + "/api/v1/agent/enroll",
        {"token": "rse_" + "0" * 64, "name": "bad", "runtime": {}},
    )
    check_eq(f"{label}: 无效接入令牌被拒绝", 401, status)

    client_cfg = work / "client.toml"
    write_client_config(
        client_cfg,
        name="e2e-node",
        console_port=console_port,
        state_dir=work / "client-state",
    )
    client = Proc(
        f"{label}/client",
        dist / "rscross-client",
        ["--config", str(client_cfg), "--enroll-token", enroll_token],
        work / "client.log",
    )
    procs.append(client)

    ok, found = wait_client_online(console_base, token, "e2e-node")
    if not check(f"{label}: 客户端完成注册并心跳为 online", ok, str(found)):
        return

    endpoint_id = found.get("endpoint_id") or ""
    check(
        f"{label}: 客户端上报了 Iroh EndpointId（64 位十六进制）",
        len(endpoint_id) == 64 and all(c in "0123456789abcdef" for c in endpoint_id),
        f"endpoint_id={endpoint_id!r}",
    )
    check(f"{label}: 客户端被分配到服务端节点", bool(found.get("node_id")), str(found.get("node_id")))
    check(f"{label}: 客户端上报了平台信息", bool(found.get("os")), str(found.get("os")))

    # ---------------- 本地服务 + 隧道 ----------------
    echo_port = free_port()
    echo_server = http.server.HTTPServer(("127.0.0.1", echo_port), EchoHandler)
    threading.Thread(target=echo_server.serve_forever, daemon=True).start()

    status, tunnel = http_json(
        "POST",
        f"{console_base}/api/v1/clients/{found['id']}/tunnels",
        {
            "name": "e2e-web",
            "proto": "http",
            "local_addr": f"127.0.0.1:{echo_port}",
            "host": "e2e.local",
        },
        token=token,
    )
    if not check(f"{label}: 可创建 HTTP 隧道", status == 200 and tunnel and tunnel.get("id"),
                 f"status={status} body={tunnel}"):
        echo_server.shutdown()
        return

    def tunnel_established():
        return "隧道已建立" in client.log() or None

    ok, _ = wait_until(f"{label}: 客户端建立隧道", tunnel_established, timeout=90, interval=1.0)
    check(f"{label}: 客户端按控制面配置建立了反向隧道", ok, "等待客户端日志出现「隧道已建立」")

    def ingress_works():
        try:
            status, body = request_with_host(ingress_port, "e2e.local", "/", timeout=8)
        except Exception:  # noqa: BLE001
            return None
        if status == 200 and body.strip() == "rscross-e2e-ok":
            return (status, body)
        return None

    ok, result = wait_until(f"{label}: 公网入口可访问隧道", ingress_works, timeout=90, interval=1.0)
    check(
        f"{label}: 经公网入口 + Host 路由到达客户端本地服务（端到端数据面）",
        ok,
        f"结果={result}",
    )

    if probe_p2p_ok:
        # P2P 探测结果只作信息输出：能否直连取决于地址可达性，不作为门禁。
        log = client.log()
        print(
            f"      · P2P 探测：{'已建立直连' if 'P2P 直连成功' in log else '未直连（回落中继，属预期）'}",
            flush=True,
        )

    echo_server.shutdown()
    return


# --------------------------------------------------------------- 场景编排


def scenario_embedded(dist: Path, work: Path) -> None:
    label = "单机内嵌"
    print("\n" + "-" * 72, flush=True)
    print(f"场景：{label} —— rscross-server --embedded（自带控制台）", flush=True)
    print("-" * 72, flush=True)

    console_port = free_port()
    tunnel_port = free_port()
    ingress_port = free_port()
    status_dir = work / "embedded" / "server-state"
    node_cfg = work / "embedded" / "server.toml"
    console_cfg = work / "embedded" / "console.toml"
    node_cfg.parent.mkdir(parents=True, exist_ok=True)

    write_node_config(
        node_cfg,
        name="local-node",
        mode="embedded",
        state_dir=status_dir,
        tunnel_port=tunnel_port,
        ingress_port=ingress_port,
    )
    write_console_config(
        console_cfg,
        bind_port=console_port,
        db_path=status_dir / "rscross-console.db",
        password="e2e-password-123",
    )

    procs: list[Proc] = []
    server = Proc(
        f"{label}/server",
        dist / "rscross-server",
        ["--embedded", "--config", str(node_cfg), "--console-config", str(console_cfg)],
        work / "embedded" / "server.log",
    )
    procs.append(server)

    console_base = f"http://127.0.0.1:{console_port}"
    if not check(f"{label}: 内嵌控制台可探活", wait_console_ready(console_base), console_base):
        dump(procs)
        for proc in procs:
            proc.stop()
        return

    token = login(console_base, "e2e-password-123")
    if not check(f"{label}: 可登录内嵌控制台", bool(token), console_base):
        dump(procs)
        for proc in procs:
            proc.stop()
        return

    status, nodes = http_json("GET", console_base + "/api/v1/nodes", token=token)
    check(
        f"{label}: 服务端启动后自动注册为本机节点",
        status == 200 and len(nodes) == 1 and nodes[0]["name"] == "local-node",
        str(nodes)[:200],
    )

    ok, node = wait_node_online(console_base, token)
    check(f"{label}: 节点上报了反向隧道端口", ok and node and node.get("tunnel_port") == tunnel_port,
          f"tunnel_port={node.get('tunnel_port') if node else None} expected={tunnel_port}")
    if node:
        check(
            f"{label}: 节点上报了 Iroh EndpointId",
            len(node.get("endpoint_id") or "") == 64,
            str(node.get("endpoint_id"))[:20],
        )

    run_pipeline(
        dist,
        work / "embedded",
        label=label,
        console_base=console_base,
        password="e2e-password-123",
        console_port=console_port,
        ingress_port=ingress_port,
        token=token,
        procs=procs,
        probe_p2p_ok=True,
    )

    # 概览与日志
    status, overview = http_json("GET", console_base + "/api/v1/overview", token=token)
    check(
        f"{label}: 概览统计包含节点/客户端/隧道",
        status == 200 and overview.get("nodes_total", 0) >= 1
        and overview.get("clients_total", 0) >= 1
        and overview.get("tunnels_total", 0) >= 1,
        str(overview)[:200],
    )
    status, logs = http_json("GET", console_base + "/api/v1/logs?limit=50", token=token)
    check(f"{label}: 日志接口返回事件", status == 200 and len(logs.get("entries", [])) > 0)

    # 控制台配置读写
    status, cfg = http_json("GET", console_base + "/api/v1/config", token=token)
    if check(f"{label}: 可读取控制台配置", status == 200 and cfg and cfg.get("config"), f"status={status}"):
        next_cfg = cfg["config"]
        next_cfg["console"]["heartbeat_secs"] = 3
        status, _ = http_json("PUT", console_base + "/api/v1/config", next_cfg, token=token)
        check_eq(f"{label}: 可保存控制台配置", 200, status)

        status, cfg2 = http_json("GET", console_base + "/api/v1/config", token=token)
        check_eq(f"{label}: 配置修改已生效", 3, cfg2["config"]["console"]["heartbeat_secs"])

        bad = json.loads(json.dumps(cfg2["config"]))
        bad["console"]["heartbeat_secs"] = 0
        status, _ = http_json("PUT", console_base + "/api/v1/config", bad, token=token)
        check_eq(f"{label}: 非法配置被拒绝（400）", 400, status)

    status, _ = http_json("GET", console_base + "/api/v1/does-not-exist")
    check_eq(f"{label}: 未知 API 路径返回 JSON 404", 404, status)

    # 优雅退出
    for proc in reversed(procs):
        code = proc.stop()
        check(f"{label}: {proc.label} 收到 SIGTERM 后正常退出", code == 0, f"退出码={code}")


def scenario_standalone(dist: Path, work: Path) -> None:
    label = "多节点汇聚"
    print("\n" + "-" * 72, flush=True)
    print(f"场景：{label} —— rscross-console + rscross-server --managed", flush=True)
    print("-" * 72, flush=True)

    console_port = free_port()
    tunnel_port = free_port()
    ingress_port = free_port()
    root = work / "standalone"
    root.mkdir(parents=True, exist_ok=True)

    console_cfg = root / "console.toml"
    node_cfg = root / "server.toml"
    node_state = root / "server-state"

    write_console_config(
        console_cfg,
        bind_port=console_port,
        db_path=root / "console.db",
        password="e2e-password-456",
    )
    write_node_config(
        node_cfg,
        name="remote-node",
        mode="managed",
        state_dir=node_state,
        tunnel_port=tunnel_port,
        ingress_port=ingress_port,
        console_port=console_port,
    )

    procs: list[Proc] = []
    console = Proc(
        f"{label}/console",
        dist / "rscross-console",
        ["--config", str(console_cfg)],
        root / "console.log",
    )
    procs.append(console)

    console_base = f"http://127.0.0.1:{console_port}"
    if not check(f"{label}: 独立控制台可探活", wait_console_ready(console_base), console_base):
        dump(procs)
        for proc in procs:
            proc.stop()
        return

    token = login(console_base, "e2e-password-456")
    if not check(f"{label}: 可登录独立控制台", bool(token), console_base):
        dump(procs)
        for proc in procs:
            proc.stop()
        return

    status, health = http_json("GET", console_base + "/api/v1/health")
    check_eq(f"{label}: 独立控制台 self-report 不是内嵌形态", False, bool(health.get("embedded")))

    # 在控制台创建节点 -> 拿命令 -> 启动服务端
    status, created = http_json(
        "POST", console_base + "/api/v1/nodes", {"name": "remote-node", "public_host": "127.0.0.1"},
        token=token,
    )
    if not check(f"{label}: 可在控制台创建节点并签发令牌",
                 status == 200 and created and created.get("node_token"), f"status={status}"):
        dump(procs)
        for proc in procs:
            proc.stop()
        return

    check(
        f"{label}: 节点命令为 managed 形态且带令牌",
        "--managed" in created["command"] and created["node_token"] in created["command"],
        created["command"],
    )

    status, _ = http_json(
        "POST", console_base + "/api/v1/node/enroll", {"token": "rsn_" + "0" * 64, "runtime": {}}
    )
    check_eq(f"{label}: 无效节点令牌被拒绝", 401, status)

    server = Proc(
        f"{label}/server",
        dist / "rscross-server",
        [
            "--managed",
            "--config",
            str(node_cfg),
            "--console",
            console_base,
            "--enroll-token",
            created["node_token"],
            "--name",
            "remote-node",
        ],
        root / "server.log",
    )
    procs.append(server)

    ok, node = wait_node_online(console_base, token, name="remote-node")
    if not check(f"{label}: 服务端以节点身份接入中央控制台", ok, str(node)):
        dump(procs)
        for proc in reversed(procs):
            proc.stop()
        return
    check(
        f"{label}: 节点上报的隧道端口与控制台一致",
        node.get("tunnel_port") == tunnel_port,
        f"{node.get('tunnel_port')} vs {tunnel_port}",
    )

    run_pipeline(
        dist,
        root,
        label=label,
        console_base=console_base,
        password="e2e-password-456",
        console_port=console_port,
        ingress_port=ingress_port,
        token=token,
        procs=procs,
    )

    # 审计里应当能看到「创建节点」与「签发令牌」
    status, audit = http_json("GET", console_base + "/api/v1/audit?limit=50", token=token)
    actions = {a.get("action") for a in (audit or [])}
    check(
        f"{label}: 审计记录了节点创建与令牌签发",
        {"create_node", "issue_enroll_token"} <= actions,
        str(sorted(actions)),
    )

    for proc in reversed(procs):
        code = proc.stop()
        check(f"{label}: {proc.label} 收到 SIGTERM 后正常退出", code == 0, f"退出码={code}")


# --------------------------------------------------------------- main


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python3 tests/e2e/e2e.py <二进制目录>", file=sys.stderr)
        return 2

    dist = Path(sys.argv[1]).resolve()
    binaries = {
        "rscross-server": dist / "rscross-server",
        "rscross-client": dist / "rscross-client",
        "rscross-console": dist / "rscross-console",
    }
    for name, binary in binaries.items():
        if not binary.exists():
            print(f"找不到二进制: {binary}", file=sys.stderr)
            return 2

    work = Path(tempfile.mkdtemp(prefix="rscross-e2e-"))
    print(f"工作目录: {work}", flush=True)

    # 二进制自检
    for name, binary in binaries.items():
        proc = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=30)
        check(f"{name} 可执行", proc.returncode == 0, (proc.stdout or proc.stderr).strip())

    default_cfg = subprocess.run(
        [str(binaries["rscross-server"]), "--print-default-config"],
        capture_output=True, text=True, timeout=30,
    )
    check(
        "服务端可打印默认配置且包含 [node]",
        default_cfg.returncode == 0 and "[node]" in default_cfg.stdout,
        f"rc={default_cfg.returncode}",
    )

    scenario_embedded(dist, work)
    scenario_standalone(dist, work)

    print("\n" + "=" * 72, flush=True)
    if FAILURES:
        print(f"失败 {len(FAILURES)}/{CHECKS} 项：", flush=True)
        for item in FAILURES:
            print("  - " + item, flush=True)
        return 1
    print(f"全部通过：{CHECKS}/{CHECKS}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
