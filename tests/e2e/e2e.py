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
import re
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

# Windows 上产物带 .exe 后缀，其余平台没有。集中成一处，
# 免得每个调用点各写一遍平台判断（漏一处就是「找不到二进制」）。
EXE = ".exe" if os.name == "nt" else ""

# Windows 没有 SIGTERM：优雅关停要靠给进程组发 CTRL_BREAK_EVENT。
# 但它只有在子进程拥有控制台时才发得出去（例如在 mintty 里跑就没有），
# 所以下面做了退化处理 —— 退化时退出码不会是 0，那是平台差异而非缺陷，
# 断言必须能区分这两件事，否则本地跑 Windows 会看到一堆假失败。
CTRL_BREAK = getattr(signal, "CTRL_BREAK_EVENT", None)
NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


def bin_path(dist: Path, name: str) -> Path:
    """拼出产物路径（自动带上平台后缀）。"""
    return dist / f"{name}{EXE}"
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


def free_port_in_pool() -> int:
    """在控制台的公网端口池范围内取一个空闲端口。

    不能直接用 free_port()：内核给的随机端口多半落在 20000-30000 之外，
    而控制面会直接拒绝池外的 remote_port（400）。从 25000 起扫是为了避开
    控制面自动分配区（它从池子起点开始找）。
    """
    for port in range(25000, 30000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("20000-30000 内没有空闲端口")


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def toml_value(text: str, section: str, key: str):
    """从 --print-default-config 的输出里取 [section] 下某个字符串键。

    只处理本仓库自己生成的那几行，不引入 TOML 依赖。
    """
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line.strip("[]")
            continue
        if current == section and "=" in line:
            name, _, value = line.partition("=")
            if name.strip() == key:
                return value.strip().strip('"')
    return None


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


def http_raw(url: str, timeout: float = 10.0):
    """返回 (status, headers_lower, text)。用于校验 HTTP 层（状态码 / Content-Type / 原文）。"""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers, body
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in (err.headers or {}).items()}
        return err.code, headers, body


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


ALL_PROCS: list["Proc"] = []


class Proc:
    """带日志文件的子进程包装。"""

    def __init__(
        self,
        label: str,
        binary: Path,
        args: list[str],
        log_path: Path,
        env_extra: dict[str, str] | None = None,
    ):
        self.label = label
        ALL_PROCS.append(self)
        self.log_path = log_path
        self.graceful_supported = True
        self._file = open(log_path, "wb")
        env = dict(os.environ)
        env["RUST_BACKTRACE"] = "1"
        if env_extra:
            env.update(env_extra)
        self.proc = subprocess.Popen(
            [str(binary), *args],
            stdout=self._file,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(log_path.parent),
            # Windows 上单独开进程组：这样才能只给这一个子进程发 CTRL_BREAK，
            # 而不是把 Ctrl+C 事件广播给整个进程组（那会连脚本自己一起带走）。
            creationflags=NEW_PROCESS_GROUP,
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
            self._file.close()
            return self.proc.returncode
        self._request_shutdown()
        try:
            code = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            print(f"!! {self.label} 未在 20 秒内退出，强制结束", flush=True)
            self.proc.kill()
            code = self.proc.wait(timeout=10)
        self._file.close()
        return code

    def _request_shutdown(self) -> None:
        """请求优雅退出；平台做不到时退化为强制结束，并记下这一点。"""
        if os.name != "nt":
            self.proc.send_signal(signal.SIGTERM)
            return
        try:
            self.proc.send_signal(CTRL_BREAK)
        except (OSError, ValueError) as err:
            # 没有控制台可发信号（如 mintty 下运行）。
            # 这时不能指望退出码为 0 —— 进程是被强制结束的。
            self.graceful_supported = False
            print(f"· {self.label}: 无法发送 CTRL_BREAK（{err}），改为强制结束", flush=True)
            self.proc.terminate()


def dump_all() -> None:
    dump(ALL_PROCS)


def stop_all() -> None:
    """兜底关停：异常路径也要把子进程收干净，否则 runner 上会留孤儿。"""
    for proc in reversed(ALL_PROCS):
        try:
            proc.stop()
        except Exception:  # noqa: BLE001
            pass


def dump(procs: list[Proc]) -> None:
    print("\n" + "=" * 72, flush=True)
    print("诊断信息（失败时自动打印现场）", flush=True)
    print("=" * 72, flush=True)
    for proc in procs:
        print(f"\n----- {proc.label} 日志尾部 ({proc.log_path}) -----", flush=True)
        print(proc.tail(), flush=True)


# --------------------------------------------------------------- 通用步骤


def raw_request(
    method: str,
    url: str,
    body=None,
    headers: dict[str, str] | None = None,
    accept: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str]]:
    """不跟随重定向地发一次请求，返回 (status, 响应头小写键值)。

    专门用来断言 307 之类的重定向 —— http_json 走 urllib 会自动跟随，
    永远看不见 3xx。
    """
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    if accept:
        request.add_header("Accept", accept)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}


def login(base: str, password: str) -> str | None:
    status, payload = http_json(
        "POST", base + "/api/v1/auth/login", {"username": "admin", "password": password}
    )
    if status == 200 and payload and payload.get("token"):
        return payload["token"]
    return None


def health_ok(base: str) -> bool:
    try:
        status, payload = http_json("GET", base + "/api/v1/health", timeout=3)
        return status == 200 and bool(payload) and bool(payload.get("ok"))
    except Exception:  # noqa: BLE001
        return False


def wait_console_ready(base: str, proc: "Proc | None" = None, timeout: float = 60.0) -> bool:
    """等控制台就绪；顺带监视进程是否已经退出（否则只会看到 ConnectionRefused）。"""

    def probe():
        if proc is not None and not proc.alive():
            raise RuntimeError(f"{proc.label} 已退出，退出码={proc.returncode()}")
        status, payload = http_json("GET", base + "/api/v1/health", timeout=2)
        return status == 200 and bool(payload) and bool(payload.get("ok"))

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if probe():
                return True
        except Exception:  # noqa: BLE001 - 轮询期任何异常都当作「还没好」
            if proc is not None and not proc.alive():
                return False
        time.sleep(0.5)
    return False


def check_web_console(label: str, base: str) -> None:
    """验证「浏览器打开控制台」这条路径本身。

    历史教训：e2e 过去只探 `/api/v1/health`，所以前端资源缺失、Content-Type 错、
    静态文件回落到 HTML 这类故障可以一路全绿 —— 而用户看到的正是白屏。
    """

    def web(name: str, ok: bool, detail: str = "") -> bool:
        # 通过时不必刷屏，失败时一定要给出证据。
        return check(f"{label}: {name}", ok, "" if ok else detail)

    status, headers, html = http_raw(base + "/")
    ct = headers.get("content-type", "")
    web("控制台首页返回 HTML 200", status == 200 and "text/html" in ct,
        f"status={status} content-type={ct} body={html[:120]!r}")
    web("首页包含 SPA 挂载点 #app", 'id="app"' in html, html[:160])

    status, headers, js = http_raw(base + "/app.js")
    ct = headers.get("content-type", "")
    web("/app.js 可加载且 Content-Type 为 JavaScript",
        status == 200 and "javascript" in ct and len(js) > 1000,
        f"status={status} content-type={ct} len={len(js)}")
    web("app.js 确实调用控制台 API", "/api/v1/" in js, js[:160])

    status, headers, css = http_raw(base + "/app.css")
    ct = headers.get("content-type", "")
    web("/app.css 可加载且 Content-Type 为 CSS",
        status == 200 and "css" in ct and len(css) > 200,
        f"status={status} content-type={ct} len={len(css)}")

    status, _, deep = http_raw(base + "/tunnels")
    web("前端深链接回落到首页（SPA 路由可用）",
        status == 200 and 'id="app"' in deep, f"status={status}")

    status, headers, _ = http_raw(base + "/does-not-exist.js")
    web("缺失的静态资源返回 404（不用 HTML 冒充 JS）",
        status == 404, f"status={status} content-type={headers.get('content-type')}")

    status, headers, _ = http_raw(base + "/api/v1/definitely-not-here")
    web("未知 API 返回 JSON 404",
        status == 404 and "json" in headers.get("content-type", ""),
        f"status={status} content-type={headers.get('content-type')}")

    status, payload = http_json("GET", base + "/api/v1/health")
    assets = payload.get("console_assets") if isinstance(payload, dict) else None
    web("health 汇报内嵌前端资源数 > 0",
        status == 200 and isinstance(assets, int) and assets > 0,
        f"status={status} console_assets={assets}")


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


def check_private_tunnel(
    label: str, dist: Path, work: Path, base: str, token: str, client_id: str
) -> None:
    """私有隧道：访问端凭密钥在本机监听 → 节点中继 → 客户端本地服务。

    这条断言覆盖的是与「端口转发」本质不同的形态：**内网侧不暴露任何公网端口**，
    入口建在访问者自己那边。它同时验证三件事：
    1. 免鉴权的 `/api/v1/access/resolve` 能用密钥换到节点坐标；
    2. 访问端二进制真的能起本地入口（`rscross-client access` 子命令）；
    3. 数据经「本地 TCP → 访问端 → 节点中继 → Iroh → 客户端本地服务」走通。
    """
    # 1) 内网侧回显服务
    echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(16)
    echo.settimeout(1.0)
    echo_port = echo.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = echo.accept()
            except (socket.timeout, OSError):
                continue
            try:
                data = conn.recv(4096)
                if data:
                    conn.sendall(b"private:" + data)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()

    # 2) 建私有隧道（自动签发访问密钥）
    status, tunnel = http_json(
        "POST",
        f"{base}/api/v1/clients/{client_id}/tunnels",
        {
            "kind": "private",
            "name": "e2e-private-e2e",
            "proto": "tcp",
            "local_addr": f"127.0.0.1:{echo_port}",
        },
        token=token,
    )
    access_key = (tunnel or {}).get("access_key") or ""
    if not check(
        f"{label}: 可创建「私有隧道」并拿到访问密钥",
        status == 200 and access_key.startswith("rsv_"),
        f"status={status} {str(tunnel)[:140]}",
    ):
        stop.set()
        echo.close()
        return

    # 3) 免鉴权解析：凭密钥换节点坐标与路由键
    status, resolved = http_json(
        "POST", f"{base}/api/v1/access/resolve", {"access_key": access_key}
    )
    check(
        f"{label}: 访问端可凭访问密钥换取节点坐标",
        status == 200 and bool((resolved or {}).get("node_endpoint"))
        and bool((resolved or {}).get("tunnel_key")),
        f"status={status} {str(resolved)[:160]}",
    )
    check(
        f"{label}: 私有隧道建议走节点中继",
        (resolved or {}).get("mode") == "relay",
        str((resolved or {}).get("mode")),
    )

    # 注意：这里刻意不测「无效密钥」—— 那会计入下面的失败限流计数，
    # 让「第几次被锁」变成依赖前面步骤的脆弱断言。无效密钥统一放在限流段里测。

    # 4) 真的起一个访问端进程，通过它的本地入口访问内网服务
    access_dir = work / "access"
    access_dir.mkdir(parents=True, exist_ok=True)
    local_port = free_port()
    access = Proc(
        f"{label}/access",
        bin_path(dist, "rscross-client"),
        [
            "access",
            "--console",
            base,
            "--key",
            access_key,
            "--listen",
            f"127.0.0.1:{local_port}",
        ],
        access_dir / "access.log",
    )

    def via_access():
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=5) as sock:
                sock.sendall(b"ping")
                sock.settimeout(5)
                reply = sock.recv(64)
        except OSError:
            return None
        return reply if reply.startswith(b"private:") else None

    ok, reply = wait_until(
        f"{label}: 访问端本地入口可用",
        via_access,
        timeout=120,
        interval=1.0,
    )
    check(
        f"{label}: 本地 TCP → 访问端 → 节点中继 → Iroh → 客户端本地服务（端到端数据面）",
        ok,
        f"reply={reply!r}",
    )
    if not ok:
        print("      · 访问端日志（末尾 60 行）：", flush=True)
        print(access.tail(60), flush=True)

    # 握手失败必须是**明确的原因**，而不是「连接断开」。
    #
    # 本地实测（Windows 真实二进制）发现的缺陷：节点拒绝密钥时写完应答就返回，
    # 而 `accept()` 返回会关闭连接，尚未送达的应答被丢掉 —— 访问端只报
    # 「读取节点应答失败: connection lost」。用户抄错密钥时看到的是网络错误，
    # 完全指错方向。修复后拒绝分支会等对端读完再返回。
    #
    # 「首次握手就成功」时日志里本来也没有失败字样，所以这条断言不会因此变脆。
    check(
        f"{label}: 访问端握手失败时报的是明确原因而非连接断开",
        "读取节点应答失败" not in access.log(),
        access.tail(30),
    )

    code = access.stop()
    check(
        f"{label}: 访问端（access 子命令）收到退出信号后正常退出",
        code == 0 or not access.graceful_supported,
        f"退出码={code} 优雅信号可用={access.graceful_supported}",
    )
    stop.set()
    echo.close()

    # 5) 密钥只有 16 位十六进制，缩短它必须同时收紧猜测的代价。
    #
    # 这一组断言刻意放在**最后**：一旦触发锁定，同一来源 IP 的后续请求
    # 都会被 429（包括正确密钥），放前面会把后面的用例全带崩。
    #
    # 也从这里开始才第一次出现无效密钥 —— 上面刻意没有无效密钥的用例，
    # 否则「第几次被锁」会变成依赖前面步骤次数的脆弱断言。
    # 10 次探测里第 10 条是形状非法的 `rsv_ab`：它同样按 401 处理
    # （服务端只做精确匹配、不按长度过滤，所以历史的长密钥仍然可用）。
    probes = [f"rsv_{i:016x}" for i in range(9)] + ["rsv_ab"]
    codes = []
    for probe in probes:
        status, _ = http_json(
            "POST", f"{base}/api/v1/access/resolve", {"access_key": probe}
        )
        codes.append(status)
    check(
        f"{label}: 连续猜错 10 次访问密钥都是 401（含形状非法的一条）",
        codes == [401] * 10,
        f"codes={codes}",
    )

    status_bad, body_bad = http_json(
        "POST", f"{base}/api/v1/access/resolve", {"access_key": "rsv_0000000000000001"}
    )
    check_eq(f"{label}: 第 11 次起被限流（429）", 429, status_bad)

    # 被锁定时连**正确**的密钥也要挡住，否则攻击者可以用它当探针
    # 判断「这把锁有没有生效」。
    status_good, body_good = http_json(
        "POST", f"{base}/api/v1/access/resolve", {"access_key": access_key}
    )
    check_eq(f"{label}: 限流生效期间正确密钥同样被挡（429）", 429, status_good)

    # 更强的一条：锁定期间，正确密钥与错误密钥的响应必须**一模一样** ——
    # 只要有一丝差异，这个接口就又变回了「密钥是否存在」的探测器。
    #
    # 比较时把数字抹掉：「请 N 秒后再试」里的 N 会随请求时刻变化，
    # 跨秒边界就可能差 1；直接比原文会变成偶发失败（flaky 比不测更糟）。
    def masked(body):
        return re.sub(r"\d+", "N", json.dumps(body, ensure_ascii=False, sort_keys=True))

    check(
        f"{label}: 限流期间无法区分密钥是否存在（响应除秒数外逐字一致）",
        body_bad is not None
        and body_good is not None
        and masked(body_bad) == masked(body_good),
        f"good={masked(body_good)} bad={masked(body_bad)}",
    )

    # 429 说的是「试得太频繁」，不是「你没权限」，所以文案里不该带
    # 「鉴权错误: 」这种错误类型前缀 —— 那是内部 Error 的 Display 泄漏到了 API。
    message = (body_bad or {}).get("message") or ""
    check(
        f"{label}: 限流提示文案干净（无错误类型前缀，且说清了原因）",
        "鉴权错误" not in message and "已锁定" in message,
        f"message={message!r}",
    )


def check_port_forward(label: str, base: str, token: str, client_id: str) -> None:
    """端口转发：节点监听公网端口 → 经 Iroh 投递到客户端本地服务。

    覆盖的是节点侧**自建 ingress** 这条新链路：客户端不为这类隧道建 FerroTunnel
    反向隧道，只把「路由键 → 本地地址」登记进 targets；节点在公网端口上 accept 后
    主动向客户端开流。这是 FerroTunnel 给不了的能力（它的服务端只有控制面 + HTTP 入口），
    所以必须单独验证，否则很容易写成「配置能存、端口没开」。
    """
    # 1) 内网侧：一个带前缀的回显服务，用于确认数据真的走了整条链路
    echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(16)
    echo.settimeout(1.0)
    echo_port = echo.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = echo.accept()
            except (socket.timeout, OSError):
                continue
            try:
                data = conn.recv(4096)
                if data:
                    conn.sendall(b"port-forward:" + data)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()

    # 2) 指定公网端口（必须在控制台端口池内，且尽量避开自动分配区）
    public_port = free_port_in_pool()
    status, tunnel = http_json(
        "POST",
        f"{base}/api/v1/clients/{client_id}/tunnels",
        {
            "kind": "port",
            "name": "e2e-port-fwd",
            "proto": "tcp",
            "local_addr": f"127.0.0.1:{echo_port}",
            "remote_port": public_port,
        },
        token=token,
    )
    created = status == 200 and (tunnel or {}).get("remote_port") == public_port
    if not check(
        f"{label}: 可创建「端口转发」隧道并指定公网端口",
        created,
        f"status={status} {str(tunnel)[:140]}",
    ):
        stop.set()
        echo.close()
        return

    # 3) 等配置经心跳下发（默认 2 秒）并真的连一次
    def forwarded():
        try:
            with socket.create_connection(("127.0.0.1", public_port), timeout=5) as sock:
                sock.sendall(b"ping")
                sock.settimeout(5)
                reply = sock.recv(64)
        except OSError:
            return None
        return reply if reply.startswith(b"port-forward:") else None

    ok, reply = wait_until(
        f"{label}: 公网端口转发可用",
        forwarded,
        timeout=90,
        interval=1.0,
    )
    check(
        f"{label}: 公网端口 → 节点 ingress → Iroh → 客户端本地服务（端到端数据面）",
        ok,
        f"reply={reply!r}",
    )

    stop.set()
    echo.close()


def check_tunnel_kinds(label: str, base: str, token: str, client_id: str) -> None:
    """四类隧道的创建、字段组合、访问密钥与非法组合拦截。

    这一组断言的价值在于：分类不只是界面上的分组，它决定了「入口形态 + 必填字段」，
    所以 P2P 填 UDP、域名解析填 TCP、私有隧道填公网端口这些组合必须被挡在服务端，
    否则客户端会拿到一条自相矛盾的配置。
    """

    def create(body):
        return http_json("POST", f"{base}/api/v1/clients/{client_id}/tunnels", body, token=token)

    # --- 域名解析：HTTP 家族 + Host，不占公网端口
    status, domain = create({
        "kind": "domain",
        "name": "e2e-domain",
        "proto": "http",
        "local_addr": "127.0.0.1:8080",
        "host": "e2e-domain.local",
    })
    check(
        f"{label}: 可创建「域名解析」隧道",
        status == 200 and (domain or {}).get("kind") == "domain",
        f"status={status} {str(domain)[:140]}",
    )
    check(
        f"{label}: 域名解析按 Host 路由且不占公网端口",
        (domain or {}).get("host") == "e2e-domain.local" and not (domain or {}).get("remote_port"),
        str(domain)[:160],
    )

    # --- 端口转发：TCP + 自动分配端口
    status, port = create({
        "kind": "port",
        "name": "e2e-port",
        "proto": "tcp",
        "local_addr": "127.0.0.1:5432",
    })
    check(
        f"{label}: 可创建「端口转发」隧道并自动分配公网端口",
        status == 200 and isinstance((port or {}).get("remote_port"), int)
        and (port or {}).get("remote_port", 0) > 0,
        f"status={status} remote_port={(port or {}).get('remote_port')}",
    )

    # --- 私有隧道：签发访问密钥，不暴露公网端口
    status, priv = create({
        "kind": "private",
        "name": "e2e-private",
        "proto": "tcp",
        "local_addr": "127.0.0.1:3306",
    })
    key = (priv or {}).get("access_key") or ""
    # 精确断言长度：密钥是给人抄的，长度本身就是产品决策，
    # 用 `> 20` 这种宽松写法会让「哪天不小心又变长」静默通过。
    check(
        f"{label}: 私有隧道签发 20 位访问密钥（rsv_ + 16 位十六进制）",
        status == 200 and key.startswith("rsv_") and len(key) == 20,
        f"status={status} key={key[:12]} len={len(key)}",
    )
    check(
        f"{label}: 私有隧道不暴露公网入口",
        not (priv or {}).get("remote_port") and not (priv or {}).get("host"),
        str(priv)[:160],
    )

    # --- P2P 隧道：仅 TCP + 中继回退开关
    status, p2p = create({
        "kind": "p2p",
        "name": "e2e-p2p",
        "proto": "tcp",
        "local_addr": "127.0.0.1:6379",
        "allow_relay": False,
    })
    p2p_key = (p2p or {}).get("access_key") or ""
    check(
        f"{label}: 可创建「P2P 隧道」并关闭中继回退",
        status == 200 and (p2p or {}).get("allow_relay") is False and len(p2p_key) == 20,
        f"status={status} {str(p2p)[:140]}",
    )

    # --- 非法组合必须被服务端拦下
    status, _ = create({"kind": "p2p", "name": "bad-p2p", "proto": "udp", "local_addr": "127.0.0.1:1"})
    check_eq(f"{label}: P2P 隧道拒绝 UDP（仅支持 TCP）", 400, status)

    status, _ = create({"kind": "domain", "name": "bad-domain", "proto": "tcp", "local_addr": "127.0.0.1:1"})
    check_eq(f"{label}: 域名解析拒绝 TCP 协议", 400, status)

    status, _ = create({
        "kind": "private",
        "name": "bad-private",
        "proto": "tcp",
        "local_addr": "127.0.0.1:1",
        "remote_port": 25000,
    })
    check_eq(f"{label}: 私有隧道拒绝填公网端口（避免误解为暴露端口）", 400, status)

    status, _ = create({"kind": "nope", "name": "bad-kind", "proto": "tcp", "local_addr": "127.0.0.1:1"})
    check_eq(f"{label}: 未知分类被拒", 400, status)

    # --- 老调用方式（不带 kind）按协议推导，保持向后兼容
    status, legacy = create({
        "name": "e2e-legacy",
        "proto": "http",
        "local_addr": "127.0.0.1:8080",
        "host": "e2e-legacy.local",
    })
    check(
        f"{label}: 不带 kind 的老调用按协议推导为域名解析",
        status == 200 and (legacy or {}).get("kind") == "domain",
        f"status={status} kind={(legacy or {}).get('kind')}",
    )

    # --- 访问密钥轮换
    if (priv or {}).get("id"):
        status, rotated = http_json(
            "POST", f"{base}/api/v1/tunnels/{priv['id']}/access-key", None, token=token
        )
        new_key = (rotated or {}).get("access_key") or ""
        check(
            f"{label}: 可轮换访问密钥且新旧不同",
            status == 200 and new_key.startswith("rsv_") and len(new_key) == 20
            and new_key != key,
            f"status={status} len={len(new_key)}",
        )

    if (domain or {}).get("id"):
        status, _ = http_json(
            "POST", f"{base}/api/v1/tunnels/{domain['id']}/access-key", None, token=token
        )
        check_eq(f"{label}: 域名解析没有访问密钥，轮换被拒", 400, status)

    # --- 列表里必须带分类字段，前端靠它分 Tab
    status, all_tunnels = http_json("GET", f"{base}/api/v1/tunnels", token=token)
    kinds = {t.get("kind") for t in (all_tunnels or [])}
    check(
        f"{label}: 隧道列表按分类返回 kind 字段",
        status == 200 and {"domain", "port", "private", "p2p"} <= kinds,
        str(sorted(k for k in kinds if k)),
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
        bin_path(dist, "rscross-client"),
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
        bin_path(dist, "rscross-server"),
        ["--embedded", "--config", str(node_cfg), "--console-config", str(console_cfg)],
        work / "embedded" / "server.log",
    )
    procs.append(server)

    console_base = f"http://127.0.0.1:{console_port}"
    ready = wait_console_ready(console_base, server)
    check(f"{label}: 服务端进程仍在运行", server.alive(), f"退出码={server.returncode()}")
    if not check(f"{label}: 内嵌控制台可探活", ready, console_base):
        dump_all()
        for proc in procs:
            proc.stop()
        return

    # 探活通过后立刻复测 3 次：区分「服务端根本没起来」与「起来后闪退」
    flap = sum(1 for _ in range(3) if not health_ok(console_base))
    check(f"{label}: 控制台探活稳定（复测 3 次）", flap == 0, f"失败 {flap}/3")

    # 探活只证明 API 活着；这里证明「浏览器里能看见界面」。
    check_web_console(label, console_base)

    token = login(console_base, "e2e-password-123")
    if not check(f"{label}: 可登录内嵌控制台", bool(token), console_base):
        dump_all()
        for proc in procs:
            proc.stop()
        return

    def self_node_registered():
        status, nodes = http_json("GET", console_base + "/api/v1/nodes", token=token)
        if status == 200 and nodes and len(nodes) == 1 and nodes[0].get("name") == "local-node":
            return nodes
        return None

    ok, nodes = wait_until("服务端自动注册本机节点", self_node_registered, timeout=60, interval=0.5)
    check(
        f"{label}: 服务端启动后自动注册为本机节点",
        ok,
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

    # 隧道的四种分类（域名解析 / 端口转发 / 私有隧道 / P2P 隧道）
    status, clients_now = http_json("GET", console_base + "/api/v1/clients", token=token)
    if check(
        f"{label}: 可取到客户端用于隧道分类验证",
        status == 200 and bool(clients_now),
        str(clients_now)[:120],
    ):
        check_tunnel_kinds(label, console_base, token, clients_now[0]["id"])
        # 端口转发的完整链路（节点自建 ingress → Iroh → 客户端本地服务）
        check_port_forward(label, console_base, token, clients_now[0]["id"])
        # 私有隧道 + 访问端的完整链路（本地入口 → 节点中继 → Iroh → 客户端）
        check_private_tunnel(
            label,
            dist,
            work / "embedded",
            console_base,
            token,
            clients_now[0]["id"],
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
        # 退出码为 0 说明走的是程序自己的优雅关停路径。
        # 平台发不出优雅信号时（Windows 无控制台，退化为强制结束）不要求 0 ——
        # 但这一档要显式写出来，不能让「没优雅退出」静默通过。
        check(
            f"{label}: {proc.label} 收到退出信号后正常退出",
            code == 0 or not proc.graceful_supported,
            f"退出码={code} 优雅信号可用={proc.graceful_supported}",
        )


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
        bin_path(dist, "rscross-console"),
        ["--config", str(console_cfg)],
        root / "console.log",
    )
    procs.append(console)

    console_base = f"http://127.0.0.1:{console_port}"
    ready = wait_console_ready(console_base, console)
    check(f"{label}: 控制台进程仍在运行", console.alive(), f"退出码={console.returncode()}")
    if not check(f"{label}: 独立控制台可探活", ready, console_base):
        dump_all()
        for proc in procs:
            proc.stop()
        return

    flap = sum(1 for _ in range(3) if not health_ok(console_base))
    check(f"{label}: 控制台探活稳定（复测 3 次）", flap == 0, f"失败 {flap}/3")

    # 探活只证明 API 活着；这里证明「浏览器里能看见界面」。
    check_web_console(label, console_base)

    token = login(console_base, "e2e-password-456")
    if not check(f"{label}: 可登录独立控制台", bool(token), console_base):
        dump_all()
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
        dump_all()
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
        bin_path(dist, "rscross-server"),
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
        dump_all()
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
        # 退出码为 0 说明走的是程序自己的优雅关停路径。
        # 平台发不出优雅信号时（Windows 无控制台，退化为强制结束）不要求 0 ——
        # 但这一档要显式写出来，不能让「没优雅退出」静默通过。
        check(
            f"{label}: {proc.label} 收到退出信号后正常退出",
            code == 0 or not proc.graceful_supported,
            f"退出码={code} 优雅信号可用={proc.graceful_supported}",
        )


# --------------------------------------------------------------- main


def scenario_default_port(dist: Path, work: Path) -> None:
    """两种控制台的默认端口必须分开：独立 7700，内嵌 7800。

    「端口对不上号」是排障里最高频的一类误解，所以这里既检查生成的配置内容，
    也真的把独立控制台拉起来（不传 --bind）确认它落在 7700。
    """
    label = "默认端口"
    print("\n" + "-" * 72, flush=True)
    print(f"场景：{label} —— 独立中央控制台不传 --bind 时监听 7700", flush=True)
    print("-" * 72, flush=True)

    root = work / "default-port"
    root.mkdir(parents=True, exist_ok=True)
    console_cfg = root / "rscross-console.toml"

    # ① 配置不存在时由程序按「中央控制台」默认值生成
    proc = subprocess.run(
        [str(bin_path(dist, "rscross-console")), "--check", "--config", str(console_cfg)],
        capture_output=True, text=True, timeout=60,
    )
    check(
        f"{label}: 独立控制台 --check 通过",
        proc.returncode == 0,
        (proc.stdout + proc.stderr).strip()[-200:],
    )
    written = console_cfg.read_text(encoding="utf-8") if console_cfg.exists() else ""
    check(f"{label}: 生成的配置默认端口是 7700", "7700" in written, written[:200])
    check(f"{label}: 生成的配置里不含 7800（那是内嵌端口）", "7800" not in written, written[:200])
    check(
        f"{label}: --check 顺带报告了内嵌前端自检",
        "前端资源" in proc.stdout,
        proc.stdout.strip()[-160:],
    )

    # ② 真的拉起来：不传 --bind，应当监听 7700 且能提供页面
    if not port_is_free(7700):
        check(f"{label}: 7700 端口可用", False, "端口被占用，跳过真实监听断言")
        return

    console = Proc(
        f"{label}/console",
        bin_path(dist, "rscross-console"),
        ["--config", str(console_cfg)],
        root / "console.log",
    )
    base = "http://127.0.0.1:7700"
    ready = wait_console_ready(base, console)
    check(f"{label}: 默认端口 7700 上可探活", ready, base)
    if ready:
        check_web_console(label, base)
    console.stop()


def scenario_console_addr(dist: Path, work: Path) -> None:
    """`--console` 的四种写法，以及「新增自建节点」的五个配置项。

    分两块验证，因为它们是这轮改造的两条主线：

    ① 地址 scheme —— ws/wss 直连、http(s) 跟 307、txt:// 走 DNS。
       解析失败的提示是否可操作，和成功时能否连上同样重要：
       用户在这三种写法下踩的坑完全不同。
    ② 节点配置项 —— 服务端地址是否真的生效（客户端拿到的地址就是填的那个）。
    """
    label = "控制台地址"
    print("\n" + "-" * 72, flush=True)
    print(f"场景：{label} —— scheme 解析与自建节点配置项", flush=True)
    print("-" * 72, flush=True)

    root = work / "console-addr"
    root.mkdir(parents=True, exist_ok=True)
    client = bin_path(dist, "rscross-client")

    # ---- ① 非法 scheme 的提示要可操作 ----
    proc = subprocess.run(
        [str(client), "--console", "127.0.0.1:7700", "--help"],
        capture_output=True, text=True, timeout=30,
    )
    # --help 会先成功退出，所以这里直接看校验是否发生在解析前：用非法值跑真正的启动。
    proc = subprocess.run(
        [str(client), "--console", "127.0.0.1:7700"],
        capture_output=True, text=True, timeout=60,
    )
    out = (proc.stdout + proc.stderr).strip()
    check(
        f"{label}: 缺 scheme 时列出支持的写法",
        proc.returncode != 0 and all(x in out for x in ("ws", "wss", "http", "https", "txt")),
        out[-200:],
    )

    # ---- ② ws:// 直连：不存在的端口应报「连不上」而不是「地址非法」 ----
    dead = free_port()
    proc = subprocess.run(
        [str(client), "--console", f"ws://127.0.0.1:{dead}"],
        capture_output=True, text=True, timeout=60,
    )
    out = (proc.stdout + proc.stderr).strip()
    check(
        f"{label}: ws:// 端口不通时报连接失败且带出该地址",
        proc.returncode != 0 and str(dead) in out,
        out[-200:],
    )
    check(
        f"{label}: ws:// 不会被说成「scheme 不支持」",
        "写法无效" not in out and str(dead) in out,
        out[-200:],
    )

    # ---- ③ http:// 入口返回非 307 时应明确要求改用 ws:// ----
    http_port = free_port()
    probe_root = root / "probe"
    probe_root.mkdir(parents=True, exist_ok=True)
    (probe_root / "index.html").write_text("<h1>not a redirect</h1>", encoding="utf-8")
    httpd = start_static_server(probe_root, http_port)
    try:
        proc = subprocess.run(
            [str(client), "--console", f"http://127.0.0.1:{http_port}/"],
            capture_output=True, text=True, timeout=60,
        )
        out = (proc.stdout + proc.stderr).strip()
        check(
            f"{label}: http:// 入口不返回 307 时提示改用 ws://",
            proc.returncode != 0 and ("307" in out or "ws://" in out),
            out[-200:],
        )
    finally:
        httpd.shutdown()

    # ---- ④ txt:// 查不到 TXT 记录 ----
    proc = subprocess.run(
        [str(client), "--console", "txt://rscross-e2e-no-such-domain.invalid"],
        capture_output=True, text=True, timeout=60,
    )
    out = (proc.stdout + proc.stderr).strip()
    check(
        f"{label}: txt:// 解析失败时说明是 TXT 记录问题",
        proc.returncode != 0 and "TXT" in out,
        out[-200:],
    )

    # ---- ⑤ 自建节点配置项：接口 + 实际生效 ----
    scenario_node_extras(dist, root)


def start_static_server(directory: Path, port: int):
    """起一个只返回 200 的静态服务器（用于验证「不返回 307」这条分支）。"""
    import functools
    import http.server
    import threading

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.RequestHandlerClass.log_message = lambda *a, **k: None  # type: ignore[assignment]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def scenario_node_extras(dist: Path, root: Path) -> None:
    """「新增自建节点」的五个配置项必须真的落库并影响下发给客户端的地址。"""
    label = "自建节点配置"
    print("\n" + "-" * 72, flush=True)
    print(f"场景：{label} —— 介绍 / 服务端地址 / 传输协议 / 中继开关", flush=True)
    print("-" * 72, flush=True)

    console_cfg = root / "console.toml"
    # 首次启动据此创建管理员；留空的话控制台会随机生成密码，脚本无从登录。
    console_cfg.write_text(
        '[admin]\ninitial_password = "e2e-password-123"\n',
        encoding="utf-8",
    )
    port = free_port()
    console = Proc(
        f"{label}/console",
        bin_path(dist, "rscross-console"),
        ["--config", str(console_cfg), "--bind", f"127.0.0.1:{port}"],
        root / "console.log",
    )
    base = f"http://127.0.0.1:{port}"
    if not check(f"{label}: 控制台启动", wait_console_ready(base, console), base):
        console.stop()
        return

    # 根路径对客户端是发现入口（307），对浏览器是控制台页面 ——
    # 两条路都断言，否则很容易为了修一条把另一条弄坏。
    status, _ = raw_request("GET", base + "/", accept="text/html")
    check_eq(f"{label}: 浏览器访问根路径仍是控制台页面", 200, status)
    status, headers = raw_request("GET", base + "/", accept="*/*")
    check_eq(f"{label}: 客户端访问根路径得307（发现入口）", 307, status)
    check(
        f"{label}: 307 的 Location 指向控制面 WS 端点",
        headers.get("location") == "/api/v1/control/ws",
        f"location={headers.get('location')!r}",
    )

    token = login(base, "e2e-password-123")
    if not check(f"{label}: 可登录", bool(token), base):
        console.stop()
        return

    status, created = http_json(
        "POST", base + "/api/v1/nodes",
        {
            "name": "self-built-1",
            "description": "香港出口 · 20Mbps",
            "public_addr": "ws://203.0.113.9:7800",
            "transport": "wss",
            "allow_relay": False,
        },
        token=token,
    )
    if not check(f"{label}: 可创建带全部配置项的节点", status == 200,
                 f"status={status} body={created}"):
        console.stop()
        return

    node = created.get("node") or {}
    check_eq(f"{label}: 介绍已保存", "香港出口 · 20Mbps", node.get("description"))
    check_eq(f"{label}: 服务端地址已保存", "ws://203.0.113.9:7800", node.get("public_addr"))
    check_eq(f"{label}: 传输协议已保存", "wss", node.get("transport"))
    check_eq(f"{label}: P2P 中继开关已保存", False, bool(node.get("allow_relay")))

    # 默认值：传输协议 tcp、中继开启
    status, second = http_json(
        "POST", base + "/api/v1/nodes", {"name": "self-built-2"}, token=token,
    )
    n2 = (second or {}).get("node") or {}
    check_eq(f"{label}: 传输协议默认 tcp", "tcp", n2.get("transport"))
    check_eq(f"{label}: P2P 中继默认开启", True, bool(n2.get("allow_relay")))

    # 非法传输协议必须被拒，并列出可选值
    status, err = http_json(
        "POST", base + "/api/v1/nodes",
        {"name": "self-built-3", "transport": "sctp"}, token=token,
    )
    check(
        f"{label}: 非法传输协议被拒且列出可选值",
        status == 400 and "quic" in json.dumps(err, ensure_ascii=False),
        f"status={status} body={err}",
    )

    # udp 已从可选列表移除（NAT 后不可用，配上去只会得到「节点在线但隧道不通」）
    status, err = http_json(
        "POST", base + "/api/v1/nodes",
        {"name": "self-built-udp", "transport": "udp"}, token=token,
    )
    check(
        f"{label}: udp 不再是可选传输协议",
        status == 400 and "udp" in json.dumps(err, ensure_ascii=False).lower(),
        f"status={status} body={err}",
    )

    # 服务端地址必须是 ws:// 或 wss://
    for bad, why in [
        ("http://203.0.113.9:7800", "http 前缀"),
        ("203.0.113.9:7800", "缺 scheme"),
        ("ws://203.0.113.9:0", "端口为 0"),
        ("ws://203.0.113.9:70000", "端口越界"),
    ]:
        status, err = http_json(
            "POST", base + "/api/v1/nodes",
            {"name": "self-built-bad", "public_addr": bad}, token=token,
        )
        check(
            f"{label}: 服务端地址拒绝{why}",
            status == 400,
            f"status={status} body={err}",
        )

    # 服务端地址优先于对外主机下发 —— 这才是「客户端据此连接」的实际含义
    node_id = node.get("id")
    status, listed = http_json("GET", base + f"/api/v1/nodes/{node_id}", token=token)
    endpoint = (listed or {}).get("endpoint") or {}
    check_eq(
        f"{label}: 下发给客户端的服务端地址就是配置的那个",
        "ws://203.0.113.9:7800", endpoint.get("public_addr"),
    )
    # 关键边界：控制台地址绝不能被当成反向隧道地址下发 ——
    # 协议与端口都不同（7800 vs 7835），混用客户端必然连不上。
    check(
        f"{label}: 反向隧道地址不含控制台端口",
        "7800" not in (endpoint.get("tunnel_server") or ""),
        f"tunnel_server={endpoint.get('tunnel_server')!r}",
    )
    check_eq(f"{label}: 传输协议一并下发", "wss", endpoint.get("transport"))

    # 修改：清空服务端地址应回落到自动推导
    status, patched = http_json(
        "PATCH", base + f"/api/v1/nodes/{node_id}",
        {"public_addr": "", "allow_relay": True, "description": ""}, token=token,
    )
    check_eq(f"{label}: 可清空服务端地址", 200, status)
    check_eq(f"{label}: 清空后回到自动推导", None, (patched or {}).get("public_addr"))
    check_eq(f"{label}: 可改回中继开启", True, bool((patched or {}).get("allow_relay")))
    check_eq(f"{label}: 可清空介绍", None, (patched or {}).get("description"))

    console.stop()


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python3 tests/e2e/e2e.py <二进制目录>", file=sys.stderr)
        return 2

    dist = Path(sys.argv[1]).resolve()
    binaries = {
        "rscross-server": bin_path(dist, "rscross-server"),
        "rscross-client": bin_path(dist, "rscross-client"),
        "rscross-console": bin_path(dist, "rscross-console"),
    }
    for name, binary in binaries.items():
        if not binary.exists():
            print(f"找不到二进制: {binary}", file=sys.stderr)
            return 2

    work = Path(tempfile.mkdtemp(prefix="rscross-e2e-"))
    print(f"工作目录: {work}", flush=True)

    # 二进制自检
    #
    # 版本号必须与 Cargo.toml 一致：曾经出现过 crate 版本停在 0.1.0、
    # 而 tag 已经是 v0.1.1 的情况 —— 用户下载 v0.1.1 的包，`--version`
    # 却报 0.1.0，根本没法确认自己装的是哪个版本。
    manifest = Path(__file__).resolve().parents[2] / "Cargo.toml"
    manifest_version = None
    try:
        found = re.search(
            r'^version = "([^"]+)"', manifest.read_text(encoding="utf-8"), re.M
        )
        manifest_version = found.group(1) if found else None
    except OSError:
        pass

    for name, binary in binaries.items():
        proc = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=30)
        out = (proc.stdout or proc.stderr).strip()
        check(f"{name} 可执行", proc.returncode == 0, out)
        check(
            f"{name} 自报版本与 Cargo.toml 一致（{manifest_version}）",
            manifest_version is not None and manifest_version in out,
            f"Cargo.toml={manifest_version} --version={out}",
        )

    default_cfg = subprocess.run(
        [str(binaries["rscross-server"]), "--print-default-config"],
        capture_output=True, text=True, timeout=30,
    )
    check(
        "服务端可打印默认配置且包含 [node]",
        default_cfg.returncode == 0 and "[node]" in default_cfg.stdout,
        f"rc={default_cfg.returncode}",
    )

    # 默认端口：独立中央控制台 7700，内嵌控制台仍是 7800（刻意分开，见 README）
    console_default = subprocess.run(
        [str(binaries["rscross-console"]), "--print-default-config"],
        capture_output=True, text=True, timeout=30,
    )
    check(
        "独立控制台可打印默认配置",
        console_default.returncode == 0 and "[console]" in console_default.stdout,
        f"rc={console_default.returncode}",
    )
    bind = toml_value(console_default.stdout, "console", "bind")
    check("独立中央控制台默认端口是 7700", bind == "0.0.0.0:7700", f"bind={bind!r}")
    embedded_url = toml_value(default_cfg.stdout, "node", "console_url")
    check(
        "内嵌控制台默认地址仍是 7800",
        bool(embedded_url) and embedded_url.endswith(":7800"),
        f"console_url={embedded_url!r}",
    )

    try:
        scenario_embedded(dist, work)
        scenario_standalone(dist, work)
        scenario_default_port(dist, work)
        scenario_console_addr(dist, work)
    except Exception as err:  # noqa: BLE001 - e2e 必须给出可诊断的失败，而不是裸 traceback
        check("e2e 脚本执行未抛异常", False, f"{type(err).__name__}: {err}")
        import traceback
        traceback.print_exc()
    finally:
        stop_all()

    print("\n" + "=" * 72, flush=True)
    if FAILURES:
        print(f"失败 {len(FAILURES)}/{CHECKS} 项：", flush=True)
        for item in FAILURES:
            print("  - " + item, flush=True)
        dump_all()
        return 1
    print(f"全部通过：{CHECKS}/{CHECKS}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
