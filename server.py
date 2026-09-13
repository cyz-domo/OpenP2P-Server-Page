#!/usr/bin/env python3
"""OpenP2P 管理面板服务器 — 仅依赖 Python 3 标准库。

职责：
1. 托管 ./public 下的静态前端
2. 把 /pxp/* 请求反向代理到 OpenP2P 官方控制台，自动附带 Authorization token
3. token 过期时用保存的账号密码自动重登（可选）

用法：
    python3 server.py --token <JWT> [--upstream https://console.openpxp.com] [--port 8377]
    python3 server.py --user goodnight --password 'xxx'   # 无 token 时自动登录
配置持久化在同目录 config.json。
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
CONFIG_FILE = BASE_DIR / "config.json"

DEFAULT_UPSTREAM = "https://console.openpxp.com"
API_PREFIX = "/pxp/"
PUSH_TIMEOUT = 40  # push rsp=1 时设备可能较慢
MAX_BODY = 1 << 20  # 请求体上限 1MB，防大包打爆内存
# 允许代理的路径前缀：只放行官方控制台 API 与下载，防把服务器当任意代理用
_PROXY_ALLOW = ("/api/",)

# ---------- 安全配置 ----------
# CSP 策略：限制脚本/样式来源，防止 XSS
_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

# ---------- 全局速率限制 ----------
RATE_LIMIT_WINDOW = 60     # 限制窗口 60 秒
RATE_LIMIT_MAX = 30        # 每窗口最多 30 次请求（登录等敏感接口更严格）
_rate_lock = threading.Lock()
_rate_limits: dict = {}     # ip -> [count, window_start]

# ---------- 登录防爆破 ----------
CAPTCHA_TTL = 300        # 验证码 5 分钟有效
CAPTCHA_LEN = 4
LOCK_THRESHOLD = 5       # 连续失败 5 次
LOCK_WINDOW = 900        # 锁定 15 分钟
_captcha_lock = threading.Lock()
_captchas: dict = {}     # captcha_id -> {"code": str, "exp": float, "used": bool}
_fail_lock = threading.Lock()
_failures: dict = {}     # ip -> [fail_count, first_fail_ts]

# 登录专用速率限制（更严格）
LOGIN_RATE_LIMIT = 10    # 每窗口最多 10 次登录尝试

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _check_rate_limit(ip: str, limit: int = RATE_LIMIT_MAX) -> bool:
    now = time.time()
    with _rate_lock:
        item = _rate_limits.get(ip)
        if not item or now - item[1] > RATE_LIMIT_WINDOW:
            _rate_limits[ip] = [1, now]
            return True
        if item[0] >= limit:
            return False
        item[0] += 1
        return True


def _sanitize_error(msg: str) -> str:
    msg = str(msg)[:200]
    msg = re.sub(r'[<>"\']', '', msg)
    return msg


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tighten_config_perm()


def tighten_config_perm() -> None:
    """收紧 config.json 权限（POSIX 生效；Windows 的 ACL 由用户目录继承保护）。"""
    import os
    import platform

    if platform.system() != "Windows":
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if ':' not in stored:
        return hmac.compare_digest(password, stored)
    salt, h = stored.split(':', 1)
    check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(check.hex(), h)


# ---------- 验证码与失败锁定 ----------
def _captcha_sweep() -> None:
    """惰性清理过期验证码（调用方需持锁）。"""
    now = time.time()
    for cid in [k for k, v in _captchas.items() if v["exp"] < now or v["used"]]:
        _captchas.pop(cid, None)


def new_captcha(theme: str = "dark") -> tuple[str, str]:
    """生成 4 位数字验证码，返回 (captcha_id, svg)。单次有效。"""
    code = "".join(secrets.choice("0123456789") for _ in range(CAPTCHA_LEN))
    cid = secrets.token_urlsafe(16)
    with _captcha_lock:
        _captcha_sweep()
        _captchas[cid] = {"code": code, "exp": time.time() + CAPTCHA_TTL, "used": False}
    return cid, captcha_svg(code, theme)


def captcha_svg(code: str, theme: str = "dark") -> str:
    """无第三方依赖的 SVG 验证码：随机旋转/位移/干扰线，噪声足够人读机难猜。配色跟随面板主题。"""
    import random

    if theme == "light":
        bg, noise = "#e2ebe6", "#b8c6bf"
        colors = ["#0d9e73", "#b07d1a", "#3d7fb8", "#8a5cb8"]
    else:
        bg, noise = "#16241f", "#3a4a44"
        colors = ["#35d9a4", "#e8b64c", "#7db4e8", "#c98ce8"]
    rnd = random.Random(secrets.token_bytes(16))
    W, H = 120, 44
    chars = []
    for i, ch in enumerate(code):
        x = 14 + i * 26 + rnd.randint(-3, 3)
        y = 30 + rnd.randint(-4, 4)
        rot = rnd.randint(-24, 24)
        color = rnd.choice(colors)
        chars.append(
            f'<text x="{x}" y="{y}" transform="rotate({rot} {x} {y})" '
            f'font-family="Consolas,monospace" font-size="26" font-weight="bold" '
            f'fill="{color}">{ch}</text>'
        )
    lines = []
    for _ in range(4):
        x1, y1, x2, y2 = rnd.randint(0, W), rnd.randint(0, H), rnd.randint(0, W), rnd.randint(0, H)
        lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{noise}" stroke-width="1"/>')
    dots = "".join(
        f'<circle cx="{rnd.randint(0, W)}" cy="{rnd.randint(0, H)}" r="1" fill="{noise}"/>'
        for _ in range(18)
    )
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
            f'<rect width="{W}" height="{H}" fill="{bg}" rx="6"/>{"".join(lines)}{dots}{"".join(chars)}</svg>')


def check_captcha(cid: str, answer: str) -> bool:
    """单次校验：无论对错都作废，防重放。"""
    if not cid or not answer:
        return False
    with _captcha_lock:
        item = _captchas.get(cid)
        if not item or item["used"] or item["exp"] < time.time():
            _captchas.pop(cid, None)
            return False
        item["used"] = True  # 一次性
        import hmac

        return hmac.compare_digest(item["code"], answer.strip())


def _fail_sweep(now: float) -> None:
    for ip in [k for k, v in _failures.items() if now - v[1] > LOCK_WINDOW]:
        _failures.pop(ip, None)


def is_locked(ip: str) -> bool:
    with _fail_lock:
        _fail_sweep(time.time())
        item = _failures.get(ip)
        return bool(item and item[0] >= LOCK_THRESHOLD and time.time() - item[1] < LOCK_WINDOW)


def record_fail(ip: str) -> None:
    with _fail_lock:
        now = time.time()
        _fail_sweep(now)
        item = _failures.get(ip)
        if item and now - item[1] < LOCK_WINDOW:
            item[0] += 1
            item[1] = now
        else:
            _failures[ip] = [1, now]


def clear_fails(ip: str) -> None:
    with _fail_lock:
        _failures.pop(ip, None)


def migrate_accounts(cfg: dict) -> None:
    """旧单账户 config（顶层 user/token/password）→ accounts 列表。幂等。"""
    accounts = cfg.get("accounts")
    if accounts:
        return
    user = cfg.get("user", "")
    if not user:
        cfg["accounts"] = []
        return
    cfg["accounts"] = [{
        "user": user,
        "token": cfg.get("token", ""),
        "password": cfg.get("password", ""),
    }]
    cfg["activeUser"] = user


class Upstream:
    """官方控制台客户端：多账户 token 池 + 自动重登 + 账户切换。

    cfg["accounts"] = [{"user": str, "token": str, "password": str(可选)}]
    cfg["activeUser"] = 当前生效账户；无 accounts 时回退到旧的单账户字段。
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.user = cfg.get("activeUser", "") or cfg.get("user", "")
        self.token = cfg.get("token", "")
        self.token_user = ""
        migrate_accounts(cfg)
        acc = self._active()
        if acc:
            self.user = acc["user"]
            self.token = acc.get("token", "")

    # ---- 账户池 ----
    def _pool(self) -> list:
        return self.cfg.setdefault("accounts", [])

    def _active(self) -> dict | None:
        for a in self._pool():
            if a["user"] == self.user:
                return a
        return None

    def list_accounts(self) -> list:
        """供前端展示的账户摘要（不含密码）。"""
        with self.lock:
            return [
                {
                    "user": a["user"],
                    "hasToken": bool(a.get("token")),
                    "tokenExp": self.jwt_exp(a.get("token", "")),
                    "hasPassword": bool(a.get("password")),
                    "active": a["user"] == self.user,
                }
                for a in self._pool()
            ]

    def switch_account(self, user: str) -> dict:
        with self.lock:
            acc = None
            for a in self._pool():
                if a["user"] == user:
                    acc = a
                    break
            if not acc:
                return {"error": -1, "detail": f"账户 {user} 不存在"}
            self.user = user
            self.token = acc.get("token", "")
            self.cfg["activeUser"] = user
            save_config(self.cfg)
        return {"error": 0, "user": user}

    def remove_account(self, user: str) -> dict:
        with self.lock:
            pool = self._pool()
            if len(pool) <= 1:
                return {"error": -1, "detail": "至少保留一个账户"}
            self.cfg["accounts"] = [a for a in pool if a["user"] != user]
            if self.user == user and self.cfg["accounts"]:
                return self.switch_account(self.cfg["accounts"][0]["user"])
            save_config(self.cfg)
        return {"error": 0}

    def _store(self, user: str, token: str, password: str | None = None):
        """写入/更新账户槽位并激活。"""
        with self.lock:
            pool = self._pool()
            acc = next((a for a in pool if a["user"] == user), None)
            if not acc:
                acc = {"user": user}
                pool.append(acc)
            acc["token"] = token
            if password is not None:
                acc["password"] = password
            self.user = user
            self.token = token
            self.token_user = self.jwt_user(token)
            self.cfg["activeUser"] = user
            # 兼容旧字段（单账户读取方），保持同步
            self.cfg["user"] = user
            self.cfg["token"] = token
            save_config(self.cfg)

    @staticmethod
    def jwt_user(token: str) -> str:
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
            return data.get("user", "")
        except Exception:
            return ""

    @staticmethod
    def jwt_exp(token: str) -> int:
        try:
            import base64

            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return int(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
        except Exception:
            return 0

    def login(self, user: str, password: str) -> dict:
        """登录官方控制台，成功后保存 token。"""
        body = json.dumps({"user": user, "password": password}).encode()
        req = urllib.request.Request(
            self.cfg["upstream"] + "/api/v1/user/login",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx) as rsp:
                data = json.loads(rsp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": e.code, "detail": _sanitize_error(e.read().decode(errors="replace"))[:300]}
        except Exception as e:
            return {"error": -1, "detail": _sanitize_error(str(e))}
        if data.get("error") != 0 or not data.get("token"):
            return data
        self._store(user, data["token"])
        return data

    def login_with_token(self, token: str) -> dict:
        """用现成 JWT 登录：先向官方验证 token 有效性，有效则入库启用。"""
        token = token.strip()
        if not token.count(".") == 2:
            return {"error": -1, "detail": "token 格式不正确（应为 JWT）"}
        # 用 profile 接口验证 token
        req = urllib.request.Request(
            self.cfg["upstream"] + "/api/v1/user/profile",
            data=b"{}",
            headers={"Authorization": token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx) as rsp:
                data = json.loads(rsp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": e.code, "detail": _sanitize_error("token 已失效或官方服务不可达")}
        except Exception as e:
            return {"error": -1, "detail": _sanitize_error(str(e))}
        if data.get("error") != 0:
            return {"error": -1, "detail": "token 无效（官方校验未通过）"}
        self._store(self.jwt_user(token), token)
        return {"error": 0, "token": token, "user": self.user}

    def ensure_token(self) -> str:
        with self.lock:
            token = self.token
        if token and self.jwt_exp(token) > time.time() + 60:
            return token
        # token 缺失/过期，尝试用当前账户保存的密码重登
        acc = self._active()
        if acc and acc.get("password"):
            self.login(acc["user"], acc["password"])
            with self.lock:
                return self.token
        return token

    def request(self, method: str, path: str, body: bytes | None, content_type: str):
        token = self.ensure_token()
        headers = {"Authorization": token}
        if body:
            headers["Content-Type"] = content_type or "application/json"
        req = urllib.request.Request(self.cfg["upstream"] + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=PUSH_TIMEOUT, context=_ssl_ctx) as rsp:
                return rsp.status, rsp.read(), dict(rsp.headers)
        except urllib.error.HTTPError as e:
            return e.code, _sanitize_error(e.read()).encode(), dict(e.headers)
        except Exception as e:
            return 502, json.dumps({"error": -2, "detail": f"upstream: {_sanitize_error(str(e))}"}).encode(), {}


_upstream: Upstream | None = None
# 可选访问口令：--auth <密钥> 启用。浏览器把密钥放在 X-Panel-Key 头（前端登录后存 localStorage）。
# 未配置时无鉴权——请配合 --host 127.0.0.1 或前置反代使用。
PANEL_KEY = ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OpenP2PPanel/1.0"

    def log_message(self, fmt, *args):  # 精简日志
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _authorized(self) -> bool:
        if not PANEL_KEY:
            return True
        # 静态首页放行（登录页需要先加载），其余一律验密钥
        if self.path == "/" or self.path.startswith("/index") or self.path.startswith("/app."):
            return True
        return self.headers.get("X-Panel-Key") == PANEL_KEY

    # ---------- 响应工具 ----------
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", _CSP_POLICY)
        if self.headers.get("X-Forwarded-Proto") == "https" or self.server.is_ssl:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    # ---------- 路由 ----------
    def do_GET(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self.path.startswith(API_PREFIX):
            self._proxy("GET")
        elif self.path.startswith("/api/"):
            self._panel_api("GET")
        else:
            self._static(self.path)

    def do_POST(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self.path.startswith(API_PREFIX):
            self._proxy("POST")
        elif self.path.startswith("/api/"):
            self._panel_api("POST")
        else:
            self._send(404, b"not found", "text/plain")

    def do_PUT(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self.path.startswith(API_PREFIX):
            self._proxy("PUT")
        else:
            self._send(404, b"not found", "text/plain")

    # ---------- 静态文件 ----------
    def _static(self, path: str):
        if path in ("/", ""):
            path = "/index.html"
        try:
            file = (PUBLIC_DIR / path.lstrip("/")).resolve()
            # 用 relative_to 做包含校验，防 ../ 与大小写/别名绕过
            file.relative_to(PUBLIC_DIR)
        except (ValueError, OSError):
            self._send(404, b"not found", "text/plain")
            return
        if not file.is_file():
            self._send(404, b"not found", "text/plain")
            return
        types = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }
        self._send(200, file.read_bytes(), types.get(file.suffix, "application/octet-stream"))

    # ---------- 面板自身 API ----------
    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _panel_api(self, method: str):
        global _upstream
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, b"payload too large", "text/plain")
            return
        raw = self.rfile.read(length) if length else b""
        if self.path == "/api/state":
            self._json({
                "upstream": _upstream.cfg["upstream"],
                "user": _upstream.user,
                "hasToken": bool(_upstream.token),
                "tokenExp": Upstream.jwt_exp(_upstream.token) if _upstream.token else 0,
                "accounts": _upstream.list_accounts(),
            })
        elif self.path == "/api/accounts/switch" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            self._json(_upstream.switch_account((data.get("user") or "").strip()))
        elif self.path == "/api/accounts/remove" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            self._json(_upstream.remove_account((data.get("user") or "").strip()))
        elif self.path == "/api/captcha" and method == "POST":
            ip = self._client_ip()
            if not _check_rate_limit(ip, 20):
                self._json({"error": 429, "detail": "请求过于频繁"})
                return
            theme = "light" if "light" in (self.headers.get("X-Panel-Theme") or "") else "dark"
            cid, svg = new_captcha(theme=theme)
            self._json({
                "captchaId": cid,
                "svg": "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode(),
            })
        elif self.path == "/api/upstream" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            new_up = (data.get("upstream") or "").strip().rstrip("/")
            if not new_up.startswith("http://") and not new_up.startswith("https://"):
                self._json({"error": -1, "detail": "官方控制台地址必须以 http:// 或 https:// 开头"})
                return
            _upstream.cfg["upstream"] = new_up
            save_config(_upstream.cfg)
            print(f"[panel] 官方代理上游地址已更新为: {new_up}")
            self._json({"error": 0, "upstream": new_up})
        elif self.path == "/api/login" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            ip = self._client_ip()
            if not _check_rate_limit(ip, LOGIN_RATE_LIMIT):
                self._json({"error": 429, "detail": "请求过于频繁，请稍后再试"})
                return
            if is_locked(ip):
                self._json({"error": 429, "detail": "失败次数过多，账号锁定 15 分钟，请稍后再试"})
                return
            if not check_captcha(data.get("captchaId") or "", data.get("captcha") or ""):
                record_fail(ip)
                left = LOCK_THRESHOLD - _failures.get(ip, [0, 0])[0]
                self._json({"error": -1, "detail": f"验证码错误（剩余 {max(left,0)} 次尝试机会）", "captchaFailed": True})
                return
            user = (data.get("user") or "").strip()
            password = data.get("password") or ""
            if not user or not password:
                self._json({"error": -1, "detail": "需要用户名和密码"})
                return
            if data.get("upstream"):
                new_up = data["upstream"].strip().rstrip("/")
                if new_up.startswith("http://") or new_up.startswith("https://"):
                    _upstream.cfg["upstream"] = new_up
                    save_config(_upstream.cfg)
            rsp = _upstream.login(user, password)
            if rsp.get("error") == 0:
                clear_fails(ip)
                if data.get("remember"):
                    _upstream._store(user, _upstream.token, password)
            else:
                record_fail(ip)
                left = LOCK_THRESHOLD - _failures.get(ip, [0, 0])[0]
                rsp["detail"] = _sanitize_error(rsp.get("detail") or "用户名或密码错误")[:120] + \
                    (f"（剩余 {max(left,0)} 次尝试）" if 0 < left <= LOCK_THRESHOLD else "")
            self._json({"error": rsp.get("error"), "detail": rsp.get("detail", "")})
        elif self.path == "/api/login-token" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            ip = self._client_ip()
            if not _check_rate_limit(ip, LOGIN_RATE_LIMIT):
                self._json({"error": 429, "detail": "请求过于频繁，请稍后再试"})
                return
            if is_locked(ip):
                self._json({"error": 429, "detail": "失败次数过多，账号锁定 15 分钟，请稍后再试"})
                return
            if not check_captcha(data.get("captchaId") or "", data.get("captcha") or ""):
                record_fail(ip)
                left = LOCK_THRESHOLD - _failures.get(ip, [0, 0])[0]
                self._json({"error": -1, "detail": f"验证码错误（剩余 {max(left,0)} 次尝试机会）", "captchaFailed": True})
                return
            if data.get("upstream"):
                new_up = data["upstream"].strip().rstrip("/")
                if new_up.startswith("http://") or new_up.startswith("https://"):
                    _upstream.cfg["upstream"] = new_up
                    save_config(_upstream.cfg)
            rsp = _upstream.login_with_token(data.get("token") or "")
            if rsp.get("error") == 0:
                clear_fails(ip)
            else:
                record_fail(ip)
                if "detail" in rsp:
                    rsp["detail"] = _sanitize_error(rsp["detail"])
            self._json(rsp)
        elif self.path == "/api/logout" and method == "POST":
            # 仅清除当前激活账户的 token（保留其他账户）
            acc = _upstream._active()
            if acc:
                acc["token"] = ""
            _upstream.token = ""
            _upstream.cfg["token"] = ""
            save_config(_upstream.cfg)
            self._json({"ok": True})
        else:
            self._json({"error": -1, "detail": "unknown panel api"}, 404)

    # ---------- 反向代理到官方控制台 ----------
    def _proxy(self, method: str):
        from urllib.parse import urlparse

        path = self.path[len(API_PREFIX) - 1:]  # 保留前导 /
        # 只放行官方 API 路径，阻断 /pxp/../ 与绝对 URI 形式的代理滥用
        if not urlparse(path).path.startswith(_PROXY_ALLOW):
            self._send(403, b"forbidden", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, b"payload too large", "text/plain")
            return
        raw = self.rfile.read(length) if length else None
        code, body, headers = _upstream.request(method, path, raw, self.headers.get("Content-Type"))
        ctype = headers.get("Content-Type", "application/json")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    global _upstream
    parser = argparse.ArgumentParser(description="OpenP2P 管理面板服务器")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机；对外提供请加 --auth")
    parser.add_argument("--port", type=int, default=8377)
    parser.add_argument("--auth", default=None, help="访问口令：设置后所有 API 需带 X-Panel-Key 头")
    parser.add_argument("--upstream", default=None, help="官方控制台地址")
    parser.add_argument("--token", default=None, help="已登录的 JWT（可选）")
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--no-save-password", action="store_true", help="不把密码写入 config.json")
    args = parser.parse_args()

    global PANEL_KEY
    PANEL_KEY = args.auth or ""

    cfg = load_config()
    cfg.setdefault("upstream", DEFAULT_UPSTREAM)
    if args.upstream:
        cfg["upstream"] = args.upstream
    if args.token:
        cfg["token"] = args.token
    if args.user:
        cfg["user"] = args.user
    # --password 归入（或预创建的）激活账户槽位
    if args.password and not args.no_save_password and cfg.get("user"):
        for a in cfg.setdefault("accounts", []):
            if a["user"] == cfg["user"]:
                a["password"] = args.password
                break
        else:
            cfg["accounts"].append({"user": cfg["user"], "token": "", "password": args.password})
    save_config(cfg)

    _upstream = Upstream(cfg)
    # 启动时校验激活账户 token，无效且该账户存有密码则自动重登
    token_ok = False
    if _upstream.token:
        code, body, _ = _upstream.request("POST", "/api/v1/user/profile", b"{}", "application/json")
        if code == 200:
            try:
                if json.loads(body.decode()).get("error") == 0:
                    token_ok = True
                    print(f"[panel] token 有效，用户: {_upstream.user or Upstream.jwt_user(_upstream.token)}")
            except Exception:
                pass
        if not token_ok:
            print("[panel] token 已失效")
    acc = _upstream._active() or {}
    if not token_ok and acc.get("password"):
        rsp = _upstream.login(acc["user"], acc["password"])
        if rsp.get("error") == 0:
            print(f"[panel] 已自动登录: {acc['user']}")
        else:
            print(f"[panel] 自动登录失败: {rsp}")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    warn = ""
    if args.host == "0.0.0.0" or args.host == "::":
        warn = "  ⚠ 对外监听" + ("（已启用口令）" if PANEL_KEY else "（未设口令，建议加 --auth）")
    print(f"[panel] OpenP2P 管理面板运行于 http://{args.host}:{args.port}  (上游: {cfg['upstream']}){warn}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[panel] 已停止")


if __name__ == "__main__":
    main()
