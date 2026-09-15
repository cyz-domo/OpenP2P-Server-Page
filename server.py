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
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        tighten_config_perm()
    except Exception:
        pass


def tighten_config_perm() -> None:
    """收紧 config.json 权限（POSIX 生效；Windows 的 ACL 由用户目录继承保护）。"""
    import os
    import platform

    if platform.system() != "Windows":
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass


# 密码在本地是"可还原"存储（面板要拿明文向官方重登），无法做单向哈希。
# 采用混淆存储（XOR+base64）：防直接 grep/肉眼读取，不是加密——拿到本机即可破解。
_OBF_KEY = "openp2p-panel-local"


def obf_encode(text: str) -> str:
    data = text.encode()
    key = _OBF_KEY.encode()
    return base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(data))).decode()


def obf_decode(text: str) -> str:
    try:
        data = base64.b64decode(text)
        key = _OBF_KEY.encode()
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode()
    except Exception:
        return text  # 兼容旧明文


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
    """无第三方依赖的 SVG 验证码：居中排列/防截断/干扰线，配色跟随面板主题。"""
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
        x = 21 + i * 26 + rnd.randint(-2, 2)
        y = 31 + rnd.randint(-2, 2)
        rot = rnd.randint(-16, 16)
        color = rnd.choice(colors)
        chars.append(
            f'<text x="{x}" y="{y}" text-anchor="middle" transform="rotate({rot} {x} {y})" '
            f'font-family="Consolas,monospace" font-size="24" font-weight="bold" '
            f'fill="{color}">{ch}</text>'
        )
    lines = []
    for _ in range(4):
        x1, y1, x2, y2 = rnd.randint(0, W), rnd.randint(0, H), rnd.randint(0, W), rnd.randint(0, H)
        lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{noise}" stroke-width="1"/>')
    dots = "".join(
        f'<circle cx="{rnd.randint(0, W)}" cy="{rnd.randint(0, H)}" r="1" fill="{noise}"/>'
        for _ in range(16)
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


# ---------- Session 管理与多用户隔离 ----------
SESSION_COOKIE_NAME = "openp2p_session"
SESSION_TTL = 7 * 86400  # 会话 7 天有效


class SessionManager:
    """服务端多用户 Session 管理器：
    - 管理每个浏览器的独立 Session，按 sessionId 隔离
    - 每个 Session 维护独立 accounts 列表与 activeUser
    - 7 天持久化到 config.json 中的 "sessions" 字段，服务重启会话不丢失
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.sessions: dict = {}
        self._load()

    def _load(self):
        with self.lock:
            raw = self.cfg.get("sessions", {})
            now = time.time()
            for sid, s in raw.items():
                if isinstance(s, dict) and s.get("exp", 0) > now:
                    self.sessions[sid] = s

    def _save(self):
        now = time.time()
        valid = {sid: s for sid, s in self.sessions.items() if s.get("exp", 0) > now}
        self.sessions = valid
        self.cfg["sessions"] = valid
        save_config(self.cfg)

    def get_session(self, sid: str) -> dict | None:
        if not sid:
            return None
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return None
            if s.get("exp", 0) < time.time():
                self.sessions.pop(sid, None)
                self._save()
                return None
            s["last_seen"] = time.time()
            return s

    def create_session(self, user: str, token: str, password: str | None = None) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            s = {
                "sid": sid,
                "created_at": now,
                "last_seen": now,
                "exp": now + SESSION_TTL,
                "activeUser": user,
                "accounts": [
                    {
                        "user": user,
                        "token": token,
                        "password": obf_encode(password) if password else "",
                    }
                ],
            }
            self.sessions[sid] = s
            self._save()
        return sid

    def delete_session(self, sid: str):
        if not sid:
            return
        with self.lock:
            if sid in self.sessions:
                self.sessions.pop(sid, None)
                self._save()

    def add_or_update_account(self, sid: str, user: str, token: str, password: str | None = None):
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return
            pool = s.setdefault("accounts", [])
            acc = next((a for a in pool if a["user"] == user), None)
            if not acc:
                acc = {"user": user}
                pool.append(acc)
            acc["token"] = token
            if password is not None:
                acc["password"] = obf_encode(password)
            s["activeUser"] = user
            s["exp"] = time.time() + SESSION_TTL
            self._save()

    def switch_account(self, sid: str, user: str) -> dict:
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return {"error": -1, "detail": "会话不存在或已过期"}
            pool = s.get("accounts", [])
            acc = next((a for a in pool if a["user"] == user), None)
            if not acc:
                return {"error": -1, "detail": f"账户 {user} 不存在"}
            s["activeUser"] = user
            s["exp"] = time.time() + SESSION_TTL
            self._save()
        return {"error": 0, "user": user}

    def remove_account(self, sid: str, user: str) -> dict:
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return {"error": -1, "detail": "会话不存在或已过期"}
            pool = s.get("accounts", [])
            if len(pool) <= 1:
                return {"error": -1, "detail": "至少保留一个账户"}
            s["accounts"] = [a for a in pool if a["user"] != user]
            if s.get("activeUser") == user and s["accounts"]:
                s["activeUser"] = s["accounts"][0]["user"]
            self._save()
        return {"error": 0}


class Upstream:
    """官方控制台客户端：认证校验与代理转发。"""

    def __init__(self, cfg: dict, session_mgr: SessionManager):
        self.cfg = cfg
        self.session_mgr = session_mgr
        self.lock = threading.Lock()

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
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return int(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
        except Exception:
            return 0

    def login(self, user: str, password: str) -> dict:
        """登录官方控制台并返回结果与 token。"""
        body = json.dumps({"user": user, "password": password}).encode()
        req = urllib.request.Request(
            self.cfg["upstream"] + "/api/v1/user/login",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx) as rsp:
                return json.loads(rsp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": e.code, "detail": _sanitize_error(e.read().decode(errors="replace"))[:300]}
        except Exception as e:
            return {"error": -1, "detail": _sanitize_error(str(e))}

    def login_with_token(self, token: str) -> dict:
        """用现成 JWT 登录：向官方验证 token 有效性。"""
        token = token.strip()
        if not token.count(".") == 2:
            return {"error": -1, "detail": "token 格式不正确（应为 JWT）"}
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
        user = self.jwt_user(token)
        return {"error": 0, "token": token, "user": user}

    def ensure_token(self, session: dict) -> str:
        """按 session 的激活账户获取有效 token；若过期且存有密码则自动重登。"""
        pool = session.get("accounts", [])
        user = session.get("activeUser", "")
        acc = next((a for a in pool if a["user"] == user), None)
        if not acc:
            return ""
        token = acc.get("token", "")
        if token and self.jwt_exp(token) > time.time() + 60:
            return token
        # token 缺失/过期，尝试用该账户保存的密码重登
        pwd_obf = acc.get("password", "")
        if pwd_obf:
            rsp = self.login(user, obf_decode(pwd_obf))
            if rsp.get("error") == 0 and rsp.get("token"):
                new_tok = rsp["token"]
                self.session_mgr.add_or_update_account(session["sid"], user, new_tok, obf_decode(pwd_obf))
                return new_tok
        return token

    def request_with_token(self, token: str, method: str, path: str, body: bytes | None, content_type: str):
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


_session_mgr: SessionManager | None = None
_upstream: Upstream | None = None
# 可选访问口令：--auth <密钥> 启用。浏览器把密钥放在 X-Panel-Key 头（前端登录后存 localStorage）。
# 未配置时无鉴权——请配合 --host 127.0.0.1 或前置反代使用。
PANEL_KEY = ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OpenP2PPanel/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _authorized(self) -> bool:
        if not PANEL_KEY:
            return True
        # 静态首页放行（登录页需要先加载），其余一律验密钥
        if self.path == "/" or self.path.startswith("/index") or self.path.startswith("/app."):
            return True
        return self.headers.get("X-Panel-Key") == PANEL_KEY

    def _get_session_id(self) -> str:
        # 1. 检查 Cookie 头
        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            import http.cookies

            c = http.cookies.SimpleCookie()
            try:
                c.load(cookie_header)
                if SESSION_COOKIE_NAME in c:
                    return c[SESSION_COOKIE_NAME].value
            except Exception:
                pass
        # 2. 检查 X-Session-Id 请求头
        sid = self.headers.get("X-Session-Id")
        if sid:
            return sid.strip()
        # 3. 检查 Authorization 头（Bearer <sid>）
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    # ---------- 响应工具 ----------
    def _send(
        self,
        code: int,
        body: bytes,
        ctype: str,
        cache_control: str | None = None,
        extra_headers: list[tuple[str, str]] | None = None,
    ):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cache_control is None:
            cache_control = "no-store, no-cache, must-revalidate"
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", _CSP_POLICY)
        if self.headers.get("X-Forwarded-Proto") == "https" or getattr(self.server, "is_ssl", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200, extra_headers: list[tuple[str, str]] | None = None):
        self._send(
            code,
            json.dumps(obj, ensure_ascii=False).encode(),
            "application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    # ---------- 路由 ----------
    def _is_proxy(self):
        return self.path.startswith("/pxp/") or self.path.startswith("/api/pxp/")

    def do_GET(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self._is_proxy():
            self._proxy("GET")
        elif self.path.startswith("/api/"):
            self._panel_api("GET")
        else:
            self._static(self.path)

    def do_POST(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self._is_proxy():
            self._proxy("POST")
        elif self.path.startswith("/api/"):
            self._panel_api("POST")
        else:
            self._send(404, b"not found", "text/plain")

    def do_PUT(self):
        if not self._authorized():
            self._json({"error": 401, "detail": "需要访问口令"}, 401)
            return
        if self._is_proxy():
            self._proxy("PUT")
        else:
            self._send(404, b"not found", "text/plain")

    # ---------- 静态文件 ----------
    _STATIC_CACHE = {
        ".js": "public, max-age=31536000, immutable",
        ".css": "public, max-age=31536000, immutable",
        ".svg": "public, max-age=86400",
        ".png": "public, max-age=86400",
        ".ico": "public, max-age=86400",
    }
    _NO_CACHE = "no-store, no-cache, must-revalidate"

    def _static(self, path: str):
        from urllib.parse import urlparse

        path = urlparse(path).path
        if path in ("/", ""):
            path = "/index.html"
        try:
            file = (PUBLIC_DIR / path.lstrip("/")).resolve()
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
        cache = self._STATIC_CACHE.get(file.suffix, self._NO_CACHE)
        self._send(200, file.read_bytes(), types.get(file.suffix, "application/octet-stream"), cache)

    # ---------- 面板自身 API ----------
    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _panel_api(self, method: str):
        global _upstream, _session_mgr
        from urllib.parse import urlparse

        req_path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, b"payload too large", "text/plain")
            return
        raw = self.rfile.read(length) if length else b""

        sid = self._get_session_id()
        session = _session_mgr.get_session(sid)

        if req_path == "/api/state":
            if session and session.get("activeUser"):
                pool = session.get("accounts", [])
                user = session.get("activeUser", "")
                acc = next((a for a in pool if a["user"] == user), None)
                token = acc.get("token", "") if acc else ""
                self._json({
                    "upstream": _upstream.cfg["upstream"],
                    "user": user,
                    "hasToken": bool(token),
                    "tokenExp": Upstream.jwt_exp(token) if token else 0,
                    "accounts": [
                        {
                            "user": a["user"],
                            "hasToken": bool(a.get("token")),
                            "tokenExp": Upstream.jwt_exp(a.get("token", "")),
                            "hasPassword": bool(a.get("password")),
                            "active": a["user"] == user,
                        }
                        for a in pool
                    ],
                })
            else:
                self._json({
                    "upstream": _upstream.cfg["upstream"],
                    "user": "",
                    "hasToken": False,
                    "tokenExp": 0,
                    "accounts": [],
                })
        elif req_path == "/api/accounts/switch" and method == "POST":
            if not session:
                self._json({"error": 401, "detail": "会话已失效，请重新登录"}, 401)
                return
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            self._json(_session_mgr.switch_account(sid, (data.get("user") or "").strip()))
        elif req_path == "/api/accounts/remove" and method == "POST":
            if not session:
                self._json({"error": 401, "detail": "会话已失效，请重新登录"}, 401)
                return
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return
            self._json(_session_mgr.remove_account(sid, (data.get("user") or "").strip()))
        elif req_path == "/api/captcha" and method == "POST":
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
        elif req_path == "/api/upstream" and method == "POST":
            try:
                data = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                self._json({"error": -1, "detail": "请求体不是合法 JSON"})
                return

            new_up = (data.get("upstream") or "").strip().rstrip("/")
            if not new_up.startswith("http://") and not new_up.startswith("https://"):
                self._json({"error": -1, "detail": "官方控制台地址必须以 http:// 或 https:// 开头"})
                return
            host = (urlparse(new_up).hostname or "").lower()
            if host not in ("console.openp2p.cn", "console.openpxp.com", "openp2p.cn", "openpxp.com"):
                self._json({"error": -1, "detail": f"仅支持官方域名（console.openp2p.cn / console.openpxp.com），拒绝: {host}"})
                return
            _upstream.cfg["upstream"] = new_up
            save_config(_upstream.cfg)
            print(f"[panel] 官方代理上游地址已更新为: {new_up}")
            self._json({"error": 0, "upstream": new_up})
        elif req_path == "/api/login" and method == "POST":
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
            if rsp.get("error") == 0 and rsp.get("token"):
                clear_fails(ip)
                tok = rsp["token"]
                if session:
                    _session_mgr.add_or_update_account(sid, user, tok, password if data.get("remember") else None)
                else:
                    sid = _session_mgr.create_session(user, tok, password if data.get("remember") else None)
                cookie = f"{SESSION_COOKIE_NAME}={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax"
                self._json(
                    {"error": 0, "sessionId": sid, "user": user, "token": tok},
                    extra_headers=[("Set-Cookie", cookie)],
                )
            else:
                record_fail(ip)
                left = LOCK_THRESHOLD - _failures.get(ip, [0, 0])[0]
                rsp["detail"] = _sanitize_error(rsp.get("detail") or "用户名或密码错误")[:120] + \
                    (f"（剩余 {max(left,0)} 次尝试）" if 0 < left <= LOCK_THRESHOLD else "")
                self._json({"error": rsp.get("error"), "detail": rsp.get("detail", "")})
        elif req_path == "/api/login-token" and method == "POST":
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
            if rsp.get("error") == 0 and rsp.get("token"):
                clear_fails(ip)
                tok = rsp["token"]
                user = rsp.get("user") or Upstream.jwt_user(tok)
                if session:
                    _session_mgr.add_or_update_account(sid, user, tok)
                else:
                    sid = _session_mgr.create_session(user, tok)
                cookie = f"{SESSION_COOKIE_NAME}={sid}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax"
                self._json(
                    {"error": 0, "sessionId": sid, "user": user, "token": tok},
                    extra_headers=[("Set-Cookie", cookie)],
                )
            else:
                record_fail(ip)
                if "detail" in rsp:
                    rsp["detail"] = _sanitize_error(rsp["detail"])
                self._json(rsp)
        elif req_path == "/api/logout" and method == "POST":
            if sid:
                _session_mgr.delete_session(sid)
            cookie = f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            self._json({"ok": True}, extra_headers=[("Set-Cookie", cookie)])
        else:
            self._json({"error": -1, "detail": "unknown panel api"}, 404)

    # ---------- 反向代理到官方控制台 ----------
    def _proxy(self, method: str):
        from urllib.parse import urlparse

        if self.path.startswith("/api/pxp/"):
            path = self.path[len("/api/pxp/") - 1:]
        elif self.path.startswith(API_PREFIX):
            path = self.path[len(API_PREFIX) - 1:]  # 保留前导 /
        else:
            path = self.path
        # 只放行官方 API 路径，阻断 /pxp/../ 与绝对 URI 形式的代理滥用
        if not urlparse(path).path.startswith(_PROXY_ALLOW):
            self._send(403, b"forbidden", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, b"payload too large", "text/plain")
            return
        raw = self.rfile.read(length) if length else None

        sid = self._get_session_id()
        session = _session_mgr.get_session(sid)
        if not session:
            self._json({"error": 401, "detail": "会话已失效，请重新登录"}, 401)
            return

        token = _upstream.ensure_token(session)
        if not token:
            self._json({"error": 401, "detail": "未获取到有效凭据，请重新登录"}, 401)
            return

        code, body, headers = _upstream.request_with_token(token, method, path, raw, self.headers.get("Content-Type"))
        ctype = headers.get("Content-Type", "application/json")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    global _upstream, _session_mgr
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
    save_config(cfg)

    _session_mgr = SessionManager(cfg)
    _upstream = Upstream(cfg, _session_mgr)

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
