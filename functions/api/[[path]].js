/**
 * OpenP2P 管理面板 — EdgeOne Makers API 处理器
 * 匹配 /api/* 路由
 */

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const SESSION_COOKIE_NAME = "openp2p_session";
const SESSION_TTL = 30 * 24 * 3600; // 30天
const DEFAULT_SECRET = "openp2p-edgeone-secret-key-32bytes-min";

/* ---------------- 基础工具与加密 ---------------- */
function base64UrlEncode(strOrBuffer) {
  let bytes = typeof strOrBuffer === "string" ? new TextEncoder().encode(strOrBuffer) : new Uint8Array(strOrBuffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  let binary = atob(base64);
  let bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

async function getHmacKey(secret) {
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret || DEFAULT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signData(dataStr, secret) {
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(dataStr));
  return `${base64UrlEncode(dataStr)}.${base64UrlEncode(signature)}`;
}

async function verifyData(signedStr, secret) {
  if (!signedStr || !signedStr.includes(".")) return null;
  const [b64Data, b64Sig] = signedStr.split(".");
  try {
    const rawData = base64UrlDecode(b64Data);
    const key = await getHmacKey(secret);
    
    let sigBase64 = b64Sig.replace(/-/g, "+").replace(/_/g, "/");
    while (sigBase64.length % 4) sigBase64 += "=";
    let sigBin = atob(sigBase64);
    let sigBytes = new Uint8Array(sigBin.length);
    for (let i = 0; i < sigBin.length; i++) sigBytes[i] = sigBin.charCodeAt(i);

    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(rawData));
    return valid ? rawData : null;
  } catch {
    return null;
  }
}

function parseJwt(token) {
  try {
    const part = token.split(".")[1];
    return JSON.parse(base64UrlDecode(part));
  } catch {
    return {};
  }
}

function jwtExp(token) {
  const p = parseJwt(token);
  return Number(p.exp || 0);
}

function jwtUser(token) {
  const p = parseJwt(token);
  return p.user || "";
}

/* ---------------- 验证码生成 ---------------- */
function generateCaptchaSvg(code, theme = "dark") {
  const isLight = theme === "light";
  const bg = isLight ? "#e2ebe6" : "#16241f";
  const noise = isLight ? "#b8c6bf" : "#3a4a44";
  const colors = isLight
    ? ["#0d9e73", "#b07d1a", "#3d7fb8", "#8a5cb8"]
    : ["#35d9a4", "#e8b64c", "#7db4e8", "#c98ce8"];

  const W = 120, H = 44;
  let chars = "";
  for (let i = 0; i < code.length; i++) {
    const x = 21 + i * 26;
    const y = 31;
    const color = colors[i % colors.length];
    chars += `<text x="${x}" y="${y}" text-anchor="middle" font-family="Consolas,monospace" font-size="24" font-weight="bold" fill="${color}">${code[i]}</text>`;
  }

  const svgXml = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="44" viewBox="0 0 120 44">` +
    `<rect width="120" height="44" fill="${bg}" rx="6"/>` +
    `<line x1="10" y1="12" x2="110" y2="34" stroke="${noise}" stroke-width="1"/>` +
    `<line x1="10" y1="36" x2="110" y2="10" stroke="${noise}" stroke-width="1"/>` +
    `${chars}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svgXml);
}

/* ---------------- 会话管理 ---------------- */
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(";").forEach((part) => {
    const [k, v] = part.trim().split("=");
    if (k && v) cookies[k] = decodeURIComponent(v);
  });
  return cookies;
}

async function getSession(request, env) {
  const secret = (env && env.SESSION_SECRET) || DEFAULT_SECRET;
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const rawCookie = cookies[SESSION_COOKIE_NAME] || request.headers.get("X-Session-Id");
  if (!rawCookie) return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };

  const verified = await verifyData(rawCookie, secret);
  if (!verified) return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };

  try {
    const session = JSON.parse(verified);
    if (!session.upstream) session.upstream = (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM;
    return session;
  } catch {
    return { accounts: [], activeUser: "", upstream: (env && env.UPSTREAM_URL) || DEFAULT_UPSTREAM };
  }
}

async function createSessionCookie(sessionData, env) {
  const secret = (env && env.SESSION_SECRET) || DEFAULT_SECRET;
  const signed = await signData(JSON.stringify(sessionData), secret);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(signed)}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Lax; Secure`;
}

function jsonRsp(data, status = 200, headers = {}) {
  const h = new Headers(headers);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
  h.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers: h });
}

export async function onRequest(context) {
  const { request, env = {} } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  // 口令鉴权
  const panelKey = env.PANEL_KEY || "";
  if (panelKey) {
    const clientKey = request.headers.get("X-Panel-Key");
    if (clientKey !== panelKey) {
      return jsonRsp({ error: 401, detail: "本面板已启用访问口令，需要正确口令" }, 401);
    }
  }

  const session = await getSession(request, env);
  const upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

  // 1. 获取面板状态
  if (pathname === "/api/state" && method === "GET") {
    const pool = session.accounts || [];
    const user = session.activeUser || "";
    const acc = pool.find((a) => a.user === user);
    const token = acc ? acc.token : "";
    return jsonRsp({
      upstream,
      user,
      hasToken: Boolean(token),
      tokenExp: token ? jwtExp(token) : 0,
      accounts: pool.map((a) => ({
        user: a.user,
        hasToken: Boolean(a.token),
        tokenExp: jwtExp(a.token || ""),
        hasPassword: Boolean(a.password),
        active: a.user === user,
      })),
    });
  }

  // 2. 验证码接口 (支持 GET 与 POST)
  if (pathname === "/api/captcha" && (method === "GET" || method === "POST")) {
    const secret = env.SESSION_SECRET || DEFAULT_SECRET;
    const theme = url.searchParams.get("theme") || request.headers.get("X-Panel-Theme") || "dark";
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    const cid = await signData(JSON.stringify({ code, exp: Date.now() + 300000 }), secret);
    const svg = generateCaptchaSvg(code, theme);
    return jsonRsp({ captcha_id: cid, captchaId: cid, svg });
  }

  // 3. 登录接口
  if (pathname === "/api/login" && method === "POST") {
    const secret = env.SESSION_SECRET || DEFAULT_SECRET;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
    }

    // 验证码校验
    const cid = body.captchaId || body.captcha_id;
    const ccode = body.captcha || body.captcha_code;
    if (cid && ccode) {
      const verified = await verifyData(cid, secret);
      if (!verified) return jsonRsp({ error: -1, detail: "验证码已过期或无效" }, 400);
      try {
        const parsed = JSON.parse(verified);
        if (Date.now() > parsed.exp || parsed.code !== String(ccode).trim()) {
          return jsonRsp({ error: -1, detail: "验证码错误或已失效" }, 400);
        }
      } catch {
        return jsonRsp({ error: -1, detail: "验证码解析失败" }, 400);
      }
    }

    // Token 登录
    if (token) {
      const profRsp = await fetch(`${upstream}/api/v1/user/profile`, {
        method: "POST",
        headers: { Authorization: token, "Content-Type": "application/json" },
        body: "{}",
      });
      const profData = await profRsp.json();
      if (profData.error !== 0) {
        return jsonRsp({ error: -1, detail: "Token 无效或已失效" }, 401);
      }
      const loginUser = profData.user || jwtUser(token);
      const pool = session.accounts.filter((a) => a.user !== loginUser);
      pool.push({ user: loginUser, token, password: "" });
      session.accounts = pool;
      session.activeUser = loginUser;

      const cookie = await createSessionCookie(session, env);
      return jsonRsp({ error: 0, user: loginUser, token }, 200, { "Set-Cookie": cookie });
    }

    // 账号密码登录
    if (user && password) {
      const loginRsp = await fetch(`${upstream}/api/v1/user/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, password }),
      });
      const loginData = await loginRsp.json();
      if (loginData.error === 0 && loginData.token) {
        const loginUser = loginData.user || user;
        const pool = session.accounts.filter((a) => a.user !== loginUser);
        pool.push({ user: loginUser, token: loginData.token, password });
        session.accounts = pool;
        session.activeUser = loginUser;

        const cookie = await createSessionCookie(session, env);
        return jsonRsp({ error: 0, user: loginUser, token: loginData.token }, 200, { "Set-Cookie": cookie });
      }
      return jsonRsp({ error: loginData.error || -1, detail: loginData.detail || "用户名或密码错误" });
    }

    return jsonRsp({ error: -1, detail: "缺少凭据" }, 400);
  }

  // 4. 退出登录
  if (pathname === "/api/logout" && method === "POST") {
    const pool = (session.accounts || []).filter((a) => a.user !== session.activeUser);
    session.accounts = pool;
    session.activeUser = pool.length > 0 ? pool[0].user : "";
    const cookie = await createSessionCookie(session, env);
    return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
  }

  // 5. 切换账户
  if (pathname === "/api/accounts/switch" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const targetUser = body.user;
    const acc = (session.accounts || []).find((a) => a.user === targetUser);
    if (!acc) return jsonRsp({ error: -1, detail: "未找到该账户" }, 404);
    session.activeUser = targetUser;
    const cookie = await createSessionCookie(session, env);
    return jsonRsp({ error: 0, user: targetUser }, 200, { "Set-Cookie": cookie });
  }

  // 6. 切换上游官方域名
  if (pathname === "/api/upstream" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const newUp = (body.upstream || "").trim().replace(/\/+$/, "");
    if (newUp.startsWith("http://") || newUp.startsWith("https://")) {
      session.upstream = newUp;
      const cookie = await createSessionCookie(session, env);
      return jsonRsp({ error: 0, upstream: newUp }, 200, { "Set-Cookie": cookie });
    }
    return jsonRsp({ error: -1, detail: "地址必须以 http:// 或 https:// 开头" }, 400);
  }

  return jsonRsp({ error: -1, detail: "未知接口" }, 404);
}
