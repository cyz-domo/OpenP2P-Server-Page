/**
 * OpenP2P 管理面板 — Vercel API 路由处理器
 * 匹配 /api/* 所有的管理接口
 */

import {
  DEFAULT_UPSTREAM,
  DEFAULT_SECRET,
  getSession,
  createSessionCookie,
  signData,
  verifyData,
  validateUpstreamUrl,
  jwtExp,
  jwtUser,
  generateCaptchaSvg,
  jsonRsp,
  getEnv,
} from "../../lib/common.js";

export const config = {
  runtime: "edge",
};

export default async function handler(request) {
  const env = getEnv();
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

  const session = await getSession(request);
  const upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

  // 1. 面板状态
  if (pathname === "/api/state" && (method === "GET" || method === "HEAD")) {
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

  // 2. 验证码接口 (2分钟窗口 + 随机 Nonce)
  if (pathname === "/api/captcha" && (method === "GET" || method === "POST")) {
    const secret = env.SESSION_SECRET || DEFAULT_SECRET;
    const theme = url.searchParams.get("theme") || request.headers.get("X-Panel-Theme") || "dark";
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    const nonce = Math.random().toString(36).slice(2, 8);
    const cid = await signData(JSON.stringify({ code, nonce, exp: Date.now() + 120000 }), secret);
    const svg = generateCaptchaSvg(code, theme);
    return jsonRsp({ captcha_id: cid, captchaId: cid, svg });
  }

  // 3. 登录 (支持密码与 Token 登录)
  if ((pathname === "/api/login" || pathname === "/api/login-token") && method === "POST") {
    const secret = env.SESSION_SECRET || DEFAULT_SECRET;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonRsp({ error: -1, detail: "请求格式错误" }, 400);
    }

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

    const token = (body.token || "").trim();
    const user = (body.user || "").trim();
    const password = body.password || "";
    const customUp = (body.upstream || "").trim().replace(/\/+$/, "");
    if (customUp) {
      const upCheck = validateUpstreamUrl(customUp);
      if (!upCheck.valid) return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
      session.upstream = upCheck.url;
    }
    const activeUpstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

    if (token) {
      const profRsp = await fetch(`${activeUpstream}/api/v1/user/profile`, {
        method: "POST",
        headers: { Authorization: token, "Content-Type": "application/json" },
        body: "{}",
      });
      const profData = await profRsp.json().catch(() => ({ error: -1 }));
      if (profData.error !== 0) {
        return jsonRsp({ error: -1, detail: "Token 无效或已失效" }, 401);
      }
      const loginUser = profData.user || jwtUser(token);
      const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
      pool.push({ user: loginUser, token, password: "" });
      session.accounts = pool;
      session.activeUser = loginUser;

      const cookie = await createSessionCookie(session);
      return jsonRsp({ error: 0, user: loginUser, token }, 200, { "Set-Cookie": cookie });
    }

    if (user && password) {
      const loginRsp = await fetch(`${activeUpstream}/api/v1/user/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, password }),
      });
      const loginData = await loginRsp.json().catch(() => ({ error: -1 }));
      if (loginData.error === 0 && loginData.token) {
        const loginUser = loginData.user || user;
        const pool = (session.accounts || []).filter((a) => a.user !== loginUser);
        pool.push({ user: loginUser, token: loginData.token, password });
        session.accounts = pool;
        session.activeUser = loginUser;

        const cookie = await createSessionCookie(session);
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
    const cookie = await createSessionCookie(session);
    return jsonRsp({ ok: true }, 200, { "Set-Cookie": cookie });
  }

  // 5. 切换账户
  if (pathname === "/api/accounts/switch" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const targetUser = body.user;
    const acc = (session.accounts || []).find((a) => a.user === targetUser);
    if (!acc) return jsonRsp({ error: -1, detail: "未找到该账户" }, 404);
    session.activeUser = targetUser;
    const cookie = await createSessionCookie(session);
    return jsonRsp({ error: 0, user: targetUser }, 200, { "Set-Cookie": cookie });
  }

  // 6. 移除账户
  if (pathname === "/api/accounts/remove" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const targetUser = body.user;
    session.accounts = (session.accounts || []).filter((a) => a.user !== targetUser);
    if (session.activeUser === targetUser) {
      session.activeUser = session.accounts.length > 0 ? session.accounts[0].user : "";
    }
    const cookie = await createSessionCookie(session);
    return jsonRsp({ error: 0, ok: true }, 200, { "Set-Cookie": cookie });
  }

  // 7. 切换官方控制台地址
  if (pathname === "/api/upstream" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const newUp = (body.upstream || "").trim().replace(/\/+$/, "");
    const upCheck = validateUpstreamUrl(newUp);
    if (!upCheck.valid) {
      return jsonRsp({ error: -1, detail: upCheck.reason }, 400);
    }
    session.upstream = upCheck.url;
    const cookie = await createSessionCookie(session);
    return jsonRsp({ error: 0, upstream: upCheck.url }, 200, { "Set-Cookie": cookie });
  }

  return jsonRsp({ error: -1, detail: "未知接口" }, 404);
}
