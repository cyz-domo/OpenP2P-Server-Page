/**
 * OpenP2P 管理面板 — Vercel 反向代理处理器
 * 匹配 /pxp/* 路由并流式代理转发至 OpenP2P 官方控制台
 * 纯 ReadableStream 直传，支持虚拟网络长轮询与拓扑同步
 */

import {
  DEFAULT_UPSTREAM,
  DEFAULT_SECRET,
  getSession,
  isPrivateHost,
  jwtExp,
  applySecurityHeaders,
  jsonRsp,
  getEnv,
} from "../lib/common.js";

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
  let upstream = session.upstream || env.UPSTREAM_URL || DEFAULT_UPSTREAM;

  // SSRF 防护
  try {
    const upUrl = new URL(upstream);
    if (upUrl.protocol !== "https:" || isPrivateHost(upUrl.hostname)) {
      upstream = DEFAULT_UPSTREAM;
    }
  } catch {
    upstream = DEFAULT_UPSTREAM;
  }

  // 计算去除 /pxp 前缀后的真实上游子路径（完整保留末尾斜杠如 /api/v1/sdwans/）
  const subPath = pathname.startsWith("/pxp/") ? pathname.slice(4) : pathname;
  const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
  let token = acc ? acc.token : "";

  // 自动刷新 Token
  if (acc && acc.password && (!token || jwtExp(token) < Date.now() / 1000 + 60)) {
    try {
      const r = await fetch(`${upstream}/api/v1/user/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: acc.user, password: acc.password }),
      });
      const d = await r.json();
      if (d.error === 0 && d.token) {
        token = d.token;
        acc.token = token;
      }
    } catch {}
  }

  const targetUrl = `${upstream}${subPath}${url.search}`;
  const fwdHeaders = new Headers(request.headers);
  fwdHeaders.delete("host");
  fwdHeaders.delete("cookie");
  if (token) fwdHeaders.set("Authorization", token);

  try {
    // 纯流式直传 ReadableStream，支持长轮询与长连接
    const upstreamRsp = await fetch(targetUrl, {
      method,
      headers: fwdHeaders,
      body: ["GET", "HEAD"].includes(method) ? undefined : request.body,
      redirect: "follow",
    });

    const respHeaders = new Headers(upstreamRsp.headers);
    respHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate");
    applySecurityHeaders(respHeaders);

    return new Response(upstreamRsp.body, {
      status: upstreamRsp.status,
      headers: respHeaders,
    });
  } catch (err) {
    return jsonRsp({ error: -2, detail: `Upstream error: ${err.message}` }, 502);
  }
}
