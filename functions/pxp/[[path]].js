/**
 * OpenP2P 管理面板 — EdgeOne Makers 反向代理处理器
 * 匹配 /pxp/* 路由并代理转发至 OpenP2P 官方控制台
 */

const DEFAULT_UPSTREAM = "https://console.openpxp.com";
const SESSION_COOKIE_NAME = "openp2p_session";
const DEFAULT_SECRET = "openp2p-edgeone-secret-key-32bytes-min";

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

function jsonRsp(data, status = 200) {
  const h = new Headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store, no-cache, must-revalidate");
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
  const subPath = pathname.slice(4); // 去除 /pxp 前缀

  const acc = (session.accounts || []).find((a) => a.user === session.activeUser);
  let token = acc ? acc.token : "";

  // Token 过期自动刷新 (如果有密码)
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
    const upstreamRsp = await fetch(targetUrl, {
      method,
      headers: fwdHeaders,
      body: ["GET", "HEAD"].includes(method) ? undefined : await request.arrayBuffer(),
      redirect: "follow",
    });

    const respHeaders = new Headers(upstreamRsp.headers);
    respHeaders.set("Cache-Control", "no-store");
    return new Response(upstreamRsp.body, {
      status: upstreamRsp.status,
      headers: respHeaders,
    });
  } catch (err) {
    return jsonRsp({ error: -2, detail: `Upstream error: ${err.message}` }, 502);
  }
}
