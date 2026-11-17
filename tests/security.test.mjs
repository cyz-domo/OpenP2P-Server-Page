import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  isPrivateHost,
  validateUpstreamUrl,
  decodeCbor,
  derToRawEcdsa,
  verifyRegistration,
  verifyAssertion,
  createChallengeToken,
  verifyChallengeToken,
  getSession,
  createSessionCookie,
  rotateSessionId,
  destroySession,
  createCaptcha,
  verifyCaptcha,
  isAllowedOrigin,
  getSessionSecret,
} from "../api/index.js";

const textEnc = new TextEncoder();
const b64u = (v) => Buffer.from(v instanceof Uint8Array ? v : new Uint8Array(v)).toString("base64url");
const b64uText = (s) => Buffer.from(String(s), "utf8").toString("base64url");

function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function cborHeader(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
  if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
  return Uint8Array.of(
    (major << 5) | 26,
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  );
}

function cborEncode(v) {
  if (v instanceof Uint8Array) return concat([cborHeader(2, v.length), v]);
  if (typeof v === "string") {
    const b = textEnc.encode(v);
    return concat([cborHeader(3, b.length), b]);
  }
  if (typeof v === "number" && Number.isInteger(v)) {
    return v >= 0 ? cborHeader(0, v) : cborHeader(1, -1 - v);
  }
  if (v === null) return Uint8Array.of(0xf6);
  if (v === true) return Uint8Array.of(0xf5);
  if (v === false) return Uint8Array.of(0xf4);
  if (Array.isArray(v)) {
    return concat([cborHeader(4, v.length), ...v.map(cborEncode)]);
  }
  if (v instanceof Map) {
    const chunks = [cborHeader(5, v.size)];
    for (const [k, val] of v) chunks.push(cborEncode(k), cborEncode(val));
    return concat(chunks);
  }
  throw new Error("unsupported CBOR test value");
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

async function buildAuthData({ rpId, flags, signCount, credentialId, coseKey }) {
  const rpHash = await sha256(textEnc.encode(rpId));
  const parts = [rpHash, Uint8Array.of(flags), Uint8Array.of((signCount >>> 24) & 0xff, (signCount >>> 16) & 0xff, (signCount >>> 8) & 0xff, signCount & 0xff)];
  if (flags & 0x40) {
    parts.push(new Uint8Array(16));
    parts.push(Uint8Array.of((credentialId.length >> 8) & 0xff, credentialId.length & 0xff));
    parts.push(credentialId);
    parts.push(cborEncode(coseKey));
  }
  return concat(parts);
}

function rawEcdsaToDer(raw) {
  const r = raw.slice(0, 32);
  const s = raw.slice(32);
  const normalized = (v) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let out = v.slice(i);
    if (out[0] & 0x80) out = concat([Uint8Array.of(0), out]);
    return out;
  };
  const R = normalized(r);
  const S = normalized(s);
  const body = concat([Uint8Array.of(0x02, R.length), R, Uint8Array.of(0x02, S.length), S]);
  return concat([Uint8Array.of(0x30, body.length), body]);
}

async function makeClientData(type, challenge, origin) {
  return textEnc.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

async function makeEs256Fixture() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const coseKey = new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
    [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
  ]);
  return { pair, jwk, coseKey };
}

async function makeRsaFixture() {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const coseKey = new Map([
    [1, 3],
    [3, -257],
    [-1, new Uint8Array(Buffer.from(jwk.n, "base64url"))],
    [-2, new Uint8Array(Buffer.from(jwk.e, "base64url"))],
  ]);
  return { pair, jwk, coseKey };
}

const kvStore = new Map();
const kvSets = new Map();
const kvCounters = new Map();

function kvCommandMock(args) {
  const cmd = String(args[0]).toUpperCase();
  let result = null;
  if (cmd === "SET") {
    const [, key, value, ...rest] = args;
    if (rest.includes("NX") && kvStore.has(key)) {
      result = null;
    } else {
      kvStore.set(key, value);
      result = "OK";
    }
  } else if (cmd === "GET") {
    result = kvStore.get(args[1]) ?? null;
  } else if (cmd === "DEL") {
    result = kvStore.delete(args[1]) ? 1 : 0;
  } else if (cmd === "SADD") {
    if (!kvSets.has(args[1])) kvSets.set(args[1], new Set());
    kvSets.get(args[1]).add(args[2]);
    result = 1;
  } else if (cmd === "SREM") {
    kvSets.get(args[1])?.delete(args[2]);
    result = 1;
  } else if (cmd === "SMEMBERS") {
    result = [...(kvSets.get(args[1]) || [])];
  } else if (cmd === "INCR") {
    const next = (kvCounters.get(args[1]) || 0) + 1;
    kvCounters.set(args[1], next);
    result = next;
  } else if (cmd === "EXPIRE") {
    result = 1;
  }
  return result;
}

const ORIGINAL_FETCH = globalThis.fetch;
const ENV_KEYS = [
  "SESSION_SECRET",
  "KV_REST_API_URL",
  "KV_REST_API_TOKEN",
  "VERCEL",
  "VERCEL_ENV",
  "NODE_ENV",
  "APP_ORIGIN",
  "RP_ID",
  "ALLOW_CUSTOM_UPSTREAM",
  "PASSKEY_REQUIRE_UV",
];
let savedEnv = {};

beforeEach(() => {
  savedEnv = {};
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];

  process.env.SESSION_SECRET = "test-secret-0123456789abcdef0123456789";
  process.env.KV_REST_API_URL = "https://kv.test";
  process.env.KV_REST_API_TOKEN = "test-token";
  delete process.env.VERCEL;
  delete process.env.VERCEL_ENV;
  process.env.NODE_ENV = "test";
  delete process.env.APP_ORIGIN;
  delete process.env.RP_ID;
  process.env.ALLOW_CUSTOM_UPSTREAM = "false";
  process.env.PASSKEY_REQUIRE_UV = "false";

  kvStore.clear();
  kvSets.clear();
  kvCounters.clear();
  globalThis.fetch = async (_url, init) => {
    const args = JSON.parse(init.body);
    const result = kvCommandMock(args);
    return new Response(JSON.stringify({ result }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
});

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

test("private host filtering covers loopback, private ranges and metadata", () => {
  for (const host of [
    "localhost",
    "foo.localhost",
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "metadata.google.internal",
    "instance-data",
  ]) {
    assert.equal(isPrivateHost(host), true, host);
  }
  assert.equal(isPrivateHost("console.openpxp.com"), false);
  assert.equal(isPrivateHost("2606:4700:4700::1111"), false);
});

test("upstream allowlist rejects custom hosts by default and blocks private ranges", () => {
  assert.equal(validateUpstreamUrl("https://console.openpxp.com", {}).valid, true);
  assert.equal(validateUpstreamUrl("https://console.openp2p.cn/", {}).valid, true);

  const custom = validateUpstreamUrl("https://console.example.com", {});
  assert.equal(custom.valid, false);
  assert.match(custom.reason, /ALLOW_CUSTOM_UPSTREAM/);

  assert.equal(validateUpstreamUrl("https://console.example.com", { ALLOW_CUSTOM_UPSTREAM: "true" }).valid, true);
  assert.equal(validateUpstreamUrl("https://127.0.0.1", { ALLOW_CUSTOM_UPSTREAM: "true" }).valid, false);
  assert.equal(validateUpstreamUrl("https://console.openpxp.com/api", {}).valid, false);
  assert.equal(validateUpstreamUrl("http://console.openpxp.com", {}).valid, false);
  assert.equal(validateUpstreamUrl("https://user:pass@console.openpxp.com", {}).valid, false);
});

test("CBOR decoder parses attestation maps and COSE keys", () => {
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Uint8Array.of(1, 2)], [-3, Uint8Array.of(3, 4)]]);
  const att = new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", Uint8Array.of(9, 8, 7)]]);
  const [decoded] = decodeCbor(cborEncode(att));
  assert.equal(decoded.get("fmt"), "none");
  assert.deepEqual([...decoded.get("authData")], [9, 8, 7]);
  const [decodedCose] = decodeCbor(cborEncode(cose));
  assert.equal(decodedCose.get(1), 2);
  assert.equal(decodedCose.get(-1), 1);
  assert.deepEqual([...decodedCose.get(-2)], [1, 2]);
});

test("DER ECDSA signatures are converted to IEEE P1363", async () => {
  const { pair } = await makeEs256Fixture();
  const msg = textEnc.encode("signature format test");
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, msg));
  const der = rawEcdsaToDer(raw);
  const converted = derToRawEcdsa(der, 32);
  assert.equal(converted.length, 64);
  assert.deepEqual([...converted], [...raw]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, converted, msg);
  assert.equal(ok, true);
});

test("ES256 registration and assertion verify, with counter replay rejection", async () => {
  const { pair, jwk, coseKey } = await makeEs256Fixture();
  const rpId = "panel.example.com";
  const origin = "https://panel.example.com";
  const challenge = "test-challenge-es256";
  const credentialId = crypto.getRandomValues(new Uint8Array(32));

  const regAuthData = await buildAuthData({
    rpId,
    flags: 0x41,
    signCount: 0,
    credentialId,
    coseKey,
  });
  const attestationObject = cborEncode(
    new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", regAuthData]])
  );
  const regClientData = await makeClientData("webauthn.create", challenge, origin);
  const registration = await verifyRegistration({
    attestationObject: b64u(attestationObject),
    clientDataJSON: b64u(regClientData),
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRpId: rpId,
    credentialId: b64u(credentialId),
  });
  assert.equal(registration.alg, "ES256");
  assert.equal(registration.credentialId, b64u(credentialId));

  const authData = await buildAuthData({ rpId, flags: 0x05, signCount: 7 });
  const clientData = await makeClientData("webauthn.get", challenge, origin);
  const signed = concat([authData, await sha256(clientData)]);
  const rawSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed));
  const signature = rawEcdsaToDer(rawSig);
  const publicKeyJwk = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };

  const assertion = await verifyAssertion({
    authenticatorData: b64u(authData),
    clientDataJSON: b64u(clientData),
    signature: b64u(signature),
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRpId: rpId,
    publicKeyJwk,
    alg: "ES256",
    storedSignCount: 6,
    requireUV: true,
  });
  assert.equal(assertion.signCount, 7);

  await assert.rejects(
    () =>
      verifyAssertion({
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(clientData),
        signature: b64u(signature),
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        publicKeyJwk,
        alg: "ES256",
        storedSignCount: 7,
        requireUV: true,
      }),
    /计数器/
  );

  await assert.rejects(
    () =>
      verifyAssertion({
        authenticatorData: b64u(authData),
        clientDataJSON: b64uText(JSON.stringify({ type: "webauthn.get", challenge: "other", origin, crossOrigin: false })),
        signature: b64u(signature),
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        publicKeyJwk,
        alg: "ES256",
        storedSignCount: 0,
        requireUV: true,
      }),
    /挑战不匹配/
  );

  const tampered = Uint8Array.from(signature);
  tampered[tampered.length - 1] ^= 0xff;
  await assert.rejects(
    () =>
      verifyAssertion({
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(clientData),
        signature: b64u(tampered),
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        publicKeyJwk,
        alg: "ES256",
        storedSignCount: 0,
        requireUV: true,
      }),
    /签名/
  );
});

test("RS256 registration and assertion verify", async () => {
  const { pair, jwk, coseKey } = await makeRsaFixture();
  const rpId = "panel.example.com";
  const origin = "https://panel.example.com";
  const challenge = "test-challenge-rs256";
  const credentialId = crypto.getRandomValues(new Uint8Array(32));

  const regAuthData = await buildAuthData({
    rpId,
    flags: 0x41,
    signCount: 0,
    credentialId,
    coseKey,
  });
  const attestationObject = cborEncode(
    new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", regAuthData]])
  );
  const registration = await verifyRegistration({
    attestationObject: b64u(attestationObject),
    clientDataJSON: b64u(await makeClientData("webauthn.create", challenge, origin)),
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRpId: rpId,
    credentialId: b64u(credentialId),
  });
  assert.equal(registration.alg, "RS256");

  const authData = await buildAuthData({ rpId, flags: 0x01, signCount: 2 });
  const clientData = await makeClientData("webauthn.get", challenge, origin);
  const signed = concat([authData, await sha256(clientData)]);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, pair.privateKey, signed)
  );
  const assertion = await verifyAssertion({
    authenticatorData: b64u(authData),
    clientDataJSON: b64u(clientData),
    signature: b64u(signature),
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRpId: rpId,
    publicKeyJwk: { kty: "RSA", n: jwk.n, e: jwk.e },
    alg: "RS256",
    storedSignCount: 0,
    requireUV: false,
  });
  assert.equal(assertion.signCount, 2);
});

test("challenge token is bound to type/origin/rpId and can only be used once", async () => {
  const request = new Request("https://panel.example.com/api/passkey/challenge");
  const challenge = await createChallengeToken(process.env, request, "get");
  assert.equal(challenge.rpId, "panel.example.com");
  assert.ok(challenge.challengeToken);

  const payload = await verifyChallengeToken(process.env, request, challenge.challengeToken, "get");
  assert.equal(payload.challenge, challenge.challenge);

  await assert.rejects(
    () => verifyChallengeToken(process.env, request, challenge.challengeToken, "get"),
    /已使用/
  );

  const createChallenge = await createChallengeToken(process.env, request, "create");
  await assert.rejects(
    () => verifyChallengeToken(process.env, request, createChallenge.challengeToken, "get"),
    /类型不匹配/
  );

  const otherOriginRequest = new Request("https://evil.example.com/api/passkey/challenge");
  const other = await createChallengeToken(process.env, otherOriginRequest, "get");
  await assert.rejects(
    () => verifyChallengeToken(process.env, request, other.challengeToken, "get"),
    /来源已变化|RP ID/
  );
});

test("server-side sessions can be revoked", async () => {
  const cookie = await createSessionCookie({
    accounts: [{ user: "alice", token: "token" }],
    activeUser: "alice",
    upstream: "https://console.openpxp.com",
  });
  assert.match(cookie, /openp2p_session=s\./);

  const request = new Request("https://panel.example.com/api/state", {
    headers: { cookie },
  });
  const session = await getSession(request);
  assert.equal(session.activeUser, "alice");
  assert.equal(session.accounts[0].user, "alice");
  assert.ok(session.__sid);

  await destroySession(session);
  const afterLogout = await getSession(request);
  assert.equal(afterLogout.activeUser, "");
  assert.equal(afterLogout.accounts.length, 0);
});

test("session id rotation invalidates the previous cookie", async () => {
  const cookie = await createSessionCookie({
    accounts: [{ user: "bob", token: "token" }],
    activeUser: "bob",
    upstream: "https://console.openpxp.com",
  });
  const request = new Request("https://panel.example.com/api/state", { headers: { cookie } });
  const session = await getSession(request);
  await rotateSessionId(session);
  const afterRotation = await getSession(request);
  assert.equal(afterRotation.activeUser, "");
});

test("captcha is six digits, ip-bound and single use", async () => {
  const request = new Request("https://panel.example.com/api/captcha", {
    headers: { "x-real-ip": "203.0.113.8" },
  });
  const captcha = await createCaptcha(process.env, request, "dark");
  const svg = decodeURIComponent(captcha.svg.split(",")[1]);
  const code = [...svg.matchAll(/>(\d)<\/text>/g)].map((m) => m[1]).join("");
  assert.equal(code.length, 6);

  await verifyCaptcha(process.env, request, captcha.captchaId, code);
  await assert.rejects(
    () => verifyCaptcha(process.env, request, captcha.captchaId, code),
    /已使用/
  );

  const second = await createCaptcha(process.env, request, "dark");
  const svg2 = decodeURIComponent(second.svg.split(",")[1]);
  const code2 = [...svg2.matchAll(/>(\d)<\/text>/g)].map((m) => m[1]).join("");
  const otherIp = new Request("https://panel.example.com/api/captcha", {
    headers: { "x-real-ip": "198.51.100.9" },
  });
  await assert.rejects(
    () => verifyCaptcha(process.env, otherIp, second.captchaId, code2),
    /网络不匹配/
  );
});

test("SESSION_SECRET fails closed in hosted environments and requires 32 chars", () => {
  const oldVercel = process.env.VERCEL;
  const oldSecret = process.env.SESSION_SECRET;
  try {
    process.env.VERCEL = "1";
    delete process.env.SESSION_SECRET;
    assert.throws(() => getSessionSecret(process.env), /SESSION_SECRET/);

    process.env.SESSION_SECRET = "short";
    assert.throws(() => getSessionSecret(process.env), /至少需要 32/);
  } finally {
    if (oldVercel === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = oldVercel;
    if (oldSecret === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = oldSecret;
  }
});

test("origin checks reject cross-site writes but allow same-origin and non-browser clients", () => {
  const same = new Request("https://panel.example.com/api/login", {
    method: "POST",
    headers: { origin: "https://panel.example.com", "sec-fetch-site": "same-origin" },
  });
  assert.equal(isAllowedOrigin(same, {}), true);

  const cross = new Request("https://panel.example.com/api/login", {
    method: "POST",
    headers: { origin: "https://evil.example.com", "sec-fetch-site": "cross-site" },
  });
  assert.equal(isAllowedOrigin(cross, {}), false);

  const sameSite = new Request("https://panel.example.com/api/login", {
    method: "POST",
    headers: { origin: "https://evil.example.com", "sec-fetch-site": "same-site" },
  });
  assert.equal(isAllowedOrigin(sameSite, {}), false);

  const noOrigin = new Request("https://panel.example.com/api/login", { method: "POST" });
  assert.equal(isAllowedOrigin(noOrigin, {}), true);
});
