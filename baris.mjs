"use strict";
import http2 from "node:http2";
import tls from "node:tls";
import WebSocket from "ws";

const token    = "doldur kardesim";
const listener = "doldur hayatim";
const password = "sifreni gir kardesim";
const serverID = "31";

const tlsSockets = [];

const keepAliveBuffer = Buffer.from(
  "GET / HTTP/1.1\r\nHost: canary.discord.com\r\nConnection: keep-alive\r\n\r\n"
);

function createTLSSocket(i) {
  const host = "canary.discord.com";
  const sock = tls.connect({
    host,
    port: 443,
    servername: host,
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined,
    noDelay: true,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
  }, () => {
    sock.setNoDelay(true);
    sock.setMaxSendFragment(4096);
    sock.setKeepAlive(true, 0);
    sock.write(keepAliveBuffer);
    sock._handle?.setSendBufferSize?.(64 * 1024);
    sock._handle?.setNoDelay?.(true);
    sock._handle?.setRecvBufferSize?.(256 * 1024);
  });
  sock.setMaxListeners(0);
  sock.on("close", () => { tlsSockets[i] = createTLSSocket(i); });
  sock.on("error", () => {});
  return sock;
}

for (let i = 0; i < 1; i++) tlsSockets[i] = createTLSSocket(i);

setInterval(() => {
  for (let i = 0; i < tlsSockets.length; i++) {
    if (tlsSockets[i].writable) tlsSockets[i].write(keepAliveBuffer);
  }
}, 3000);

const sessionSettings = [
  { initialWindowSize: 2147483647, maxConcurrentStreams: 65535, maxHeaderListSize: 65536, maxFrameSize: 16777215, headerTableSize: 65536 },
];

const sessionPool = sessionSettings.map((settings) =>
  http2.connect("https://canary.discord.com", {
    rejectUnauthorized: true,
    settings: { enablePush: false, ...settings },
    createConnection() {
      const sock = tls.connect({
        host: "canary.discord.com",
        port: 443,
        servername: "canary.discord.com",
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
        ALPNProtocols: ["h2"],
        checkServerIdentity: () => undefined,
        noDelay: true,
      });
      sock.setNoDelay(true);
      sock.setKeepAlive(true, 0);
      return sock;
    },
  })
);

for (let i = 0; i < sessionPool.length; i++) {
  sessionPool[i].ref();
  sessionPool[i].once("connect", () => console.log(`[HTTP2] Session ${i} connected`));
  sessionPool[i].on("error", (err) => { console.error(`[HTTP2] Session ${i} error:`, err.message); process.exit(1); });
  sessionPool[i].on("close", () => { console.log(`[HTTP2] Session ${i} closed`); process.exit(1); });
}

const requestOptions = Object.freeze({ endStream: false });
const guilds       = new Map();
const requestCache = new Map();
let mfaToken   = null;
let mfaRunning = false;

let heartbeatBuffer = null;
let identifyBuffer  = null;

function rebuildGatewayBuffers() {
  heartbeatBuffer = Buffer.from(JSON.stringify({ op: 1, d: null }));
  identifyBuffer  = Buffer.from(JSON.stringify({
    op: 2,
    d: {
      token: listener,
      intents: 1,
      properties: { os: "linux", browser: "chrome", device: "pc" },
      zerortt: true
    }
  }));
}

function parseGatewayPayload(raw) {
  const msg = JSON.parse(raw);
  return { t: msg.t, d: msg.d };
}

function buildRequest(oldVanity) {
  const rawPayload = `{"code":"${oldVanity}"}`;
  const payload = Buffer.from(rawPayload);

  const headers = Object.freeze({
    ":method": "PATCH",
    ":path": `/api/v9/guilds/${serverID}/vanity-url`,
    Authorization: token,
    "Content-Type": "application/json",
    "Content-Length": String(payload.byteLength),
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6InRyLVRSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM2LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjQzOTE3OCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=",
    "X-Discord-Mfa-Authorization": mfaToken,
  });

  const tlsBuf = Buffer.from(
    `PATCH /api/v9/guilds/${serverID}/vanity-url HTTP/1.1\r\n` +
    `Host: canary.discord.com\r\n` +
    `Authorization: ${token}\r\n` +
    `Content-Type: application/json\r\n` +
    `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\r\n` +
    `X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6InRyLVRSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM2LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjQzOTE3OCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=\r\n` +
    `X-Discord-Mfa-Authorization: ${mfaToken}\r\n` +
    `Content-Length: ${Buffer.byteLength(rawPayload)}\r\n\r\n` +
    rawPayload
  );

  requestCache.set(oldVanity, { headers, payload, tlsBuf });
}

function rebuildRequestCache() {
  requestCache.clear();
  for (const code of guilds.values()) {
    if (code) buildRequest(code);
  }
  console.log(`[CACHE] ${requestCache.size} vanity cached`);
}

function handleReady(d) {
  guilds.clear();
  const g = d?.guilds;
  if (!Array.isArray(g)) return;
  for (const row of g) guilds.set(row.id, row.vanity_url_code);
  console.log(`[READY] ${guilds.size} guilds`);
  if (mfaToken) rebuildRequestCache();
}

function handleGuildUpdate(d) {
  const id = d?.id;
  const oldVanity = guilds.get(id);
  if (oldVanity && oldVanity !== d.vanity_url_code) {
    setTimeout(() => {
      setImmediate(() => {
        const c = requestCache.get(oldVanity);
        for (let i = 0; i < sessionPool.length; i++) sessionPool[i].request(c.headers, requestOptions).end(c.payload);
        for (let i = 0; i < tlsSockets.length; i++) tlsSockets[i].write(c.tlsBuf);
      });
    }, 3000);
  }
  guilds.set(id, d.vanity_url_code);
}

function onmessage(raw) {
  const { t, d } = parseGatewayPayload(raw);
  if (t === "READY") handleReady(d);
  else if (t === "GUILD_UPDATE") handleGuildUpdate(d);
}

async function http2Mfa() {
  if (!token || !password) return false;

  let session;
  try {
    session = http2.connect("https://canary.discord.com", {
      settings: { enablePush: false, initialWindowSize: 2147483647, maxHeaderListSize: 131072 },
      createConnection: () =>
        tls.connect(443, "canary.discord.com", {
          servername: "canary.discord.com",
          rejectUnauthorized: false,
          ALPNProtocols: ["h2"],
          minVersion: "TLSv1.3",
          maxVersion: "TLSv1.3",
          ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        }),
    });

    await new Promise((resolve, reject) => {
      session.once("connect", resolve);
      session.once("error", reject);
    });

    const makeRequest = (method, path, body) => new Promise((resolve) => {
      const headers = {
        ":method": method, ":path": path,
        ":authority": "canary.discord.com", ":scheme": "https",
        Authorization: token, "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6InRyLVRSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM2LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjQzOTE3OCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=",
      };
      if (body) headers["Content-Length"] = Buffer.byteLength(body);
      const stream = session.request(headers);
      const chunks = [];
      const timeoutId = setTimeout(() => resolve(""), 3000);
      const done = (r) => { clearTimeout(timeoutId); resolve(r); };
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => done(Buffer.concat(chunks).toString()));
      stream.on("error", () => done(""));
      if (body) stream.write(body);
      stream.end();
    });

    const triggerRes = await makeRequest("PATCH", `/api/v10/guilds/0/vanity-url`, JSON.stringify({ code: "" }));
    if (!triggerRes) return false;

    let json;
    try { json = JSON.parse(triggerRes); } catch { return false; }

    if (json?.code === 60003 && json.mfa?.ticket) {
      const mfaRes = await makeRequest("POST", "/api/v10/mfa/finish",
        JSON.stringify({ ticket: json.mfa.ticket, mfa_type: "password", data: password }));
      let mfaJson;
      try { mfaJson = JSON.parse(mfaRes); } catch { return false; }
      if (mfaJson?.token) {
        mfaToken = mfaJson.token;
        rebuildRequestCache();
        console.log(`[MFA] OK`);
        return true;
      }
    }
    return false;
  } catch (e) {
    console.error("[MFA] Error:", e.message);
    return false;
  } finally {
    if (session) { try { session.close(); } catch {} }
  }
}

async function runMfaLoop() {
  if (mfaRunning) return;
  mfaRunning = true;
  try { await http2Mfa(); } finally { mfaRunning = false; }
}

const wsOptions = {
  perMessageDeflate: false,
  skipUTF8Validation: true,
  rejectUnauthorized: true,
  noDelay: true,
};

function attachGateway(ws) {
  ws.on("open", () => {
    ws._socket?.setNoDelay?.(true);
    ws._socket?.setKeepAlive?.(true, 0);
    ws.send(identifyBuffer);
    setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(heartbeatBuffer);
    }, 41250);
  });
  ws.on("message", (raw) => { onmessage(raw); });
  ws.on("close", () => process.exit(1));
  ws.on("error", () => {});
}

function main() {
  rebuildGatewayBuffers();

  sessionPool[0].once("connect", () => {
    for (let i = 0; i < sessionPool.length; i++) {
      sessionPool[i].request({
        ":method": "HEAD", ":path": "/api/v10/gateway",
        ":authority": "canary.discord.com", ":scheme": "https",
      }, { endStream: true }).end();
    }

    runMfaLoop();
    setInterval(runMfaLoop, 240_000);

    setInterval(() => {
      for (let i = 0; i < sessionPool.length; i++) {
        sessionPool[i].request({ ":method": "HEAD", ":path": "/api/v10/gateway" }, { endStream: true }).end();
      }
    }, 30_000);

    setInterval(() => {
      for (let i = 0; i < sessionPool.length; i++) sessionPool[i].ping(() => {});
    }, 90_000);
  });

  attachGateway(new WebSocket("wss://gateway.discord.gg/?v=10&encoding=json", wsOptions));
  attachGateway(new WebSocket("wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json", wsOptions));
}

main();
// iyi kullanırsız aklınız varsa bok bok kodlar kullanmayın 2 ay onceki main dahasi icin @howeverfaraway eklersin 
