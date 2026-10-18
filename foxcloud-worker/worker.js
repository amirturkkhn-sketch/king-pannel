import { connect as e } from "cloudflare:sockets";
var t = Object.defineProperty, n = (e, t) => () => (e && (t = e(e = 0)), t), r = (e, n) => { for (var r in n) t(e, r, { get: n[r], enumerable: !0 }) }, i = {};
r(i, { errorPage: () => o, indexPage: () => a, subscriptionPage: () => s });
async function a() { return new Response(c, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }) }
async function o() { return new Response(l, { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } }) }
async function s(e, t) {
  let { splitAndFilter: n } = await Promise.resolve().then(function () { return x(), _ }),
    { generateSubscription: r, generateVlessConfig: i } = await Promise.resolve().then(function () { return h(), d }),
    a = n(e.UUID || "", ","), o = new URL(t.url),
    s = a.map(e => ({ uuid: e, link: r(e, o), vlessJson: JSON.stringify(i(e, o), null, 2) })),
    c = e => e.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"),
    l = s.length > 0 ? s[0] : null,
    u = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>FoxCloud Subscription</title></head><body><h1>FoxCloud</h1><p>${c(l?.link || "")}</p></body></html>`;
  return new Response(u, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
var c, l, u = n(() => { c = `<!DOCTYPE html><html><body>Welcome</body></html>`; l = `<!DOCTYPE html><html><body>Error</body></html>`; });
u();
var d = {};
r(d, { generateAllConfigs: () => m, generateSubscription: () => f, generateVlessConfig: () => p });
function f(e, t) { return `vless://${e}@${t.hostname}:443?encryption=none&security=tls&sni=${t.hostname}&fp=chrome&type=ws&host=${t.hostname}&path=ws&ed=4096#${t.hostname}` }
function p(e, t) { return { v: "2", ps: t.hostname, add: t.hostname, port: "443", id: e, aid: "0", net: "ws", type: "none", host: t.hostname, path: "/ws", tls: "tls", sni: t.hostname, fp: "chrome" } }
function m(e, t) { return { vless: f(e, t), vlessJson: p(e, t) } }
var h = n(() => {});
const g = { TESTING_VERSION: 0, RELEASE_VERSION: 1, COMMAND_TCP: 1, COMMAND_UDP: 2, COMMAND_MUX: 3, ADDRESS_TYPE_IPV4: 1, ADDRESS_TYPE_DOMAIN: 2, ADDRESS_TYPE_IPV6: 3, RESPONSE_DATA: e => new Uint8Array([e, 0]).buffer };
var _ = {};
r(_, { contains: () => v, filterEmpty: () => y, splitAndFilter: () => b });
function v(e, t) { return e.includes(t) }
function y(e) { return e.filter(e => e !== "") }
function b(e, t) { return y(e.split(t)) }
var x = n(() => {});
x();
function S(e) { let t = new Uint8Array(e), n = Array.from(t, e => e.toString(16).padStart(2, "0")); return [n.slice(0, 4).join(""), n.slice(4, 6).join(""), n.slice(6, 8).join(""), n.slice(8, 10).join(""), n.slice(10, 16).join("")].join("-") }
function C(e, t) {
  if (e.byteLength < 24) throw Error("invalid protocol header");
  let n = new DataView(e), r = n.getUint8(0);
  if (r !== g.RELEASE_VERSION && r !== g.TESTING_VERSION) throw Error("invalid protocol version");
  let i = S(e.slice(1, 17));
  if (!v(t, i)) throw Error("invalid user");
  let a = n.getUint8(17), o = n.getUint8(18 + a);
  if (o !== g.COMMAND_TCP && o !== g.COMMAND_UDP) throw Error("unsupported command");
  let s = 18 + a + 1, c = n.getUint16(s), l = n.getUint8(s + 2), u = "", d, f;
  switch (l) {
    case g.ADDRESS_TYPE_IPV4: d = 4, f = s + 3, u = new Uint8Array(e.slice(f, f + d)).join("."); break;
    case g.ADDRESS_TYPE_DOMAIN: d = n.getUint8(s + 3), f = s + 4, u = new TextDecoder().decode(e.slice(f, f + d)); break;
    case g.ADDRESS_TYPE_IPV6: d = 16, f = s + 3, u = Array.from({ length: 8 }, (e, t) => n.getUint16(f + t * 2).toString(16)).join(":"); break;
    default: throw Error("invalid address type")
  }
  return { version: r, isUDP: o === g.COMMAND_UDP, address: u, port: c, rawData: e.slice(f + d) }
}
function w(e) { try { (e.readyState === WebSocket.OPEN || e.readyState === WebSocket.CLOSING) && e.close() } catch (e) {} }
async function T(e, t, n, r) { for (let i of r) try { return await E(i, e, t, n) } catch (e) { continue } }
async function E(t, n, r, i) {
  let a = null, o = null, s = null;
  try {
    let c = e(t), l = c.writable.getWriter();
    await l.write(r), a = async e => { await l.write(e.data) }, o = async () => { await c.close() }, s = async () => { await c.close() },
    i.addEventListener("message", a), i.addEventListener("close", o), i.addEventListener("error", s);
    let u = c.readable.getReader(), { done: d, value: f } = await u.read();
    if (d) throw Error("connection was done");
    return u.releaseLock(), i.send(await new Blob([g.RESPONSE_DATA(n), f]).arrayBuffer()), c
  } catch (e) { throw a && i.removeEventListener("message", a), o && i.removeEventListener("close", o), s && i.removeEventListener("error", s), e }
}
async function D(e, t, n) {
  let r;
  try {
    let n = t.address;
    if (isNaN(Number(n.split(".")[0]))) try { n = await O(n) } catch (e) {}
    r = await E({ hostname: n, port: t.port }, t.version, t.rawData, e)
  } catch { r = await T(t.version, t.rawData, e, n) }
  if (r === void 0) throw Error("cannot connect");
  await r.readable.pipeTo(new WritableStream({ write(t) { e.send(t) }, abort() { w(e) }, close() { w(e) } }))
}
async function O(e) {
  try {
    let t = await fetch(`https://cloudflare-dns.com/dns-query?name=${e}&type=A`, { headers: { Accept: "application/dns-json" } });
    if (t.ok) { let e = await t.json(); if (e.Answer && e.Answer.length > 0) { let t = e.Answer.find(e => e.type === 1); if (t) return t.data } }
  } catch (e) {}
  return e
}
async function k(t, n) {
  let r = e({ hostname: "8.8.8.8", port: 53 }), i = r.writable.getWriter();
  await i.write(n.rawData), t.addEventListener("message", async e => { await i.write(e.data) }), t.addEventListener("close", async () => { await r.close() }), t.addEventListener("error", async () => { await r.close() });
  let a = r.readable.getReader(), { done: o, value: s } = await a.read();
  if (o) throw Error("done");
  a.releaseLock(), t.send(await new Blob([g.RESPONSE_DATA(n.version), s]).arrayBuffer()), await r.readable.pipeTo(new WritableStream({ write(e) { t.send(e) }, abort() { w(t) }, close() { w(t) } }))
}
function A(e) { e = e.replace(/-/g, "+").replace(/_/g, "/"); let t = atob(e), n = new ArrayBuffer(t.length), r = new Uint8Array(n); for (let e = 0; e < t.length; e++)r[e] = t.charCodeAt(e); return n }
function j(e, t) {
  return new Promise((n, r) => {
    if (t) try { n(A(t)) } catch (e) { r(e) }
    let i = t => { typeof t.data == "string" ? r("invalid data") : n(t.data), e.removeEventListener("message", i), e.removeEventListener("error", a) },
      a = t => { r(t.error || "WebSocket error"), e.removeEventListener("message", i), e.removeEventListener("error", a) };
    e.addEventListener("message", i), e.addEventListener("error", a), setTimeout(() => { r("timeout"), e.removeEventListener("message", i), e.removeEventListener("error", a) }, 1e4)
  })
}
function M(e, t) {
  let n = t.UUID.split(",").filter(e => e !== ""), r = t.PROXY_IP.split(",").filter(e => e !== ""), [i, a] = Object.values(new WebSocketPair());
  if (a === void 0) throw "WebSocket server not defined";
  if (i === void 0) throw "WebSocket client not defined";
  return a.accept(), j(a, e.headers.get("Sec-WebSocket-Protocol")).then(e => C(e, n)).then(async e => { if (e.isUDP) if (e.port === 53) await k(a, e); else throw Error("UDP unsupported"); await D(a, e, r) }).catch(e => { w(a) }), new Response(null, { status: 101, webSocket: i })
}
u(), h(), x();
async function N(e, t, n) {
  try {
    let n = e.headers.get("Upgrade");
    if (n && n === "websocket") return M(e, t);
    let r = new URL(e.url);
    if (r.pathname === "/sub") { let { subscriptionPage: n } = await Promise.resolve().then(function () { return u(), i }); return await n(t, e) }
    let o = b(t.UUID, ",");
    for (let e of o) if (r.pathname.includes(e)) return new Response(f(e, r), { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    return await a()
  } catch (e) { return await o() }
}
var P = { async fetch(e, t, n) { return N(e, t, n) } };
export { P as default };
