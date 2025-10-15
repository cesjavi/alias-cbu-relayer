(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AliasCBU = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  "use strict";

  // ---------- Utils ----------
  const FIELD_P = (2n ** 251n) + (17n * (2n ** 192n)) + 1n;
  const strip0x = (h) => (h || "").toLowerCase().replace(/^0x/, "");
  const padHex64 = (h) => "0x" + strip0x(h).padStart(64, "0");
  const toFeltHex = (hex) => {
    let n = BigInt("0x" + strip0x(hex));
    n = ((n % FIELD_P) + FIELD_P) % FIELD_P;
    return "0x" + n.toString(16);
  };
  const toUint256 = (value) => {
    const bn = BigInt(value);
    return {
      low: "0x" + (bn & ((1n << 128n) - 1n)).toString(16),
      high: "0x" + (bn >> 128n).toString(16)
    };
  };
  const shortHex = (h) => {
    if (!h) return "";
    const s = strip0x(h);
    return "0x" + s.slice(0,6) + "..." + s.slice(-6); // usar "..." (evitar el carácter U+2026)
  };

  // ---------- Estado interno ----------
  const state = {
    apiBase: "",        // "" => mismo origen
    account: null,
    address: null,
    cfg: null,
    prepared: null,
    walletName: null,
  };
  const getState = () => ({ ...state });

  // ---------- HTTP ----------
  const apiUrl = (path) => {
    const base = state.apiBase ? state.apiBase.replace(/\/$/, "") : "";
    return `${base}${path}`;
  };
  async function httpJson(url, opt = {}) {
    const r = await fetch(url, opt);
    const t = await r.text();
    let d=null; try { d=t?JSON.parse(t):null; } catch {}
    if (!r.ok) throw new Error(d?.detail || d?.error || t || `HTTP ${r.status}`);
    return d ?? {};
  }

  // ---------- Wallet detection ----------
  function detectXverse() {
    if (typeof window === "undefined") return null;
    const guesses = [];
    if (window.starknet_xverse) guesses.push(window.starknet_xverse);
    const providers = window.xverseProviders;
    if (providers?.starknet) guesses.push(providers.starknet);
    if (window.xverse) {
      if (window.xverse.starknet) guesses.push(window.xverse.starknet);
      if (window.xverse.starknetProvider) guesses.push(window.xverse.starknetProvider);
    }
    if (window.xverseProvider) guesses.push(window.xverseProvider);
    if (window.xverseWallet?.starknet) guesses.push(window.xverseWallet.starknet);
    if (window.btc?.starknet) guesses.push(window.btc.starknet);
    for (const guess of guesses) {
      if (!guess) continue;
      if (typeof guess === "function") {
        try {
          const maybe = guess();
          if (maybe) return maybe;
        } catch (_) {}
      }
      if (typeof guess.getProvider === "function") {
        try {
          const provider = guess.getProvider();
          if (provider) return provider;
        } catch (_) {}
      }
      if (guess?.provider) return guess.provider;
      if (guess?.request || guess?.enable || guess?.account || guess?.selectedAddress || guess?.selectedAccount) {
        return guess;
      }
    }
    return null;
  }

  function waitForWallets(ms = 8000) {
    return new Promise((resolve) => {
      const kick = () => {
        const sn = (typeof window !== "undefined") ? window.starknet : null;
        const argentx = (sn && sn.isArgentX) ? sn : ((typeof window !== "undefined") ? window.starknet_argentX : null);
        const braavos = (sn && sn.isBraavos) ? sn : ((typeof window !== "undefined") ? (window.starknet_braavos || window.braavos) : null);
        const xverse = detectXverse();
        resolve({ braavos, argentx, xverse });
      };
      if (typeof window !== "undefined" && (window.starknet || window.starknet_braavos || window.braavos || window.starknet_argentX || window.starknet_xverse || window.xverseProviders || window.xverse || window.xverseProvider || window.xverseWallet)) {
        return kick();
      }
      if (typeof window !== "undefined") {
        const handler = () => kick();
        window.addEventListener('starknet#initialized', handler, { once: true });
        window.addEventListener('xverse#initialized', handler, { once: true });
      }
      setTimeout(kick, ms);
    });
  }

  async function connect() {
    const { braavos, argentx, xverse } = await waitForWallets(8000);
    const candidates = [
      { name: 'ArgentX', obj: argentx },
      { name: 'Braavos', obj: braavos },
      { name: 'Xverse', obj: xverse },
      { name: 'Braavos (legacy)', obj: (typeof window !== "undefined") ? window.braavos : null },
    ];
    for (const { name, obj } of candidates) {
      if (!obj) continue;
      try {
        if (typeof obj.enable === 'function') {
          await obj.enable({ starknetVersion: 'v5' });
        } else if (obj.request) {
          await obj.request({ type: 'wallet_requestAccounts' });
        }
        const acc = obj.account || obj.selectedAccount || obj;
        const addr = acc?.address || obj.selectedAddress;
        if (addr) {
          state.account = acc;
          state.address = padHex64(addr);
          state.walletName = name;
          return { address: state.address, wallet: name };
        }
      } catch (e) {
        // probar la siguiente
      }
    }
    throw new Error("No se encontró ArgentX, Braavos ni Xverse. Verificá permisos del sitio o la instalación.");
  }

  async function loadConfig() {
    const cfg = await httpJson(apiUrl("/api/config"));
    // Normalizar
    cfg.aic_token = padHex64(cfg.aic_token);
    cfg.relayer_address = padHex64(cfg.relayer_address);
    cfg.chain_id = "0x" + strip0x(cfg.chain_id).replace(/^0+/, '');
    state.cfg = cfg;
    return cfg;
  }

  // ---------- Build typed data ----------
  function buildTypedData(alias_key_hex, len, user_hex, nonce, chainId_hex) {
    const cleanHex = (h) => {
      const s = strip0x(h);
      return "0x" + (s.replace(/^0+/, "") || "0");
    };
    return {
      types: {
        StarkNetDomain: [
          { name: "name", type: "felt" },
          { name: "version", type: "felt" },
          { name: "chainId", type: "felt" },
        ],
        RegisterAlias: [
          { name: "user_addr", type: "felt" },
          { name: "alias_key", type: "felt" },
          { name: "len", type: "felt" },
          { name: "nonce", type: "felt" },
        ],
      },
      primaryType: "RegisterAlias",
      domain: { name: "AliasCBU", version: "1", chainId: cleanHex(chainId_hex) },
      message: {
        user_addr: toFeltHex(user_hex),
        alias_key: toFeltHex(alias_key_hex),
        len: String(len),
        nonce: String(nonce),
      },
    };
  }

  async function signTypedMessageWithFallback(accountObj, typed) {
    // estándar
    if (accountObj?.signMessage) {
      try {
        let sig = await accountObj.signMessage(typed);
        if (!Array.isArray(sig) && sig?.r && sig?.s) sig = [sig.r, sig.s];
        return sig;
      } catch (e) { /* sigue fallback */ }
    }
    // Intento genérico vía request (p.ej. Xverse expone el provider directamente)
    if (state.walletName === 'Xverse') {
      const xverse = detectXverse();
      if (xverse?.request) {
        const payloads = [
          { type: "wallet_signTypedData", params: typed },
          { type: "wallet_signTypedData", params: [typed] },
          { type: "wallet_signMessage", params: typed },
          { type: "wallet_signMessage", params: [typed] },
        ];
        for (const payload of payloads) {
          try {
            let sig = await xverse.request(payload);
            if (sig?.result) sig = sig.result;
            if (!sig) continue;
            if (!Array.isArray(sig) && sig?.r && sig?.s) sig = [sig.r, sig.s];
            if (Array.isArray(sig)) return sig;
          } catch (_) {
            // probar siguiente forma
          }
        }
      }
    }
    // Braavos nativo
    const br = (typeof window !== "undefined") ? (window.starknet_braavos || window.braavos) : null;
    if (br?.request) {
      let sig = await br.request({ type: "braavos_signMessage", params: typed });
      if (!Array.isArray(sig) && sig?.r && sig?.s) sig = [sig.r, sig.s];
      return sig;
    }
    throw new Error("No se pudo firmar el mensaje (wallet no expone signMessage).");
  }

  // ---------- API de backend ----------
  async function prepare(alias) {
    if (!state.address) throw new Error("Conectá la wallet primero");
    const body = { user_address: state.address, alias: String(alias || "").trim() };
    const r = await httpJson(apiUrl("/api/prepare"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    state.prepared = r;
    return r;
  }

  async function approve() {
    if (!state.account || !state.cfg || !state.prepared) throw new Error("Falta connect/config/prepare");
    const amount = toUint256(state.prepared.fee_aic_wei);
    const approveCall = {
      contractAddress: state.cfg.aic_token,
      entrypoint: "approve",
      calldata: [ state.cfg.relayer_address, amount.low, amount.high ]
    };

    // Compatibilidad básica (la wallet suele estimar)
    const res = await state.account.execute([approveCall], undefined, { version: "0x3" });
    const txHash = res?.transaction_hash || res;
    return { txHash };
  }

  async function sign() {
    if (!state.account || !state.cfg || !state.prepared) throw new Error("Falta connect/config/prepare");
    const typed = buildTypedData(
      state.prepared.alias_key,
      state.prepared.len,
      state.address,
      state.prepared.nonce,
      state.cfg.chain_id
    );
    const sig = await signTypedMessageWithFallback(state.account, typed);
    state.prepared.signature = sig;
    return { signature: sig };
  }

  async function submit(aliasOverride) {
    if (!state.prepared?.signature) throw new Error("Falta firmar");
    const alias = (aliasOverride ?? "").trim() || undefined;
    const body = {
      user_address: state.address,
      alias: alias || undefined,
      signature: state.prepared.signature,
      nonce: state.prepared.nonce
    };
    const r = await httpJson(apiUrl("/api/submit"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return r; // { ok, tx_hash, relayer }
  }

  async function resolveAlias(alias) {
    const q = encodeURIComponent(String(alias || "").trim());
    return await httpJson(apiUrl(`/api/resolve_alias?alias=${q}`));
  }

  async function resolveAddress(address) {
    const q = encodeURIComponent(String(address || "").trim());
    return await httpJson(apiUrl(`/api/resolve_address?address=${q}`));
  }

  async function faucet(address) {
    const addr = address || state.address;
    if (!addr) throw new Error("Falta address (o conectá la wallet)");
    return await httpJson(apiUrl(`/api/faucet`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address: addr })
    });
  }

  // ---------- init ----------
  function init(opts = {}) {
    state.apiBase = opts.apiBase || "";
    return {
      getState,
      shortHex,
      connect,
      loadConfig,
      prepare,
      approve,
      sign,
      submit,
      resolveAlias,
      resolveAddress,
      faucet,
    };
  }

  return { init };
}));
