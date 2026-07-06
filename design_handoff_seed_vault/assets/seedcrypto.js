/* SeedCrypto — offline BIP39/BIP32 validation + address derivation + OpenSSL-compatible encryption.
   No network calls. Uses WebCrypto for SHA-256/SHA-512/HMAC/PBKDF2/AES-CBC; pure JS for
   secp256k1, ed25519, keccak-256, ripemd-160, bech32, base58. */
(function () {
  'use strict';
  const te = new TextEncoder();

  // ---------- small utils ----------
  const concat = (...arrs) => {
    const len = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  const bytesToBig = (u8) => u8.reduce((a, b) => (a << 8n) | BigInt(b), 0n);
  const bigToBytes = (n, len) => {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
  };
  const ser32 = (i) => new Uint8Array([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]);

  // ---------- WebCrypto primitives ----------
  const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const sha512 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-512', data));
  async function hmacSha512(key, data) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
  }
  async function pbkdf2(pass, salt, iterations, hash, bytes) {
    const k = await crypto.subtle.importKey('raw', pass, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash }, k, bytes * 8);
    return new Uint8Array(bits);
  }

  // ---------- BIP39 ----------
  const WORDS = window.BIP39_WORDS;
  const WORDSET = new Set(WORDS);

  function normalizeMnemonic(text) {
    return text.normalize('NFKD').trim().toLowerCase().split(/\s+/).filter(Boolean);
  }

  async function validateMnemonic(text) {
    const words = normalizeMnemonic(text);
    const res = { words, badWords: [], lengthOk: false, checksumOk: false, ok: false };
    if (!words.length) return res;
    words.forEach((w, i) => { if (!WORDSET.has(w)) res.badWords.push(i); });
    res.lengthOk = [12, 15, 18, 21, 24].includes(words.length);
    if (res.badWords.length || !res.lengthOk) return res;
    // bits
    const idx = words.map((w) => WORDS.indexOf(w));
    let bits = '';
    for (const i of idx) bits += i.toString(2).padStart(11, '0');
    const entBits = (words.length * 11 * 32) / 33;
    const csBits = words.length * 11 - entBits;
    const entropy = new Uint8Array(entBits / 8);
    for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    const h = await sha256(entropy);
    const csExpected = h[0].toString(2).padStart(8, '0').slice(0, csBits);
    res.checksumOk = bits.slice(entBits) === csExpected;
    res.ok = res.checksumOk;
    return res;
  }

  async function mnemonicToSeed(text, passphrase) {
    const mnemonic = normalizeMnemonic(text).join(' ');
    const salt = te.encode('mnemonic' + (passphrase || '').normalize('NFKD'));
    return pbkdf2(te.encode(mnemonic), salt, 2048, 'SHA-512', 64);
  }

  function suggest(prefix, limit) {
    prefix = prefix.toLowerCase();
    if (!prefix) return [];
    const out = [];
    for (const w of WORDS) {
      if (w.startsWith(prefix)) { out.push(w); if (out.length >= (limit || 8)) break; }
    }
    return out;
  }

  // ---------- secp256k1 ----------
  const SP = 2n ** 256n - 2n ** 32n - 977n;
  const SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const SG = [
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
  ];
  const mod = (a, m) => ((a % m) + m) % m;
  function inv(a, m) {
    a = mod(a, m);
    let [g, x, g1, x1] = [m, 0n, a, 1n];
    while (g1 !== 0n) {
      const q = g / g1;
      [g, g1] = [g1, g - q * g1];
      [x, x1] = [x1, x - q * x1];
    }
    return mod(x, m);
  }
  function secAdd(P1, P2) {
    if (!P1) return P2;
    if (!P2) return P1;
    const [x1, y1] = P1, [x2, y2] = P2;
    if (x1 === x2 && mod(y1 + y2, SP) === 0n) return null;
    let l;
    if (x1 === x2 && y1 === y2) l = mod(3n * x1 * x1 * inv(2n * y1, SP), SP);
    else l = mod((y2 - y1) * inv(x2 - x1, SP), SP);
    const x3 = mod(l * l - x1 - x2, SP);
    const y3 = mod(l * (x1 - x3) - y1, SP);
    return [x3, y3];
  }
  function secMul(k, P) {
    let R = null, Q = P;
    while (k > 0n) {
      if (k & 1n) R = secAdd(R, Q);
      Q = secAdd(Q, Q);
      k >>= 1n;
    }
    return R;
  }
  const pubCompressed = (P) => concat(new Uint8Array([P[1] & 1n ? 3 : 2]), bigToBytes(P[0], 32));
  const pubUncompressed64 = (P) => concat(bigToBytes(P[0], 32), bigToBytes(P[1], 32));

  // ---------- BIP32 (secp256k1) ----------
  async function bip32Master(seed) {
    const I = await hmacSha512(te.encode('Bitcoin seed'), seed);
    return { k: I.slice(0, 32), c: I.slice(32) };
  }
  async function bip32Child(node, index) {
    const hardened = index >= 0x80000000;
    let data;
    if (hardened) data = concat(new Uint8Array([0]), node.k, ser32(index));
    else data = concat(pubCompressed(secMul(bytesToBig(node.k), SG)), ser32(index));
    const I = await hmacSha512(node.c, data);
    const kChild = mod(bytesToBig(I.slice(0, 32)) + bytesToBig(node.k), SN);
    return { k: bigToBytes(kChild, 32), c: I.slice(32) };
  }
  const H = 0x80000000;
  async function bip32Path(seed, path) {
    let node = await bip32Master(seed);
    for (const i of path) node = await bip32Child(node, i);
    return node;
  }

  // ---------- keccak-256 ----------
  const KRC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  const KROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
  const M64 = (1n << 64n) - 1n;
  const rotl64 = (x, n) => ((x << n) | (x >> (64n - n))) & M64;
  function keccakF(s) {
    for (let r = 0; r < 24; r++) {
      const c = [];
      for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1n);
        for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
      }
      const b = new Array(25);
      for (let x = 0; x < 5; x++)
        for (let y = 0; y < 5; y++) {
          const i = x + 5 * y;
          b[y + 5 * ((2 * x + 3 * y) % 5)] = KROT[i] ? rotl64(s[i], BigInt(KROT[i])) : s[i];
        }
      for (let x = 0; x < 5; x++)
        for (let y = 0; y < 5; y++) {
          const i = x + 5 * y;
          s[i] = b[i] ^ (~b[((x + 1) % 5) + 5 * y] & M64) & b[((x + 2) % 5) + 5 * y];
        }
      s[0] ^= KRC[r];
    }
  }
  function keccak256(data) {
    const rate = 136;
    const s = new Array(25).fill(0n);
    const padded = new Uint8Array(Math.ceil((data.length + 1) / rate) * rate);
    padded.set(data);
    padded[data.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    for (let off = 0; off < padded.length; off += rate) {
      for (let i = 0; i < rate / 8; i++) {
        let lane = 0n;
        for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
        s[i] ^= lane;
      }
      keccakF(s);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
      let lane = s[i];
      for (let j = 0; j < 8; j++) { out[i * 8 + j] = Number(lane & 0xffn); lane >>= 8n; }
    }
    return out;
  }

  // ---------- ripemd-160 ----------
  function ripemd160(data) {
    const rl = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
      [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
      [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
      [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
    ];
    const rr = [
      [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
      [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
      [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
      [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
      [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
    ];
    const sl = [
      [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
      [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
      [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
      [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
      [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
    ];
    const sr = [
      [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
      [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
      [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
      [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
      [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
    ];
    const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
    const f = (j, x, y, z) => {
      if (j < 16) return x ^ y ^ z;
      if (j < 32) return (x & y) | (~x & z);
      if (j < 48) return (x | ~y) ^ z;
      if (j < 64) return (x & z) | (y & ~z);
      return x ^ (y | ~z);
    };
    const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    // pad
    const ml = data.length;
    const withOne = new Uint8Array((((ml + 8) >> 6) + 1) * 64);
    withOne.set(data);
    withOne[ml] = 0x80;
    const bitLen = ml * 8;
    const dv = new DataView(withOne.buffer);
    dv.setUint32(withOne.length - 8, bitLen >>> 0, true);
    dv.setUint32(withOne.length - 4, Math.floor(bitLen / 0x100000000), true);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    for (let off = 0; off < withOne.length; off += 64) {
      const X = [];
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const rnd = j >> 4;
        let t = (al + f(j, bl, cl, dl) + X[rl[rnd][j & 15]] + KL[rnd]) >>> 0;
        t = (rol(t, sl[rnd][j & 15]) + el) >>> 0;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
        t = (ar + f(79 - j, br, cr, dr) + X[rr[rnd][j & 15]] + KR[rnd]) >>> 0;
        t = (rol(t, sr[rnd][j & 15]) + er) >>> 0;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = t;
    }
    const out = new Uint8Array(20);
    const ov = new DataView(out.buffer);
    ov.setUint32(0, h0, true); ov.setUint32(4, h1, true); ov.setUint32(8, h2, true);
    ov.setUint32(12, h3, true); ov.setUint32(16, h4, true);
    return out;
  }

  // ---------- base58 / base58check ----------
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58(u8) {
    let n = bytesToBig(u8);
    let out = '';
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of u8) { if (b === 0) out = '1' + out; else break; }
    return out;
  }
  async function base58check(payload) {
    const chk = (await sha256(await sha256(payload))).slice(0, 4);
    return base58(concat(payload, chk));
  }

  // ---------- bech32 ----------
  const BCH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const BGEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function bpolymod(values) {
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= BGEN[i];
    }
    return chk;
  }
  function bech32Encode(hrp, data) {
    const exp = [];
    for (const c of hrp) exp.push(c.charCodeAt(0) >> 5);
    exp.push(0);
    for (const c of hrp) exp.push(c.charCodeAt(0) & 31);
    const pm = bpolymod(exp.concat(data, [0, 0, 0, 0, 0, 0])) ^ 1;
    const chk = [];
    for (let i = 0; i < 6; i++) chk.push((pm >>> (5 * (5 - i))) & 31);
    return hrp + '1' + data.concat(chk).map((d) => BCH[d]).join('');
  }
  function convertBits(data, from, to) {
    let acc = 0, bits = 0;
    const out = [];
    for (const b of data) {
      acc = (acc << from) | b;
      bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & ((1 << to) - 1)); }
    }
    if (bits > 0) out.push((acc << (to - bits)) & ((1 << to) - 1));
    return out;
  }

  // ---------- ed25519 (for Solana) ----------
  const EP = 2n ** 255n - 19n;
  const ED = mod(-121665n * inv(121666n, EP), EP);
  const EGX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  const EGY = mod(4n * inv(5n, EP), EP);
  // extended coords [X, Y, Z, T]
  const EG = [EGX, EGY, 1n, mod(EGX * EGY, EP)];
  const EID = [0n, 1n, 1n, 0n];
  function edAdd(p, q) {
    const [X1, Y1, Z1, T1] = p, [X2, Y2, Z2, T2] = q;
    const A = mod((Y1 - X1) * (Y2 - X2), EP);
    const B = mod((Y1 + X1) * (Y2 + X2), EP);
    const C = mod(2n * ED * T1 * T2, EP);
    const D = mod(2n * Z1 * Z2, EP);
    const E = B - A, F = D - C, G = D + C, Hh = B + A;
    return [mod(E * F, EP), mod(G * Hh, EP), mod(F * G, EP), mod(E * Hh, EP)];
  }
  function edMul(k, P) {
    let R = EID, Q = P;
    while (k > 0n) {
      if (k & 1n) R = edAdd(R, Q);
      Q = edAdd(Q, Q);
      k >>= 1n;
    }
    return R;
  }
  async function ed25519Pub(priv32) {
    const h = await sha512(priv32);
    const a = h.slice(0, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    // little-endian scalar
    let s = 0n;
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(a[i]);
    const P = edMul(s, EG);
    const zi = inv(P[2], EP);
    const x = mod(P[0] * zi, EP), y = mod(P[1] * zi, EP);
    const enc = bigToBytes(y | ((x & 1n) << 255n), 32).reverse();
    return enc;
  }
  // SLIP-0010 ed25519 (hardened only)
  async function slip10Master(seed) {
    const I = await hmacSha512(te.encode('ed25519 seed'), seed);
    return { k: I.slice(0, 32), c: I.slice(32) };
  }
  async function slip10Child(node, index) {
    const I = await hmacSha512(node.c, concat(new Uint8Array([0]), node.k, ser32(index)));
    return { k: I.slice(0, 32), c: I.slice(32) };
  }
  async function slip10Path(seed, path) {
    let node = await slip10Master(seed);
    for (const i of path) node = await slip10Child(node, i);
    return node;
  }

  // ---------- address builders ----------
  async function btcLegacyAddress(pub33) {
    const h160 = ripemd160(await sha256(pub33));
    return base58check(concat(new Uint8Array([0]), h160));
  }
  async function btcSegwitAddress(pub33) {
    const h160 = ripemd160(await sha256(pub33));
    return bech32Encode('bc', [0].concat(convertBits(Array.from(h160), 8, 5)));
  }
  function ethAddress(pub64) {
    const raw = hex(keccak256(pub64).slice(12));
    const h = hex(keccak256(te.encode(raw)));
    let out = '0x';
    for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? raw[i].toUpperCase() : raw[i];
    return out;
  }
  async function tronAddress(pub64) {
    return base58check(concat(new Uint8Array([0x41]), keccak256(pub64).slice(12)));
  }

  const CHAINS = {
    'btc-segwit': { name: 'Bitcoin — Native SegWit (BIP84)', pathLabel: (i) => `m/84'/0'/0'/0/${i}` },
    'btc-legacy': { name: 'Bitcoin — Legacy (BIP44)', pathLabel: (i) => `m/44'/0'/0'/0/${i}` },
    eth: { name: 'Ethereum (BIP44)', pathLabel: (i) => `m/44'/60'/0'/0/${i}` },
    sol: { name: 'Solana (BIP44 / ed25519)', pathLabel: (i) => `m/44'/501'/${i}'/0'` },
    tron: { name: 'Tron (BIP44)', pathLabel: (i) => `m/44'/195'/0'/0/${i}` },
  };

  async function deriveAddresses(seed, chain, count) {
    const out = [];
    if (chain === 'sol') {
      for (let i = 0; i < count; i++) {
        const node = await slip10Path(seed, [H + 44, H + 501, H + i, H + 0]);
        out.push({ index: i, path: CHAINS.sol.pathLabel(i), address: base58(await ed25519Pub(node.k)) });
      }
      return out;
    }
    const purpose = chain === 'btc-segwit' ? 84 : 44;
    const coin = chain === 'eth' ? 60 : chain === 'tron' ? 195 : 0;
    // derive account node once, then children
    const acct = await bip32Path(seed, [H + purpose, H + coin, H + 0, 0]);
    for (let i = 0; i < count; i++) {
      const node = await bip32Child(acct, i);
      const P = secMul(bytesToBig(node.k), SG);
      let address;
      if (chain === 'btc-segwit') address = await btcSegwitAddress(pubCompressed(P));
      else if (chain === 'btc-legacy') address = await btcLegacyAddress(pubCompressed(P));
      else if (chain === 'eth') address = ethAddress(pubUncompressed64(P));
      else address = await tronAddress(pubUncompressed64(P));
      out.push({ index: i, path: CHAINS[chain].pathLabel(i), address });
    }
    return out;
  }

  // ---------- OpenSSL-compatible encryption ----------
  // Matches: openssl enc -aes-256-cbc -pbkdf2 -iter <iter> -salt -in seeds.md -out seeds.md.enc
  async function opensslEncrypt(text, passphrase, iterations) {
    const iter = iterations || 100000;
    const salt = crypto.getRandomValues(new Uint8Array(8));
    const keyiv = await pbkdf2(te.encode(passphrase), salt, iter, 'SHA-256', 48);
    const key = await crypto.subtle.importKey('raw', keyiv.slice(0, 32), 'AES-CBC', false, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: keyiv.slice(32, 48) }, key, te.encode(text)));
    return concat(te.encode('Salted__'), salt, ct);
  }
  async function opensslDecrypt(blobBytes, passphrase, iterations) {
    const iter = iterations || 100000;
    const salt = blobBytes.slice(8, 16);
    const keyiv = await pbkdf2(te.encode(passphrase), salt, iter, 'SHA-256', 48);
    const key = await crypto.subtle.importKey('raw', keyiv.slice(0, 32), 'AES-CBC', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: keyiv.slice(32, 48) }, key, blobBytes.slice(16));
    return new TextDecoder().decode(pt);
  }

  // ---------- self-test against published vectors ----------
  async function selfTest() {
    const r = {};
    r.keccakEmpty = hex(keccak256(new Uint8Array(0))) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
    r.ripemdEmpty = hex(ripemd160(new Uint8Array(0))) === '9c1185a5c5e9fc54612808977ee8f548b2258d31';
    const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    r.checksum = (await validateMnemonic(m)).ok;
    r.checksumRejects = !(await validateMnemonic(m.replace('about', 'abandon'))).ok;
    const seed = await mnemonicToSeed(m, '');
    r.seed = hex(seed).startsWith('5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1');
    r.btcLegacy = (await deriveAddresses(seed, 'btc-legacy', 1))[0].address === '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA';
    r.btcSegwit = (await deriveAddresses(seed, 'btc-segwit', 1))[0].address === 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';
    r.eth = (await deriveAddresses(seed, 'eth', 1))[0].address === '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
    // SLIP-0010 ed25519 test vector 1
    const s10seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const n0 = await slip10Path(s10seed, [H + 0]);
    r.slip10Priv = hex(n0.k) === '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3';
    r.slip10Pub = hex(await ed25519Pub(n0.k)) === '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c';
    // openssl roundtrip
    const blob = await opensslEncrypt('hello seeds', 'pw', 1000);
    r.opensslHeader = new TextDecoder().decode(blob.slice(0, 8)) === 'Salted__';
    r.opensslRoundtrip = (await opensslDecrypt(blob, 'pw', 1000)) === 'hello seeds';
    r.allPass = Object.values(r).every(Boolean);
    return r;
  }

  window.SeedCrypto = {
    validateMnemonic, mnemonicToSeed, normalizeMnemonic, suggest,
    deriveAddresses, CHAINS, opensslEncrypt, opensslDecrypt, selfTest,
    WORDS,
  };
})();
