/* SeedCrypto — offline BIP39 validation + address derivation + OpenSSL-compatible
   encryption. No network calls. Built on the audited @scure/@noble libraries, with
   the OpenSSL envelope done via WebCrypto. `selfTest()` re-checks the published
   test vectors at startup. */

import { wordlist } from '@scure/bip39/wordlists/english'
import { mnemonicToSeedSync } from '@scure/bip39'
import { HDKey } from '@scure/bip32'
import { secp256k1 } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha2'
import { sha512 } from '@noble/hashes/sha2'
import { hmac } from '@noble/hashes/hmac'
import { keccak_256 } from '@noble/hashes/sha3'
import { ripemd160 } from '@noble/hashes/legacy'
import { bech32, base58, createBase58check } from '@scure/base'

const te = new TextEncoder()
const base58check = createBase58check(sha256)

// SHA-256 of the official BIP39 english.txt (newline-joined words + trailing newline)
const WORDLIST_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'

export const WORDS: readonly string[] = wordlist
const WORDSET = new Set(wordlist)

// Common typographic characters mapped to ASCII equivalents (dashes, smart
// quotes, ellipsis, non-breaking/thin spaces, bullets). Anything not listed
// here is escaped by asciify() instead.
const ASCII_MAP: Record<string, string> = {
  '‐': '-', '‑': '-', '‒': '-', '–': '-', // hyphen/figure/en dash
  '—': '--', '―': '--', '−': '-',              // em dash / bar / minus
  '‘': "'", '’': "'", '‚': "'", '‛': "'", // single quotes
  '“': '"', '”': '"', '„': '"', '‟': '"', // double quotes
  '…': '...',                                              // ellipsis
  ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ', // non-breaking / thin spaces
  '•': '*', '·': '.',                                // bullet / middle dot
}

/** Force a string to 7-bit ASCII: transliterate common typographic characters,
    and escape anything else as `\uXXXX` (lossless — nothing is dropped). */
export function asciify(text: string): string {
  let out = ''
  for (const ch of text) {
    const code = ch.codePointAt(0)!
    if (code <= 0x7f) out += ch
    else if (ASCII_MAP[ch] !== undefined) out += ASCII_MAP[ch]
    else out += code <= 0xffff ? '\\u' + code.toString(16).padStart(4, '0') : '\\u{' + code.toString(16) + '}'
  }
  return out
}

const hex = (u8: Uint8Array) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
const concat = (...arrs: Uint8Array[]) => {
  const out = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0))
  let o = 0
  for (const a of arrs) { out.set(a, o); o += a.length }
  return out
}

// ---------- BIP39 ----------

export interface Validation {
  words: string[]
  /** indices (0-based) of words not in the wordlist */
  badWords: number[]
  lengthOk: boolean
  checksumOk: boolean
  ok: boolean
}

export function normalizeMnemonic(text: string): string[] {
  return text.normalize('NFKD').trim().toLowerCase().split(/\s+/).filter(Boolean)
}

export function validateMnemonic(text: string): Validation {
  const words = normalizeMnemonic(text)
  const res: Validation = { words, badWords: [], lengthOk: false, checksumOk: false, ok: false }
  if (!words.length) return res
  words.forEach((w, i) => { if (!WORDSET.has(w)) res.badWords.push(i) })
  res.lengthOk = [12, 15, 18, 21, 24].includes(words.length)
  if (res.badWords.length || !res.lengthOk) return res
  let bits = ''
  for (const w of words) bits += WORDS.indexOf(w).toString(2).padStart(11, '0')
  const entBits = (words.length * 11 * 32) / 33
  const csBits = words.length * 11 - entBits
  const entropy = new Uint8Array(entBits / 8)
  for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2)
  const csExpected = sha256(entropy)[0].toString(2).padStart(8, '0').slice(0, csBits)
  res.checksumOk = bits.slice(entBits) === csExpected
  res.ok = res.checksumOk
  return res
}

export function mnemonicToSeed(text: string, passphrase: string): Uint8Array {
  return mnemonicToSeedSync(normalizeMnemonic(text).join(' '), passphrase || '')
}

export function suggest(prefix: string, limit = 8): string[] {
  prefix = prefix.toLowerCase()
  if (!prefix) return []
  const out: string[] = []
  for (const w of WORDS) {
    if (w.startsWith(prefix)) { out.push(w); if (out.length >= limit) break }
  }
  return out
}

// ---------- SLIP-0010 ed25519 (hardened-only, for Solana) ----------

interface Slip10Node { k: Uint8Array; c: Uint8Array }
const H = 0x80000000
const ser32 = (i: number) =>
  new Uint8Array([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff])

function slip10Path(seed: Uint8Array, path: number[]): Slip10Node {
  const I0 = hmac(sha512, te.encode('ed25519 seed'), seed)
  let node: Slip10Node = { k: I0.slice(0, 32), c: I0.slice(32) }
  for (const i of path) {
    const I = hmac(sha512, node.c, concat(new Uint8Array([0]), node.k, ser32(i)))
    node = { k: I.slice(0, 32), c: I.slice(32) }
  }
  return node
}

// ---------- address builders ----------

function btcLegacyAddress(pub33: Uint8Array): string {
  return base58check.encode(concat(new Uint8Array([0]), ripemd160(sha256(pub33))))
}

function btcSegwitAddress(pub33: Uint8Array): string {
  const h160 = ripemd160(sha256(pub33))
  return bech32.encode('bc', [0, ...bech32.toWords(h160)])
}

// P2SH-wrapped SegWit (BIP49): pay-to-script-hash of the P2WPKH redeem script
// `OP_0 <20-byte pubkey hash>`. Yields a mainnet "3…" address.
function btcNestedAddress(pub33: Uint8Array): string {
  const redeem = concat(new Uint8Array([0x00, 0x14]), ripemd160(sha256(pub33)))
  const scriptHash = ripemd160(sha256(redeem))
  return base58check.encode(concat(new Uint8Array([0x05]), scriptHash))
}

function ethAddress(pub64: Uint8Array): string {
  const raw = hex(keccak_256(pub64).slice(12))
  const h = hex(keccak_256(te.encode(raw)))
  let out = '0x'
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? raw[i].toUpperCase() : raw[i]
  return out
}

function tronAddress(pub64: Uint8Array): string {
  return base58check.encode(concat(new Uint8Array([0x41]), keccak_256(pub64).slice(12)))
}

// ---------- chains & derivation ----------

export type ChainKey = 'btc-segwit' | 'btc-nested' | 'btc-legacy' | 'eth' | 'sol' | 'tron'

export const CHAINS: Record<ChainKey, { name: string; pathLabel: (i: number) => string }> = {
  'btc-segwit': { name: 'Bitcoin — Native SegWit (BIP84)', pathLabel: (i) => `m/84'/0'/0'/0/${i}` },
  'btc-nested': { name: 'Bitcoin — Nested SegWit / P2SH (BIP49)', pathLabel: (i) => `m/49'/0'/0'/0/${i}` },
  'btc-legacy': { name: 'Bitcoin — Legacy (BIP44)', pathLabel: (i) => `m/44'/0'/0'/0/${i}` },
  eth: { name: 'Ethereum (BIP44)', pathLabel: (i) => `m/44'/60'/0'/0/${i}` },
  sol: { name: 'Solana (BIP44 / ed25519)', pathLabel: (i) => `m/44'/501'/${i}'/0'` },
  tron: { name: 'Tron (BIP44)', pathLabel: (i) => `m/44'/195'/0'/0/${i}` },
}

export interface DerivedAddress {
  index: number
  path: string
  address: string
  /** wallet-importable private key: WIF (Bitcoin), 0x-hex (Ethereum),
      hex (Tron), base58 64-byte keypair (Solana / Phantom format) */
  priv: string
}

export interface AccountDerivation {
  /** account-level extended public key (zpub for BIP84, xpub for BIP44) for
      watch-only balance discovery; null for ed25519 chains, which have no
      public derivation */
  xpub: string | null
  addresses: DerivedAddress[]
}

// SLIP-0132 extended-key version bytes: BIP84 zprv/zpub, BIP49 yprv/ypub.
// BIP44 uses scure's xprv/xpub default.
const ZPRV_ZPUB = { private: 0x04b2430c, public: 0x04b24746 }
const YPRV_YPUB = { private: 0x049d7878, public: 0x049d7cb2 }

/** WIF for a compressed-pubkey private key (mainnet). */
const toWif = (key: Uint8Array) =>
  base58check.encode(concat(new Uint8Array([0x80]), key, new Uint8Array([0x01])))

const yieldToUi = () => new Promise<void>((r) => setTimeout(r, 0))

/** Derive `count` receive addresses with their private keys, plus the
    account xpub. Async so the UI can show progress and drop stale results;
    yields to the event loop periodically. */
export async function deriveAddresses(
  seed: Uint8Array, chain: ChainKey, count: number
): Promise<AccountDerivation> {
  const addresses: DerivedAddress[] = []
  if (chain === 'sol') {
    for (let i = 0; i < count; i++) {
      const node = slip10Path(seed, [H + 44, H + 501, H + i, H + 0])
      const pub = ed25519.getPublicKey(node.k)
      addresses.push({
        index: i,
        path: CHAINS.sol.pathLabel(i),
        address: base58.encode(pub),
        priv: base58.encode(concat(node.k, pub)),
      })
      if (i % 5 === 4) await yieldToUi()
    }
    return { xpub: null, addresses }
  }
  const purpose = chain === 'btc-segwit' ? 84 : chain === 'btc-nested' ? 49 : 44
  const coin = chain === 'eth' ? 60 : chain === 'tron' ? 195 : 0
  const versions = chain === 'btc-segwit' ? ZPRV_ZPUB : chain === 'btc-nested' ? YPRV_YPUB : undefined
  const master = HDKey.fromMasterSeed(seed, versions)
  const acct = master.derive(`m/${purpose}'/${coin}'/0'`)
  const external = acct.deriveChild(0)
  for (let i = 0; i < count; i++) {
    const node = external.deriveChild(i)
    const pub33 = node.publicKey!
    const key = node.privateKey!
    let address: string, priv: string
    if (chain === 'btc-segwit' || chain === 'btc-nested' || chain === 'btc-legacy') {
      address = chain === 'btc-segwit' ? btcSegwitAddress(pub33)
        : chain === 'btc-nested' ? btcNestedAddress(pub33)
        : btcLegacyAddress(pub33)
      priv = toWif(key)
    } else {
      const pub64 = secp256k1.ProjectivePoint.fromHex(pub33).toRawBytes(false).slice(1)
      address = chain === 'eth' ? ethAddress(pub64) : tronAddress(pub64)
      priv = chain === 'eth' ? '0x' + hex(key) : hex(key)
    }
    addresses.push({ index: i, path: CHAINS[chain].pathLabel(i), address, priv })
    if (i % 5 === 4) await yieldToUi()
  }
  return { xpub: acct.publicExtendedKey, addresses }
}

// ---------- OpenSSL-compatible encryption ----------
// Byte-identical to: openssl enc -aes-256-cbc -pbkdf2 -iter <iter> -salt
// Format: "Salted__" + 8 salt bytes + AES-256-CBC ciphertext (PKCS#7).
// Key material = PBKDF2-HMAC-SHA256(pass, salt, iter, 48B) → 32B key + 16B IV.

async function pbkdf2Subtle(pass: Uint8Array, salt: Uint8Array, iterations: number, bytes: number) {
  const k = await crypto.subtle.importKey('raw', pass as BufferSource, 'PBKDF2', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, k, bytes * 8))
}

export async function opensslEncrypt(text: string, passphrase: string, iterations = 100000): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(8))
  const keyiv = await pbkdf2Subtle(te.encode(passphrase), salt, iterations, 48)
  const key = await crypto.subtle.importKey('raw', keyiv.slice(0, 32) as BufferSource, 'AES-CBC', false, ['encrypt'])
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: keyiv.slice(32, 48) as BufferSource }, key, te.encode(text)))
  return concat(te.encode('Salted__'), salt, ct)
}

/** Wrap ciphertext the way `openssl enc -a` does (base64, 64-char lines),
    preceded by `#` comment lines. OpenSSL's base64 decoder skips the comment
    lines on decrypt, so the file stays a plain
    `openssl enc -d ... -a -in seeds.md.enc` away from readable. */
export function armor(bytes: Uint8Array, comments: string[]): string {
  let b64 = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    b64 += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  b64 = btoa(b64)
  // a newline inside a comment would end the `#` line and corrupt the base64
  // block, so flatten any that sneak in (e.g. from a pasted envelope title);
  // asciify so the whole file stays 7-bit ASCII
  const lines = comments.map((c) => '# ' + asciify(c.replace(/[\r\n]+/g, ' ')))
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64))
  return lines.join('\n') + '\n'
}

/** Inverse of {@link armor}: drop `#` comment lines, join and decode base64. */
export function dearmor(text: string): Uint8Array {
  const b64 = text.split('\n').filter((l) => !l.startsWith('#')).join('').replace(/\s+/g, '')
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

export async function opensslDecrypt(blob: Uint8Array, passphrase: string, iterations = 100000): Promise<string> {
  const salt = blob.slice(8, 16)
  const keyiv = await pbkdf2Subtle(te.encode(passphrase), salt, iterations, 48)
  const key = await crypto.subtle.importKey('raw', keyiv.slice(0, 32) as BufferSource, 'AES-CBC', false, ['decrypt'])
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: keyiv.slice(32, 48) as BufferSource }, key, blob.slice(16) as BufferSource)
  return new TextDecoder().decode(pt)
}

// ---------- startup self-test against published vectors ----------

export async function selfTest(): Promise<Record<string, boolean>> {
  const r: Record<string, boolean> = {}
  r.wordlist = WORDS.length === 2048 && hex(sha256(te.encode(WORDS.join('\n') + '\n'))) === WORDLIST_SHA256
  r.keccakEmpty = hex(keccak_256(new Uint8Array(0))) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  r.ripemdEmpty = hex(ripemd160(new Uint8Array(0))) === '9c1185a5c5e9fc54612808977ee8f548b2258d31'
  const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  r.checksum = validateMnemonic(m).ok
  r.checksumRejects = !validateMnemonic(m.replace('about', 'abandon')).ok
  const seed = mnemonicToSeed(m, '')
  r.seed = hex(seed).startsWith('5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1')
  r.btcLegacy = (await deriveAddresses(seed, 'btc-legacy', 1)).addresses[0].address === '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'
  const segwit = await deriveAddresses(seed, 'btc-segwit', 1)
  r.btcSegwit = segwit.addresses[0].address === 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'
  // BIP84 spec test vectors for the same mnemonic: account zpub + first WIF
  r.btcZpub = segwit.xpub === 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'
  r.btcWif = segwit.addresses[0].priv === 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'
  // BIP49 (P2SH-wrapped SegWit, "3…"): canonical address + account ypub
  const nested = await deriveAddresses(seed, 'btc-nested', 1)
  r.btcNested = nested.addresses[0].address === '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf'
  r.btcYpub = nested.xpub === 'ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP'
  r.eth = (await deriveAddresses(seed, 'eth', 1)).addresses[0].address === '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
  // SLIP-0010 ed25519 test vector 1, chain m/0'
  const s10 = slip10Path(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]), [H + 0])
  r.slip10Priv = hex(s10.k) === '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'
  r.slip10Pub = hex(ed25519.getPublicKey(s10.k)) === '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'
  const blob = await opensslEncrypt('hello seeds', 'pw', 1000)
  r.opensslHeader = new TextDecoder().decode(blob.slice(0, 8)) === 'Salted__'
  r.opensslRoundtrip = (await opensslDecrypt(blob, 'pw', 1000)) === 'hello seeds'
  const armored = armor(blob, ['a comment'])
  r.armorHeader = armored.startsWith('# a comment\nU2FsdGVk') // base64("Salted__")
  r.armorRoundtrip = (await opensslDecrypt(dearmor(armored), 'pw', 1000)) === 'hello seeds'
  r.allPass = Object.values(r).every(Boolean)
  return r
}
