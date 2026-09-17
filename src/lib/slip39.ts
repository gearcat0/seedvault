/* SLIP-0039 (Shamir's Secret-Sharing for Mnemonic Codes) — share validation,
   metadata decoding and master-secret recovery, implemented from the spec and
   checked against every vector in Trezor's official vectors.json (see
   test/slip39.test.mjs and slip39SelfTest()). Recovery only: this app backs up
   shares that already exist; it does not generate or split secrets. */

import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha2'
import { SLIP39_WORDS } from './slip39-words'
import { WORDS as BIP39_WORDS, normalizeMnemonic } from './seedcrypto'

const te = new TextEncoder()
const SLIP39_WORDSET = new Set(SLIP39_WORDS)
const BIP39_WORDSET = new Set(BIP39_WORDS)

// SHA-256 of the official wordlist.txt (newline-joined + trailing newline)
export const SLIP39_WORDLIST_SHA256 = 'bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3'

// ---------- share format constants (SLIP-0039) ----------

const RADIX_BITS = 10
const ID_BITS = 15
const EXT_BITS = 1
const EXP_BITS = 4
const ID_EXP_WORDS = 2 // identifier + extendable flag + iteration exponent
const CHECKSUM_WORDS = 3
const METADATA_WORDS = ID_EXP_WORDS + 2 + CHECKSUM_WORDS // 7
const MIN_VALUE_WORDS = 13 // 128-bit minimum secret
export const SHARE_LENGTHS = [20, 33] // the two standard lengths (128/256-bit)

const DIGEST_BYTES = 4
const SECRET_INDEX = 255
const DIGEST_INDEX = 254
const BASE_ITERATIONS = 10000
const ROUNDS = 4

// ---------- rs1024 checksum ----------

const RS_GEN = [
  0x00e0e040, 0x01c1c080, 0x03838100, 0x07070200, 0x0e0e0009,
  0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
]

function rs1024Polymod(values: number[]): number {
  let chk = 1
  for (const v of values) {
    const b = chk >> 20
    chk = ((chk & 0xfffff) << 10) ^ v
    for (let i = 0; i < 10; i++) if ((b >> i) & 1) chk ^= RS_GEN[i]
  }
  return chk
}

const customization = (extendable: boolean) =>
  Array.from(te.encode(extendable ? 'shamir_extendable' : 'shamir'))

function rs1024Verify(extendable: boolean, data: number[]): boolean {
  return rs1024Polymod(customization(extendable).concat(data)) === 1
}

// ---------- GF(256), generator 3, modulus x^8+x^4+x^3+x+1 ----------

const EXP = new Uint8Array(255)
const LOG = new Uint8Array(256)
{
  let poly = 1
  for (let i = 0; i < 255; i++) {
    EXP[i] = poly
    LOG[poly] = i
    poly = (poly << 1) ^ poly // multiply by 3
    if (poly & 0x100) poly ^= 0x11b
  }
}

type Point = { x: number; y: Uint8Array }

/** Lagrange interpolation of the share polynomial at `x`. */
function interpolate(points: Point[], x: number): Uint8Array {
  const xs = new Set(points.map((p) => p.x))
  if (xs.size !== points.length) throw new Error('Invalid set of shares — duplicate member index with different values.')
  const exact = points.find((p) => p.x === x)
  if (exact) return exact.y
  const len = points[0].y.length
  if (points.some((p) => p.y.length !== len)) throw new Error('Invalid set of shares — all shares must have the same length.')
  let logProd = 0
  for (const p of points) logProd += LOG[p.x ^ x]
  const result = new Uint8Array(len)
  for (const p of points) {
    let sum = 0
    for (const o of points) if (o.x !== p.x) sum += LOG[p.x ^ o.x]
    const logBasis = (((logProd - LOG[p.x ^ x] - sum) % 255) + 255) % 255
    for (let k = 0; k < len; k++) {
      result[k] ^= p.y[k] === 0 ? 0 : EXP[(LOG[p.y[k]] + logBasis) % 255]
    }
  }
  return result
}

function recoverSecret(threshold: number, points: Point[]): Uint8Array {
  if (threshold === 1) return points[0].y
  const secret = interpolate(points, SECRET_INDEX)
  const digestShare = interpolate(points, DIGEST_INDEX)
  const digest = digestShare.slice(0, DIGEST_BYTES)
  const random = digestShare.slice(DIGEST_BYTES)
  const expected = hmac(sha256, random, secret).slice(0, DIGEST_BYTES)
  if (digest.some((b, i) => b !== expected[i])) {
    throw new Error('Invalid digest of the shared secret — a share is from a different secret or corrupted.')
  }
  return secret
}

// ---------- share decoding ----------

export interface Slip39Share {
  words: string[]
  /** indices (0-based) of words not in the SLIP39 wordlist */
  badWords: number[]
  lengthOk: boolean
  checksumOk: boolean
  ok: boolean
  /** the whole phrase reads as a BIP39 mnemonic instead */
  looksLikeBip39: boolean
  /** human-readable problem when !ok */
  error?: string
  // decoded metadata (present when ok)
  id?: number
  extendable?: boolean
  iterationExp?: number
  groupIndex?: number
  groupThreshold?: number
  groupCount?: number
  memberIndex?: number
  memberThreshold?: number
  /** share value bytes (present when ok) */
  value?: Uint8Array
}

/** True when the words read as a SLIP39 share: a standard share length and
    every word from the SLIP39 wordlist. Used by the BIP39 editor to redirect. */
export function looksLikeSlip39(words: string[]): boolean {
  return SHARE_LENGTHS.includes(words.length) && words.every((w) => SLIP39_WORDSET.has(w))
}

export function validateShare(text: string): Slip39Share {
  const words = normalizeMnemonic(text)
  const res: Slip39Share = { words, badWords: [], lengthOk: false, checksumOk: false, ok: false, looksLikeBip39: false }
  if (!words.length) return res
  words.forEach((w, i) => { if (!SLIP39_WORDSET.has(w)) res.badWords.push(i) })
  if ([12, 15, 18, 21, 24].includes(words.length) && words.every((w) => BIP39_WORDSET.has(w))) {
    res.looksLikeBip39 = true
    res.error = 'This reads as a BIP39 seed phrase (' + words.length + ' words from the BIP39 wordlist) — SLIP39 shares have 20 or 33 words. Use a regular seed phrase entry instead.'
    return res
  }
  if (res.badWords.length) {
    res.error = 'Not in the SLIP39 wordlist: ' + res.badWords.map((i) => '#' + (i + 1) + ' "' + words[i] + '"').join(', ') + '.'
    return res
  }
  const padding = (RADIX_BITS * (words.length - METADATA_WORDS)) % 16
  res.lengthOk = words.length >= METADATA_WORDS + MIN_VALUE_WORDS && padding <= 8
  if (!res.lengthOk) {
    res.error = 'A SLIP39 share has 20 words (128-bit) or 33 words (256-bit) — currently ' + words.length + '.'
    return res
  }
  const data = words.map((w) => SLIP39_WORDS.indexOf(w))
  const idExp = data[0] * 1024 + data[1]
  const extendable = ((idExp >> EXP_BITS) & 1) === 1
  if (!rs1024Verify(extendable, data)) {
    res.error = 'All words are valid but the share checksum fails — a word is wrong or two are swapped. Re-check against your written copy.'
    return res
  }
  res.checksumOk = true
  res.id = idExp >> (EXT_BITS + EXP_BITS)
  res.extendable = extendable
  res.iterationExp = idExp & ((1 << EXP_BITS) - 1)
  const tmp = data[2] * 1024 + data[3]
  res.groupIndex = (tmp >> 16) & 0xf
  res.groupThreshold = ((tmp >> 12) & 0xf) + 1
  res.groupCount = ((tmp >> 8) & 0xf) + 1
  res.memberIndex = (tmp >> 4) & 0xf
  res.memberThreshold = (tmp & 0xf) + 1
  if (res.groupCount < res.groupThreshold) {
    res.error = 'Invalid share: group threshold (' + res.groupThreshold + ') greater than group count (' + res.groupCount + ').'
    return res
  }
  // value words → bytes; the left padding bits must be zero
  const valueWords = data.slice(ID_EXP_WORDS + 2, -CHECKSUM_WORDS)
  const valueBits = RADIX_BITS * valueWords.length
  const byteLen = (valueBits - padding) / 8
  let bits = ''
  for (const v of valueWords) bits += v.toString(2).padStart(RADIX_BITS, '0')
  if (padding > 0 && parseInt(bits.slice(0, padding) || '0', 2) !== 0) {
    res.error = 'Invalid share padding — the share value is malformed.'
    return res
  }
  const value = new Uint8Array(byteLen)
  for (let i = 0; i < byteLen; i++) value[i] = parseInt(bits.slice(padding + i * 8, padding + i * 8 + 8), 2)
  res.value = value
  res.ok = true
  return res
}

// ---------- combining ----------

export interface Slip39GroupStatus {
  index: number
  /** distinct valid member shares entered */
  have: number
  need: number
}

export interface Slip39Status {
  /** enough consistent shares to attempt recovery */
  complete: boolean
  /** blocking problem (inconsistent set), independent of completeness */
  error: string | null
  /** what is still missing, e.g. "1 more share from group 2" */
  missing: string | null
  id?: number
  extendable?: boolean
  groupThreshold?: number
  groupCount?: number
  groups: Slip39GroupStatus[]
  /** master-secret strength in bits once known */
  strengthBits?: number
}

/** Assess a set of (already individually validated) shares: consistency,
    per-group progress, and whether recovery can be attempted. */
export function assessShares(shares: Slip39Share[]): Slip39Status {
  const valid = shares.filter((s) => s.ok)
  const st: Slip39Status = { complete: false, error: null, missing: null, groups: [] }
  if (!valid.length) { st.missing = 'no valid shares yet'; return st }
  const first = valid[0]
  st.id = first.id; st.extendable = first.extendable
  st.groupThreshold = first.groupThreshold; st.groupCount = first.groupCount
  st.strengthBits = first.value!.length * 8
  for (const s of valid) {
    if (s.id !== first.id || s.extendable !== first.extendable || s.iterationExp !== first.iterationExp) {
      st.error = 'Shares are from different backups — all shares must begin with the same two words (same identifier).'
      return st
    }
    if (s.groupThreshold !== first.groupThreshold || s.groupCount !== first.groupCount) {
      st.error = 'Shares disagree on the group threshold/count — they are not from the same backup.'
      return st
    }
    if (s.value!.length !== first.value!.length) {
      st.error = 'Shares have different lengths — they are not from the same backup.'
      return st
    }
  }
  const byGroup = new Map<number, Map<number, Slip39Share>>()
  for (const s of valid) {
    let g = byGroup.get(s.groupIndex!)
    if (!g) byGroup.set(s.groupIndex!, (g = new Map()))
    const prev = g.get(s.memberIndex!)
    if (prev && prev.value!.some((b, i) => b !== s.value![i])) {
      st.error = 'Two different shares claim the same position (group ' + (s.groupIndex! + 1) + ', member ' + (s.memberIndex! + 1) + ') — one of them is wrong.'
      return st
    }
    g.set(s.memberIndex!, s)
    const mt = g.values().next().value!.memberThreshold
    if (s.memberThreshold !== mt) {
      st.error = 'Shares within group ' + (s.groupIndex! + 1) + ' disagree on the member threshold — they are not from the same backup.'
      return st
    }
  }
  for (const [gi, members] of [...byGroup.entries()].sort((a, b) => a[0] - b[0])) {
    st.groups.push({ index: gi, have: members.size, need: members.values().next().value!.memberThreshold! })
  }
  const completeGroups = st.groups.filter((g) => g.have >= g.need)
  if (completeGroups.length >= st.groupThreshold!) {
    st.complete = true
  } else {
    const parts: string[] = []
    for (const g of st.groups) {
      if (g.have < g.need) parts.push((g.need - g.have) + ' more from group ' + (g.index + 1))
    }
    const groupsMissing = st.groupThreshold! - st.groups.length
    if (groupsMissing > 0 && st.groups.length < st.groupCount!) {
      parts.push(st.groupCount! > 1 ? 'shares from ' + groupsMissing + ' more group' + (groupsMissing > 1 ? 's' : '') : 'more shares')
    }
    st.missing = parts.length ? 'need ' + parts.join(', ') : 'need more shares'
  }
  return st
}

// ---------- master-secret decryption (4-round Feistel, PBKDF2-SHA256) ----------

async function pbkdf2(pass: Uint8Array, salt: Uint8Array, iterations: number, bytes: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', pass as BufferSource, 'PBKDF2', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' }, k, bytes * 8))
}

const concat = (...arrs: Uint8Array[]) => {
  const out = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0))
  let o = 0
  for (const a of arrs) { out.set(a, o); o += a.length }
  return out
}

async function decryptEms(
  ems: Uint8Array, passphrase: string, iterationExp: number, id: number, extendable: boolean
): Promise<Uint8Array> {
  const salt = extendable ? new Uint8Array(0) : concat(te.encode('shamir'), new Uint8Array([id >> 8, id & 0xff]))
  const iterations = (BASE_ITERATIONS << iterationExp) / ROUNDS
  const pw = te.encode(passphrase)
  let l = ems.slice(0, ems.length >> 1)
  let r = ems.slice(ems.length >> 1)
  for (let i = ROUNDS - 1; i >= 0; i--) {
    const f = await pbkdf2(concat(new Uint8Array([i]), pw), concat(salt, r), iterations, r.length)
    const next = l.map((b, k) => b ^ f[k])
    l = r
    r = next
  }
  return concat(r, l)
}

/** SLIP39 passphrases must be printable ASCII (0x20–0x7E). */
export function passphraseOk(pass: string): boolean {
  return [...pass].every((c) => { const x = c.codePointAt(0)!; return x >= 0x20 && x <= 0x7e })
}

/** Recover the master secret from a complete, consistent set of shares.
    Throws with a human-readable message on any inconsistency. */
export async function combineShares(texts: string[], passphrase = ''): Promise<Uint8Array> {
  const shares = texts.map(validateShare)
  const bad = shares.find((s) => !s.ok)
  if (bad) throw new Error(bad.error || 'invalid share')
  const st = assessShares(shares)
  if (st.error) throw new Error(st.error)
  if (!st.complete) throw new Error('Insufficient shares: ' + (st.missing || 'need more shares'))
  // exactly the needed shares: first memberThreshold distinct members of the
  // first groupThreshold complete groups
  const byGroup = new Map<number, Map<number, Slip39Share>>()
  for (const s of shares) {
    let g = byGroup.get(s.groupIndex!)
    if (!g) byGroup.set(s.groupIndex!, (g = new Map()))
    if (!g.has(s.memberIndex!)) g.set(s.memberIndex!, s)
  }
  const groupPoints: Point[] = []
  for (const [gi, members] of [...byGroup.entries()].sort((a, b) => a[0] - b[0])) {
    const need = members.values().next().value!.memberThreshold!
    if (members.size < need) continue
    const pts = [...members.values()].slice(0, need).map((s) => ({ x: s.memberIndex!, y: s.value! }))
    groupPoints.push({ x: gi, y: recoverSecret(need, pts) })
    if (groupPoints.length === st.groupThreshold) break
  }
  const first = shares[0]
  const ems = recoverSecret(st.groupThreshold!, groupPoints)
  return decryptEms(ems, passphrase, first.iterationExp!, first.id!, first.extendable!)
}

export function suggestSlip39(prefix: string, limit = 8): string[] {
  prefix = prefix.toLowerCase()
  if (!prefix) return []
  const out: string[] = []
  for (const w of SLIP39_WORDS) {
    if (w.startsWith(prefix)) { out.push(w); if (out.length >= limit) break }
  }
  return out
}

// ---------- startup self-test (vectors from Trezor's vectors.json) ----------

const hex = (u8: Uint8Array) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

export async function slip39SelfTest(): Promise<Record<string, boolean>> {
  const r: Record<string, boolean> = {}
  r.slip39Wordlist = SLIP39_WORDS.length === 1024 &&
    hex(sha256(te.encode(SLIP39_WORDS.join('\n') + '\n'))) === SLIP39_WORDLIST_SHA256
  // vector 1: valid mnemonic without sharing (128 bits), passphrase TREZOR
  const single = 'duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard'
  r.slip39Single = hex(await combineShares([single], 'TREZOR')) === 'bb54aac4b89dc868ba37d9cc21b2cece'
  // vector 2: one word changed — checksum must reject
  r.slip39BadChecksum = !validateShare(single.replace('keyboard', 'kidney')).ok
  // vector 17: threshold number of groups and members in each group (128 bits)
  const grouped = [
    'eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter',
    'eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup',
    'eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces',
    'eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate',
    'eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing',
  ]
  r.slip39Groups = hex(await combineShares(grouped, 'TREZOR')) === '7c3397a292a5941682d7a4ae2d898d11'
  const info = validateShare(single)
  r.slip39Decode = info.ok && info.groupThreshold === 1 && info.memberThreshold === 1 && info.value!.length === 16
  r.slip39DetectsBip39 = validateShare('legal winner thank year wave sausage worth useful legal winner thank yellow').looksLikeBip39
  r.slip39Detect = looksLikeSlip39(normalizeMnemonic(single))
  return r
}
