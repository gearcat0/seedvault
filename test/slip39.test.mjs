// SLIP-0039 — every vector from Trezor's official vectors.json must pass:
// valid sets recover the expected master secret (passphrase "TREZOR"), and the
// master secret must act as the BIP32 seed producing the vector's xprv;
// invalid sets must throw.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assessShares, combineShares, looksLikeSlip39, passphraseOk, slip39SelfTest,
  suggestSlip39, validateShare,
} from '../dist/test/slip39.mjs'
import { validateMnemonic, normalizeMnemonic } from '../dist/test/seedcrypto.mjs'
import { HDKey } from '@scure/bip32'

const vectors = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'slip39-vectors.json'), 'utf8'))
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

test('official vectors.json: all ' + vectors.length + ' vectors', async () => {
  for (const [name, mnemonics, ms, xprv] of vectors) {
    if (ms) {
      const secret = await combineShares(mnemonics, 'TREZOR')
      assert.equal(hex(secret), ms, name)
      // the master secret is the BIP32 seed (how Trezor derives from SLIP39)
      assert.equal(HDKey.fromMasterSeed(secret).privateExtendedKey, xprv, name + ' (xprv)')
    } else {
      await assert.rejects(() => combineShares(mnemonics, 'TREZOR'), undefined, name)
    }
  }
})

test('share metadata decodes (2-of-3, group 1 of 1)', () => {
  const s = validateShare(vectors[3][1][0]) // "4. Basic sharing 2-of-3"
  assert.equal(s.ok, true)
  assert.equal(s.groupThreshold, 1)
  assert.equal(s.groupCount, 1)
  assert.equal(s.memberThreshold, 2)
  assert.equal(s.value.length, 16)
})

test('assessShares reports progress and inconsistencies', () => {
  const [a, b] = vectors[3][1] // 2-of-3: one share is not enough
  const one = assessShares([validateShare(a)])
  assert.equal(one.complete, false)
  assert.match(one.missing, /1 more from group 1/)
  const two = assessShares([validateShare(a), validateShare(b)])
  assert.equal(two.complete, true)
  assert.equal(two.error, null)
  // mixing in a share from a different backup (different identifier)
  const foreign = validateShare(vectors[0][1][0])
  assert.match(assessShares([validateShare(a), foreign]).error, /same identifier/)
})

test('wrong passphrase still recovers, but a different secret (by design)', async () => {
  const secret = await combineShares(vectors[3][1].slice(0, 2), 'not-trezor')
  assert.notEqual(hex(secret), vectors[3][2])
  assert.equal(secret.length, 16)
})

test('cross-detection: BIP39 <-> SLIP39', () => {
  const bip39 = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
  const slip39 = vectors[0][1][0]
  // a BIP39 phrase pasted into a SLIP39 input
  const asShare = validateShare(bip39)
  assert.equal(asShare.ok, false)
  assert.equal(asShare.looksLikeBip39, true)
  assert.match(asShare.error, /BIP39 seed phrase/)
  // a SLIP39 share pasted into the BIP39 input
  assert.equal(looksLikeSlip39(normalizeMnemonic(slip39)), true)
  assert.equal(validateMnemonic(slip39).ok, false)
  // and a normal BIP39 phrase does not trip the detector
  assert.equal(looksLikeSlip39(normalizeMnemonic(bip39)), false)
})

test('share validation failure modes are distinguished', () => {
  const good = vectors[0][1][0]
  const typo = validateShare(good.replace('duckling', 'ducklin'))
  assert.deepEqual(typo.badWords, [0])
  assert.match(typo.error, /Not in the SLIP39 wordlist/)
  const short = validateShare('academic academic academic')
  assert.equal(short.lengthOk, false)
  const swapped = good.split(' ')
  ;[swapped[4], swapped[5]] = [swapped[5], swapped[4]]
  const badCs = validateShare(swapped.join(' '))
  assert.equal(badCs.badWords.length, 0)
  assert.equal(badCs.checksumOk, false)
  assert.match(badCs.error, /checksum fails/)
})

test('passphrase rules and autocomplete', () => {
  assert.equal(passphraseOk('correct horse'), true)
  assert.equal(passphraseOk('café'), false)
  assert.deepEqual(suggestSlip39('ducklin'), ['duckling'])
})

test('slip39SelfTest: every vector passes', async () => {
  const r = await slip39SelfTest()
  for (const [k, ok] of Object.entries(r)) assert.equal(ok, true, `vector ${k} failed`)
})

test('markdown export: slip39 entry with shares, groups and passphrase', async () => {
  const { buildMarkdown } = await import('../dist/test/markdown.mjs')
  const texts = vectors[3][1].slice(0, 2) // 2-of-3, both shares held
  const entry = {
    id: 1, kind: 'slip39', label: 'Shamir backup', mnemonic: '', passphrase: 'pw',
    xpub: '', xpubInfo: null, note: 'share 3 is with the lawyer', validation: null,
    slip39Shares: [...texts, ''], slip39: null, derivations: [],
  }
  const md = buildMarkdown([entry])
  assert.match(md, /SLIP39 \(Shamir\) backup, 2 shares, 128-bit master secret \(identifier \d+\)/)
  assert.match(md, /Group 1: 2 shares recorded here, any 2 of the group recover it/)
  assert.match(md, /SLIP39 passphrase: `pw`/)
  assert.match(md, /Share 1 \(group 1, member \d+\):/)
  assert.match(md, /Share 2 \(group 1, member \d+\):/)
  assert.match(md, / 1\. shadow/) // both vector shares start with "shadow"
  assert.doesNotMatch(md, /Share 3/)
  assert.ok(md === md.split('').filter((c) => c.charCodeAt(0) <= 0x7f).join(''), 'pure ASCII')
})
