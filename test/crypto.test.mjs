// Tests the exact crypto code the app ships (bundled by `npm run build:test`),
// including a byte-compatibility round-trip against the real OpenSSL CLI.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  selfTest, validateMnemonic, mnemonicToSeed, deriveAddresses,
  opensslEncrypt, opensslDecrypt, suggest, normalizeMnemonic,
} from '../dist/test/seedcrypto.mjs'
import { buildMarkdown } from '../dist/test/markdown.mjs'

const VECTOR = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

test('selfTest: every published vector passes', async () => {
  const r = await selfTest()
  for (const [k, ok] of Object.entries(r)) assert.equal(ok, true, `vector ${k} failed`)
})

test('validation failure modes are distinguished', () => {
  assert.equal(validateMnemonic(VECTOR).ok, true)
  const bad = validateMnemonic(VECTOR.replace('about', 'abandn'))
  assert.deepEqual(bad.badWords, [11])
  const wrongLen = validateMnemonic(VECTOR + ' abandon')
  assert.equal(wrongLen.badWords.length, 0)
  assert.equal(wrongLen.lengthOk, false)
  const badCs = validateMnemonic(VECTOR.replace('about', 'abandon'))
  assert.equal(badCs.lengthOk, true)
  assert.equal(badCs.checksumOk, false)
  // NFKD + case + whitespace normalization
  assert.equal(validateMnemonic('  ' + VECTOR.toUpperCase().replace(/ /g, '\n') + '  ').ok, true)
})

test('derivation matches wallets for all five chains', async () => {
  const seed = mnemonicToSeed(VECTOR, '')
  const one = async (chain) => (await deriveAddresses(seed, chain, 1))[0].address
  assert.equal(await one('btc-segwit'), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu') // BIP84 vector
  assert.equal(await one('btc-legacy'), '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA') // BIP44 vector
  assert.equal(await one('eth'), '0x9858EfFD232B4033E47d90003D41EC34EcaEda94') // MEW/Ledger
  assert.equal(await one('sol'), 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk') // Phantom m/44'/501'/0'/0'
  assert.equal(await one('tron'), 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH') // TronLink
  const segwit = await deriveAddresses(seed, 'btc-segwit', 3)
  assert.equal(segwit[2].address, 'bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z') // BIP84 index 2
  for (const a of segwit) assert.equal(a.address.length, 42)
})

test('BIP39 passphrase changes addresses', async () => {
  const a = (await deriveAddresses(mnemonicToSeed(VECTOR, ''), 'eth', 1))[0].address
  const b = (await deriveAddresses(mnemonicToSeed(VECTOR, 'TREZOR'), 'eth', 1))[0].address
  assert.notEqual(a, b)
})

test('suggest completes prefixes from the wordlist', () => {
  assert.deepEqual(suggest('zo', 8), ['zone', 'zoo'])
  assert.equal(suggest('', 8).length, 0)
  assert.equal(suggest('abandon', 8)[0], 'abandon')
})

test('openssl CLI decrypts our output; we decrypt openssl output', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'seedvault-test-'))
  try {
    const plaintext = buildMarkdown([{
      id: 1, kind: 'seed', label: 'Test seed', mnemonic: VECTOR, passphrase: '',
      note: 'unit test', validation: null,
      derivations: [{ id: 'd1', chain: 'btc-segwit', count: '2', deriving: false, descs: { 0: 'first' },
        addresses: await deriveAddresses(mnemonicToSeed(VECTOR, ''), 'btc-segwit', 2) }],
    }])
    const pass = 'correct horse battery staple'

    // ours → openssl
    const enc = await opensslEncrypt(plaintext, pass, 100000)
    const encPath = join(dir, 'seeds.md.enc')
    writeFileSync(encPath, enc)
    const decrypted = execFileSync('openssl', [
      'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '100000',
      '-in', encPath, '-pass', 'pass:' + pass,
    ]).toString()
    assert.equal(decrypted, plaintext)

    // openssl → ours
    const mdPath = join(dir, 'seeds.md')
    writeFileSync(mdPath, plaintext)
    execFileSync('openssl', [
      'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '100000', '-salt',
      '-in', mdPath, '-out', encPath, '-pass', 'pass:' + pass,
    ])
    const theirs = new Uint8Array(readFileSync(encPath))
    assert.equal(await opensslDecrypt(theirs, pass, 100000), plaintext)

    // wrong passphrase must not decrypt
    await assert.rejects(() => opensslDecrypt(enc, 'wrong-passphrase', 100000))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('markdown export format', () => {
  const md = buildMarkdown([
    { id: 1, kind: 'seed', label: 'Cold storage', mnemonic: VECTOR, passphrase: 'x y', note: 'in the safe',
      validation: null, derivations: [] },
    { id: 2, kind: 'note', label: '2FA codes', mnemonic: '', passphrase: '', note: 'code1 code2',
      validation: null, derivations: [] },
  ])
  assert.match(md, /^# Seed phrase backup\n/)
  assert.match(md, /## 1\. Cold storage/)
  assert.match(md, /- Type: BIP39 seed phrase, 12 words \(checksum valid\)/)
  assert.match(md, /- BIP39 passphrase: `x y`/)
  assert.match(md, /^ {5}1\. abandon/m)
  assert.match(md, /## 2\. 2FA codes\n\ncode1 code2/)
  assert.match(md, /openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -in seeds\.md -out seeds\.md\.enc/)
  assert.equal(normalizeMnemonic(VECTOR).length, 12)
})
