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
  opensslEncrypt, opensslDecrypt, armor, dearmor, suggest, normalizeMnemonic,
} from '../dist/test/seedcrypto.mjs'
import { buildMarkdown, decryptCommand } from '../dist/test/markdown.mjs'
import { reorderEntries } from '../dist/test/types.mjs'

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
  const one = async (chain) => (await deriveAddresses(seed, chain, 1)).addresses[0].address
  assert.equal(await one('btc-segwit'), 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu') // BIP84 vector
  assert.equal(await one('btc-legacy'), '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA') // BIP44 vector
  assert.equal(await one('eth'), '0x9858EfFD232B4033E47d90003D41EC34EcaEda94') // MEW/Ledger
  assert.equal(await one('sol'), 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk') // Phantom m/44'/501'/0'/0'
  assert.equal(await one('tron'), 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH') // TronLink
  const segwit = await deriveAddresses(seed, 'btc-segwit', 3)
  assert.equal(segwit.addresses[2].address, 'bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z') // BIP84 index 2
  for (const a of segwit.addresses) assert.equal(a.address.length, 42)
})

test('BIP39 passphrase changes addresses', async () => {
  const a = (await deriveAddresses(mnemonicToSeed(VECTOR, ''), 'eth', 1)).addresses[0].address
  const b = (await deriveAddresses(mnemonicToSeed(VECTOR, 'TREZOR'), 'eth', 1)).addresses[0].address
  assert.notEqual(a, b)
})

test('private keys independently re-derive their own addresses', async () => {
  const { secp256k1 } = await import('@noble/curves/secp256k1')
  const { ed25519 } = await import('@noble/curves/ed25519')
  const { keccak_256 } = await import('@noble/hashes/sha3')
  const { ripemd160 } = await import('@noble/hashes/legacy')
  const { sha256 } = await import('@noble/hashes/sha2')
  const { base58, bech32, createBase58check } = await import('@scure/base')
  const b58c = createBase58check(sha256)
  const seed = mnemonicToSeed(VECTOR, '')

  // BIP84 spec vectors: first WIF for the abandon…about mnemonic
  const segwit = await deriveAddresses(seed, 'btc-segwit', 2)
  assert.equal(segwit.addresses[0].priv, 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d')
  for (const a of segwit.addresses) {
    const decoded = b58c.decode(a.priv) // 0x80 ‖ key32 ‖ 0x01
    assert.equal(decoded[0], 0x80)
    assert.equal(decoded[33], 0x01)
    const pub = secp256k1.getPublicKey(decoded.slice(1, 33), true)
    assert.equal(bech32.encode('bc', [0, ...bech32.toWords(ripemd160(sha256(pub)))]), a.address)
  }
  const legacy = (await deriveAddresses(seed, 'btc-legacy', 1)).addresses[0]
  {
    const key = b58c.decode(legacy.priv).slice(1, 33)
    const pub = secp256k1.getPublicKey(key, true)
    assert.equal(b58c.encode(new Uint8Array([0, ...ripemd160(sha256(pub))])), legacy.address)
  }

  // Ethereum: 0x-hex key → keccak(pubkey)[12:] must equal the address
  const eth = (await deriveAddresses(seed, 'eth', 1)).addresses[0]
  assert.match(eth.priv, /^0x[0-9a-f]{64}$/)
  {
    const pub = secp256k1.getPublicKey(eth.priv.slice(2), false).slice(1)
    const raw = Buffer.from(keccak_256(pub).slice(12)).toString('hex')
    assert.equal('0x' + raw, eth.address.toLowerCase())
  }

  // Tron: hex key → base58check(0x41 ‖ keccak(pubkey)[12:])
  const tron = (await deriveAddresses(seed, 'tron', 1)).addresses[0]
  assert.match(tron.priv, /^[0-9a-f]{64}$/)
  {
    const pub = secp256k1.getPublicKey(tron.priv, false).slice(1)
    assert.equal(b58c.encode(new Uint8Array([0x41, ...keccak_256(pub).slice(12)])), tron.address)
  }

  // Solana: base58 64-byte keypair (Phantom format), second half = pubkey = address
  const sol = (await deriveAddresses(seed, 'sol', 1)).addresses[0]
  const pair = base58.decode(sol.priv)
  assert.equal(pair.length, 64)
  assert.deepEqual(Array.from(ed25519.getPublicKey(pair.slice(0, 32))), Array.from(pair.slice(32)))
  assert.equal(base58.encode(pair.slice(32)), sol.address)
})

test('account xpub alone reproduces the addresses (watch-only)', async () => {
  const { HDKey } = await import('@scure/bip32')
  const { sha256 } = await import('@noble/hashes/sha2')
  const { ripemd160 } = await import('@noble/hashes/legacy')
  const { bech32, createBase58check } = await import('@scure/base')
  const b58c = createBase58check(sha256)
  const seed = mnemonicToSeed(VECTOR, '')

  // BIP84 spec vector for the account zpub
  const segwit = await deriveAddresses(seed, 'btc-segwit', 3)
  assert.equal(segwit.xpub, 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')
  const watch = HDKey.fromExtendedKey(segwit.xpub, { private: 0x04b2430c, public: 0x04b24746 })
  assert.equal(watch.privateKey, null) // public-only — safe to share
  for (const a of segwit.addresses) {
    const pub = watch.deriveChild(0).deriveChild(a.index).publicKey
    assert.equal(bech32.encode('bc', [0, ...bech32.toWords(ripemd160(sha256(pub)))]), a.address)
  }

  const legacy = await deriveAddresses(seed, 'btc-legacy', 2)
  assert.match(legacy.xpub, /^xpub/)
  const watchL = HDKey.fromExtendedKey(legacy.xpub)
  for (const a of legacy.addresses) {
    const pub = watchL.deriveChild(0).deriveChild(a.index).publicKey
    assert.equal(b58c.encode(new Uint8Array([0, ...ripemd160(sha256(pub))])), a.address)
  }

  assert.equal((await deriveAddresses(seed, 'sol', 1)).xpub, null) // ed25519: no public derivation
  assert.match((await deriveAddresses(seed, 'eth', 1)).xpub, /^xpub/)
  assert.match((await deriveAddresses(seed, 'tron', 1)).xpub, /^xpub/)
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
        ...(await deriveAddresses(mnemonicToSeed(VECTOR, ''), 'btc-segwit', 2)) }],
    }])
    const pass = 'correct horse battery staple'

    // ours → openssl: armored with comment header, exactly what the app saves
    const enc = await opensslEncrypt(plaintext, pass, 100000)
    const armored = armor(enc, [
      'Generated 2026-07-07 17:49:01',
      'To decrypt run: ' + decryptCommand('seeds.md.enc'),
    ])
    const encPath = join(dir, 'seeds.md.enc')
    writeFileSync(encPath, armored)
    const decrypted = execFileSync('openssl', [
      'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '100000', '-a',
      '-in', encPath, '-pass', 'pass:' + pass,
    ]).toString()
    assert.equal(decrypted, plaintext)

    // the plaintext carries xpub + private keys for each derived address
    assert.match(plaintext, /account xpub \(watch-only, finds all balances\): zpub6rFR7y4Q2Aij/)
    assert.match(plaintext, /private key: KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d/)

    // the file is printable ASCII with the comments on top
    assert.match(armored, /^# Generated 2026-07-07 17:49:01\n# To decrypt run: openssl enc -d/)
    assert.match(armored, /\n(U2FsdGVk)/) // base64("Salted__") right after the comments
    assert.ok([...armored].every((c) => c === '\n' || (c >= ' ' && c <= '~')))

    // openssl -a → ours
    const mdPath = join(dir, 'seeds.md')
    writeFileSync(mdPath, plaintext)
    execFileSync('openssl', [
      'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '100000', '-salt', '-a',
      '-in', mdPath, '-out', encPath, '-pass', 'pass:' + pass,
    ])
    const theirs = dearmor(readFileSync(encPath, 'utf8'))
    assert.equal(await opensslDecrypt(theirs, pass, 100000), plaintext)

    // wrong passphrase must not decrypt
    await assert.rejects(() => opensslDecrypt(enc, 'wrong-passphrase', 100000))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('decrypt command names the saved file, quoted when needed', () => {
  assert.equal(decryptCommand('seeds.md.enc'),
    'openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -a -in seeds.md.enc | more')
  assert.equal(decryptCommand('family backup 2026.enc'),
    "openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -a -in 'family backup 2026.enc' | more")
  assert.equal(decryptCommand("bob's.enc"),
    "openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -a -in 'bob'\\''s.enc' | more")
})

test('armor flattens newlines in comments so the header cannot be corrupted', async () => {
  const enc = await opensslEncrypt('x', 'pw', 1000)
  const armored = armor(enc, ['line one\nline two\r\nline three', 'Generated 2026-07-07'])
  assert.match(armored, /^# line one line two line three\n# Generated 2026-07-07\n/)
  // every line is either a comment or base64
  for (const l of armored.trimEnd().split('\n')) assert.match(l, /^(#|[A-Za-z0-9+/=]+$)/)
  assert.equal(await opensslDecrypt(dearmor(armored), 'pw', 1000), 'x')
})

test('reorderEntries moves an entry to an insertion point', () => {
  const list = [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]
  assert.deepEqual(reorderEntries(list, 1, 4).map((e) => e.id), [2, 3, 4, 1]) // first → end
  assert.deepEqual(reorderEntries(list, 4, 0).map((e) => e.id), [4, 1, 2, 3]) // last → front
  assert.deepEqual(reorderEntries(list, 2, 3).map((e) => e.id), [1, 3, 2, 4]) // one step down
  assert.equal(reorderEntries(list, 2, 1), list) // dropping onto its own slot is a no-op
  assert.equal(reorderEntries(list, 2, 2), list) // ...from either side
  assert.equal(reorderEntries(list, 99, 0), list) // unknown id is a no-op
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
  assert.doesNotMatch(md, /account xpub|private key:/) // no derivations in this fixture
  assert.match(md, /openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -a -in seeds\.md -out seeds\.md\.enc/)
  assert.equal(normalizeMnemonic(VECTOR).length, 12)
})
