# Seed Vault

Desktop app (Electron) for backing up BIP39 seed phrases. Each phrase is
validated offline (wordlist + checksum), real addresses are derived for
Bitcoin (SegWit/Legacy), Ethereum, Solana and Tron so you can compare against
your wallet and catch transcription errors, and everything is encrypted into a
single `seeds.md.enc` file that any machine with OpenSSL can decrypt:

```sh
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -a -in seeds.md.enc | more
```

The file is printable ASCII: a `#` comment header carrying an optional
envelope title (plaintext — visible without the passphrase), the generation
timestamp, the decrypt command with the actual file name, and the local
`openssl version` at creation time (OpenSSL skips these lines when
decrypting), followed by the base64-armored ciphertext — safe to print,
paste, or archive anywhere. Entries can be reordered by dragging in the
sidebar; the order becomes the section order in the backup.

The decrypted `seeds.md` is pure 7-bit ASCII: typographic characters (em/en
dashes, smart quotes, ellipses) are transliterated, and any other non-ASCII in
a label/note/passphrase is escaped losslessly as `\uXXXX` (a non-ASCII
passphrase is additionally flagged, since it must be restored as the original
characters). Nothing is dropped.

Each derivation section in the backup also carries every address's
wallet-importable private key (WIF for Bitcoin, hex for Ethereum/Tron,
Phantom-style base58 keypair for Solana) so a single account can be restored
without importing the whole seed, plus the account xpub (zpub for BIP84) for
watch-only balance discovery. Solana has no xpub — SLIP-0010 ed25519 is
hardened-only.

## Guarantees

- **Zero network.** Enforced three ways: `webRequest` deny-all in the main
  process, `connect-src 'none'` CSP in the page, and no remote content anywhere.
- **No temp files.** Entries live in memory only; the sole file ever written is
  the ciphertext, through the OS save dialog. The main process refuses to write
  anything that doesn't start with the OpenSSL `Salted__` header.
- **OpenSSL-compatible output.** AES-256-CBC, PBKDF2-HMAC-SHA256, 100000
  iterations, `Salted__` envelope, base64-armored (`-a`) with a comment
  header. The test suite round-trips against the real `openssl` CLI in both
  directions, comments included.
- **Self-testing crypto.** On every launch the renderer re-checks published
  test vectors (BIP39, BIP84/BIP44, SLIP-0010, keccak/ripemd, OpenSSL
  round-trip, wordlist SHA-256) and refuses to run if any fail.
- Clipboard copies are cleared after 30 s (unless you copied something else
  since); Chromium spellcheck is disabled; closing with entries warns first.

## Stack

- Electron (sandboxed renderer, context isolation, no node integration)
- React + the `evm-ui` design system (`../evm-ui`)
- Audited crypto: `@scure/bip39`, `@scure/bip32`, `@noble/curves`,
  `@noble/hashes`, `@scure/base`; WebCrypto for the OpenSSL envelope

## Develop

```sh
npm install
npm start          # build renderer + launch (add `-- --no-sandbox` in containers)
npm test           # crypto/markdown suite incl. OpenSSL CLI round-trip
npx tsc --noEmit   # typecheck
```

Layout: `main.js` / `preload.js` (Electron main), `index.html` + `src/`
(renderer; `src/lib/seedcrypto.ts` is all the crypto), `test/`.
