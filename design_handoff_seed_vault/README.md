# Handoff: Seed Vault — offline seed-phrase backup (Electron)

## Overview

Seed Vault is a desktop app for people who hold many BIP39 seed phrases on paper.
The user enters each seed phrase; the app **validates it offline** (wordlist +
checksum), derives real addresses for several asset types so the user can compare
against their wallet and catch transcription errors, and lets them attach freeform
notes. When everything is entered, the user encrypts the whole set into a single
`seeds.md.enc` file using a passphrase — **byte-compatible with the `openssl enc`
command line** — so it can be decrypted decades from now on any machine with
OpenSSL, no special software required.

Hard requirements from the product owner:

- **Zero network calls.** Everything (wordlist, validation, derivation, encryption) is local.
- **No temporary files.** Plaintext exists only in memory; the only file ever written is the encrypted output (via a save dialog).
- **OpenSSL-compatible encryption** so decryption never depends on this app existing.

## About the Design Files

The files in this bundle are **design references created in HTML** — a working
prototype showing the intended look and behavior, not production code to ship
directly. The task is to **recreate this design as an Electron application**,
using your codebase's established patterns (e.g. React + the real `evm-ui`
package). One exception: `assets/seedcrypto.js` is a functionally correct,
test-vector-verified reference for all the crypto logic (see "Crypto reference"
below) — you may port it, but in production you should prefer audited libraries.

## Fidelity

**High-fidelity.** The prototype uses the real `evm-ui` design system (the
project's bound DS) with its actual stylesheet. Recreate the UI pixel-perfectly
using the `evm-ui` React components (`Button`, `Card`, `Badge`, `Input`,
`Textarea`, `Select`, `Field`, `Modal`, `Table`, `EmptyState`, `StatusBar`) and
its CSS tokens. All colors/spacing/type below are given as `--evm-*` token names;
resolve them from `ds/_ds_bundle.css`.

## Screens / Views

The app is a single window, three vertical bands: header, body (sidebar + detail
pane), status bar. Dark theme only (`--evm-bg` canvas).

### 1. Header (fixed, full width)

- Layout: flex row, `padding: 12px 20px`, `border-bottom: 1px solid var(--evm-border)`, background `--evm-surface-1`, gap 16px.
- Left: 28×28 logo tile (`--evm-accent-faint` bg, `--evm-accent` mono text "SV", radius `--evm-radius-md`), then two-line title: "Seed Vault" (`--evm-text-md`, semibold) over "Validate seed phrases offline · encrypt to a portable OpenSSL file" (`--evm-text-xs`, `--evm-text-3`).
- Right: success Badge with dot, text "offline — no network"; primary Button "Encrypt & export…" (opens the export modal).

### 2. Sidebar (280px, left)

- Background `--evm-surface-1`, right border `--evm-border`; three zones:
  - Header row: "ENTRIES" label (`--evm-text-xs`, uppercase, letter-spacing 0.06em, `--evm-text-3`) + mono count.
  - Scrollable entry list (8px horizontal padding, 2px gaps). Each row: radius `--evm-radius-md`, padding 9px 10px, pointer cursor; selected row gets `--evm-surface-3` bg + `--evm-border-strong` 1px border; hover `--evm-surface-2`. Contents: entry label (body size, single line, ellipsis) over a row with a status Badge (dot) + meta text (`--evm-text-xs`, `--evm-text-4`).
    - Badge tones: seed → `success "valid"`, `danger "invalid"` / `"bad checksum"`, `warning` while checking, `neutral "empty"`; text sections → `neutral "text section"`. Meta: "N words", "· +passphrase" suffix when a BIP39 passphrase is set.
  - Footer (top border): stacked full-width buttons — secondary "+ Seed phrase", ghost "+ Text-only section".

### 3. Detail pane — empty state

Centered `EmptyState` (~80px top padding): decorative mono glyph "·· ·· ··",
title "Back up your seed phrases", supporting paragraph, two buttons
(primary "Add a seed phrase", ghost "Add a text-only section").

### 4. Detail pane — seed entry

Max content width 880px, centered, `padding: 24px 28px 48px`, 16px stack gap.

1. **Label row**: `Field` "Label" with full-width `Input` (placeholder
   "e.g. Ledger — main cold storage") + ghost "Delete" button aligned to the
   input's baseline. Delete is two-step: first click turns it into red
   "Really delete?", second click deletes (state resets when selection changes).
2. **Seed phrase Card**: header title "Seed phrase", subtitle "BIP39 mnemonic —
   12, 15, 18, 21 or 24 words. Validated locally, never transmitted.", header
   action = status Badge (same tones as sidebar; success text "checksum valid").
   Body (12px stack gap):
   - `Textarea` (3 rows, mono font, line-height 1.7, spellcheck/autocapitalize off, placeholder "type or paste the words…").
   - **Autocomplete row** (only while the last token is a partial word): label "complete:" + up to 8 clickable accent Badges with candidate words (mono). Clicking replaces the last token, appends a space, refocuses the textarea with the caret at the end.
   - **Word chips**: one Badge per entered word, mono, prefixed by its 1-based number at 45% opacity. Tone per word: `danger` if not in the wordlist, `success` when the whole phrase validates, `neutral` otherwise.
   - **Validation message** (one line, `--evm-text-sm`): e.g. `Not in the BIP39 wordlist: #5 "abandn". Fix the highlighted words.` (danger color) / `A BIP39 phrase has 12, 15, 18, 21 or 24 words — currently 13.` (warning) / `All words are valid but the checksum fails — a word is wrong or two are swapped. Re-check against your paper copy.` (danger).
   - **BIP39 passphrase** `Field` (max-width 420px): mono Input, label "BIP39 passphrase (optional 25th word)", hint "Changes every derived address. Included in the encrypted file so the backup is complete."
3. **Derived-address Cards — one per asset type** (a seed can have any number;
   the user adds more because one seed often backs multiple chains):
   - Header: title "Derived addresses", subtitle "Compare with your wallet — a
     match proves the phrase was entered correctly." Header actions: chain
     `Select` (options below), numeric `Input` (width 72px, min 1, max 50,
     default 10) for address count, and — when more than one section exists — a
     small ghost "✕" remove button.
   - Chain options: Bitcoin — Native SegWit (BIP84) · Bitcoin — Legacy (BIP44) · Ethereum · Solana · Tron.
   - Body: zebra `Table`, columns `#` (32px) · `Path` (130px, mono, nowrap) ·
     `Address` (shrink-to-fit `width:1%`, mono `--evm-text-sm`, **nowrap — addresses must never wrap**) ·
     `Description` (all remaining width) · copy (52px).
     - Description cell: inline borderless Input (padding 4px 8px, transparent
       bg/border; hover shows `--evm-border`; focus shows `--evm-surface-2` bg +
       `--evm-border-strong`), placeholder "optional". Lets the user name each
       address; values persist per section+index and are included in the export.
     - Copy cell: ghost sm Button "copy" → "✓" for 1.2s after click.
   - Body alt-states: spinner row "deriving addresses…" while deriving; muted
     "Enter a valid seed phrase above to derive addresses." when the phrase
     isn't valid yet.
   - Below the last section: secondary sm button "+ Add another asset type"
     (new section defaults to the first chain not already used).
4. **Notes Card**: title "Notes", subtitle "Freeform — where it's stored, which
   wallets use it, what's on it.", body = `Textarea` (5 rows).

### 5. Detail pane — text-only entry

Same label row (label placeholder "e.g. Exchange accounts / 2FA recovery codes"),
then a Card "Text" (subtitle "A section with no seed phrase — goes into the
encrypted file as-is.") containing a 14-row `Textarea`.

### 6. Status bar (bottom, fixed)

Thin bar (`padding: 6px 16px`, top border, `--evm-surface-1`, `--evm-text-xs`,
`--evm-text-3`): "Seeds N" · "Valid N" (count turns `--evm-success` when all
seeds valid) · "Text sections N" · spacer · "BIP39 wordlist · SHA-256 verified"
(accent) · "no network · no temp files · in-memory only".

### 7. Export modal ("Encrypt & export")

Overlay modal, 660px wide, max-height 88vh. Body stack (14px gaps):

1. **Blocking banner** (danger-faint bg) when there are no entries or any seed
   entry is invalid: export is refused until fixed — the app's whole purpose is
   preventing bad backups. Message lists the offending entry labels.
2. **Plaintext preview**: label “Plaintext preview — `seeds.md`” + char count;
   `<pre>` (mono `--evm-text-xs`, `--evm-surface-2` bg, border, radius, max-height
   200px, scrollable) showing the exact markdown that will be encrypted.
3. **Passphrase row**: two password `Field`s side by side ("Encryption
   passphrase", min 8 chars; "Repeat passphrase" — gets the invalid/red style
   while it doesn't match).
4. **Strength meter**: four 4px segments + right-aligned label
   (too short / weak / fair / strong / very strong). Scoring: ≥8 chars, ≥12
   chars, ≥3 character classes, ≥16 chars with 3 classes → 0–4 segments; colors
   danger/danger/warning/success/accent.
5. **Decrypt command**: labelled mono code row with copy button:
   `openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in seeds.md.enc -out seeds.md`
   plus hint: "Encryption is AES-256-CBC with PBKDF2 (100000 iterations,
   SHA-256) — byte-identical to `openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt`."
6. **Success banner** (success-faint) after encryption: file name, byte size,
   reminder that the passphrase is unrecoverable.
- Footer: ghost "Cancel", primary "Encrypt & save seeds.md.enc" (disabled unless
  passphrase ≥8 chars, matches, and nothing is blocking; label "Encrypting…"
  while busy).

## Interactions & Behavior

- **Validation pipeline** (debounced ~400ms after typing): normalize NFKD,
  lowercase, split on whitespace → check every word against the BIP39 English
  wordlist → check length ∈ {12,15,18,21,24} → verify the SHA-256 checksum bits.
  Distinct failure modes get distinct messages (see above). Invalid words are
  highlighted **by position**.
- **Derivation** runs automatically whenever the phrase becomes valid or the
  passphrase/chain/count changes (deb. 50–600ms). All sections of a seed
  re-derive on phrase/passphrase change. Guard against races with a token per
  entry (stale async results are dropped).
- **Derivation paths** (standard account 0, external chain):
  - Bitcoin SegWit: `m/84'/0'/0'/0/i` → P2WPKH bech32 (`bc1q…`, always 42 chars)
  - Bitcoin Legacy: `m/44'/0'/0'/0/i` → P2PKH base58check (`1…`)
  - Ethereum: `m/44'/60'/0'/0/i` → EIP-55 checksummed hex
  - Solana: `m/44'/501'/i'/0'` (SLIP-0010 ed25519, all hardened; Phantom-style) → base58 pubkey
  - Tron: `m/44'/195'/0'/0/i` → base58check of `0x41 ‖ keccak256(pubkey)[12:]`
- **Export**: builds the markdown in memory, encrypts, then opens the OS save
  dialog (`showSaveFilePicker` in the prototype; use Electron's `dialog.showSaveDialog` +
  `fs.writeFile` of the ciphertext only). **Never write the plaintext to disk.**
- Copy buttons use the clipboard API and flash "✓" for 1.2s.
- No persistence: entries live in memory only and are lost on quit (by design —
  the encrypted file is the artifact). Confirm-close with unsaved entries is a
  sensible Electron addition.

## State Management

- `entries: Entry[]`, `selectedId`, `confirmDeleteId`, `copiedKey`,
  export modal state (`open`, `pass`, `pass2`, `busy`, `doneMessage`).
- `Entry = { id, kind: 'seed'|'note', label, mnemonic, passphrase, note, validation, derivations }`
- `Derivation = { id, chain, count, addresses: {index, path, address}[] | null, deriving, descs: {[index]: string} }`

## Markdown output format (`seeds.md`)

```
# Seed phrase backup

Generated YYYY-MM-DD with Seed Vault (fully offline). Every seed phrase below
passed BIP39 checksum validation, and the listed addresses were derived from it —
after restoring, compare addresses to confirm a correct recovery.

---

## 1. <label>

- Type: BIP39 seed phrase, 24 words (checksum valid)
- BIP39 passphrase: none | `<passphrase>`

Seed phrase:

     1. word1       2. word2       3. word3       4. word4
     5. …                                   (4 numbered words per line, indented code block)

Notes:

<freeform note>

First 10 addresses — Bitcoin — Native SegWit (BIP84):

    m/84'/0'/0'/0/0      bc1q…  — <description if provided>
    …
(one block per derivation section)

---

To re-encrypt after editing this file:

    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -in seeds.md -out seeds.md.enc
```

Text-only entries are just `## N. <title>` + their text.

## Encryption (must stay OpenSSL-compatible)

Output format is exactly what `openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt`
produces: ASCII `Salted__` + 8 random salt bytes + AES-256-CBC ciphertext
(PKCS#7). Key material = PBKDF2-HMAC-SHA256(passphrase, salt, 100000 iters,
48 bytes) → first 32 = key, last 16 = IV. The prototype's implementation
round-trips against real OpenSSL. Keep the iteration count displayed in the UI
identical to the one used, or the shown decrypt command won't work.

## Crypto reference (`assets/seedcrypto.js`)

Self-contained, dependency-free implementation used by the prototype:
BIP39 validation/seed, BIP32 secp256k1, SLIP-0010 ed25519, keccak-256,
ripemd-160, bech32, base58check, EIP-55, and the OpenSSL envelope. It ships a
`selfTest()` verified against published vectors (BIP39/BIP84/BIP44 for the
`abandon…about` mnemonic, SLIP-0010 test vector 1, keccak/ripemd empty-string
hashes, OpenSSL round-trip). **Known past bug to not reintroduce:** the bech32
charset is 32 chars ending in `l` (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`).
For production, prefer audited libraries — `@scure/bip39`, `@scure/bip32`,
`@noble/curves`, `@noble/hashes` — run entirely in the renderer/main process
with no native deps, and keep `selfTest()` as a startup assertion. The BIP39
wordlist (`assets/bip39-english.js`) matches the official file
(SHA-256 `2f5eed53…4dbda` of newline-joined words).

## Design Tokens

All from `evm-ui` (`ds/_ds_bundle.css`), dark-first. Key ones: canvas
`--evm-bg #08080a`; surfaces `--evm-surface-1…4`; accent `--evm-accent #00e4b8`
(+ hover/muted/faint); semantic `--evm-danger/warning/success/info` each with
`-faint`; text `--evm-text-1…4`; borders `--evm-border`, `--evm-border-strong`;
radii `--evm-radius-sm/md/lg/pill`; spacing `--evm-space-1…6` (4px base); fonts
`--evm-font-sans`, `--evm-font-mono` (mono for every address, path, hash,
command, count). Use the tokens, never raw hex.

## Electron notes

- Disable all network access outright (no remote content, CSP `default-src 'none'`
  plus `connect-src 'none'`; consider `session.webRequest` deny-all) so the
  "no network" promise is enforced, not just observed.
- All crypto is fast enough in JS; no native modules needed. WebCrypto
  (`crypto.subtle`) is available in the renderer.
- Write only the ciphertext, via the save dialog. No temp files, no logs of
  seed material, disable Chromium spellcheck on seed inputs (the prototype sets
  `spellcheck=false`), and consider clearing the clipboard some seconds after
  a copy.

## Assets

No images or icon fonts. The "SV" logo tile and "·· ·· ··" empty-state glyph are
plain text. Everything else is evm-ui components + tokens.

## Files

- `Seed Vault.dc.html` — the full prototype (markup template + logic class in one file; open in a browser to interact).
- `assets/seedcrypto.js` — crypto reference implementation (see above).
- `assets/bip39-english.js` — verified BIP39 English wordlist as `window.BIP39_WORDS`.
- `ds/styles.css`, `ds/_ds_bundle.css` — the evm-ui stylesheet and tokens the prototype links.
