import { asciify, CHAINS, normalizeMnemonic } from './seedcrypto'
import type { Entry } from './types'

export const KDF_ITERATIONS = 100000

/** The decrypt command for a given saved file name, shell-quoted if needed. */
export function decryptCommand(fileName: string, kdfIter = KDF_ITERATIONS): string {
  const quoted = /^[\w.@-]+$/.test(fileName) ? fileName : `'${fileName.replace(/'/g, `'\\''`)}'`
  return `openssl enc -d -aes-256-cbc -pbkdf2 -iter ${kdfIter} -a -in ${quoted} | more`
}

/** Build the seeds.md plaintext exactly as specified in the handoff.
    The document is pure 7-bit ASCII (see {@link asciify}); the only field left
    byte-exact is the BIP39 passphrase, which is a secret that must be typed back
    character-for-character to recover the funds. */
export function buildMarkdown(entries: Entry[], kdfIter = KDF_ITERATIONS): string {
  const lines: string[] = []
  const today = new Date().toISOString().slice(0, 10)
  lines.push('# Seed phrase backup')
  lines.push('')
  lines.push('Generated ' + today + ' with Seed Vault (fully offline). Every seed phrase below')
  lines.push('passed BIP39 checksum validation, and the listed addresses were derived from it --')
  lines.push('after restoring, compare addresses to confirm a correct recovery.')
  lines.push('')
  let n = 0
  for (const e of entries) {
    n++
    lines.push('---')
    lines.push('')
    lines.push('## ' + n + '. ' + asciify(e.label || 'Untitled'))
    lines.push('')
    if (e.kind === 'note') {
      lines.push(asciify(e.note) || '(empty)')
      lines.push('')
      continue
    }
    const words = normalizeMnemonic(e.mnemonic)
    lines.push('- Type: BIP39 seed phrase, ' + words.length + ' words (checksum valid)')
    if (!e.passphrase) {
      lines.push('- BIP39 passphrase: none')
    } else {
      const pass = asciify(e.passphrase)
      // If the passphrase held non-ASCII, it is shown escaped -- warn loudly,
      // because it must be typed back as the ORIGINAL characters, not the escapes.
      const note = pass !== e.passphrase
        ? '  (contains non-ASCII; \\uXXXX are Unicode escapes -- restore the original characters, not this text)'
        : ''
      lines.push('- BIP39 passphrase: `' + pass + '`' + note)
    }
    lines.push('')
    lines.push('Seed phrase:')
    lines.push('')
    for (let i = 0; i < words.length; i += 4) {
      const chunk = words.slice(i, i + 4).map((w, j) => String(i + j + 1).padStart(2, ' ') + '. ' + w.padEnd(10))
      lines.push(('    ' + chunk.join(' ')).replace(/\s+$/, ''))
    }
    lines.push('')
    if (e.note && e.note.trim()) {
      lines.push('Notes:')
      lines.push('')
      lines.push(asciify(e.note.trim()))
      lines.push('')
    }
    for (const d of e.derivations) {
      if (!(d.addresses && d.addresses.length)) continue
      lines.push('First ' + d.addresses.length + ' addresses -- ' + asciify(CHAINS[d.chain].name) + ':')
      lines.push('')
      if (d.xpub) {
        // on its own line -- the xpub is long and would wrap
        lines.push('    account xpub (watch-only, finds all balances):')
        lines.push('    ' + d.xpub)
        lines.push('')
      }
      for (const a of d.addresses) {
        const desc = d.descs[a.index]
        lines.push('    ' + a.path.padEnd(20) + ' ' + a.address + (desc && desc.trim() ? '  -- ' + asciify(desc.trim()) : ''))
        lines.push('    ' + ''.padEnd(20) + ' private key: ' + a.priv)
      }
      lines.push('')
    }
  }
  lines.push('---')
  lines.push('')
  lines.push('To re-encrypt after editing this file:')
  lines.push('')
  lines.push('    openssl enc -aes-256-cbc -pbkdf2 -iter ' + kdfIter + ' -salt -a -in seeds.md -out seeds.md.enc')
  lines.push('')
  return lines.join('\n')
}
