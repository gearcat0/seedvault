import { CHAINS, normalizeMnemonic } from './seedcrypto'
import type { Entry } from './types'

export const KDF_ITERATIONS = 100000

/** The decrypt command for a given saved file name, shell-quoted if needed. */
export function decryptCommand(fileName: string, kdfIter = KDF_ITERATIONS): string {
  const quoted = /^[\w.@-]+$/.test(fileName) ? fileName : `'${fileName.replace(/'/g, `'\\''`)}'`
  return `openssl enc -d -aes-256-cbc -pbkdf2 -iter ${kdfIter} -a -in ${quoted} | more`
}

/** Build the seeds.md plaintext exactly as specified in the handoff. */
export function buildMarkdown(entries: Entry[], kdfIter = KDF_ITERATIONS): string {
  const lines: string[] = []
  const today = new Date().toISOString().slice(0, 10)
  lines.push('# Seed phrase backup')
  lines.push('')
  lines.push('Generated ' + today + ' with Seed Vault (fully offline). Every seed phrase below')
  lines.push('passed BIP39 checksum validation, and the listed addresses were derived from it —')
  lines.push('after restoring, compare addresses to confirm a correct recovery.')
  lines.push('')
  let n = 0
  for (const e of entries) {
    n++
    lines.push('---')
    lines.push('')
    lines.push('## ' + n + '. ' + (e.label || 'Untitled'))
    lines.push('')
    if (e.kind === 'note') {
      lines.push(e.note || '(empty)')
      lines.push('')
      continue
    }
    const words = normalizeMnemonic(e.mnemonic)
    lines.push('- Type: BIP39 seed phrase, ' + words.length + ' words (checksum valid)')
    lines.push('- BIP39 passphrase: ' + (e.passphrase ? '`' + e.passphrase + '`' : 'none'))
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
      lines.push(e.note.trim())
      lines.push('')
    }
    for (const d of e.derivations) {
      if (!(d.addresses && d.addresses.length)) continue
      lines.push('First ' + d.addresses.length + ' addresses — ' + CHAINS[d.chain].name + ':')
      lines.push('')
      for (const a of d.addresses) {
        const desc = d.descs[a.index]
        lines.push('    ' + a.path.padEnd(20) + ' ' + a.address + (desc && desc.trim() ? '  — ' + desc.trim() : ''))
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
