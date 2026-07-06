import React, { useMemo, useState } from 'react'
import { Button, Field, Input, Modal } from 'evm-ui'
import { opensslEncrypt } from '../lib/seedcrypto'
import { buildMarkdown, KDF_ITERATIONS } from '../lib/markdown'
import type { Entry } from '../lib/types'

function passStrength(pass: string): number {
  if (!pass) return 0
  let score = 0
  if (pass.length >= 8) score++
  if (pass.length >= 12) score++
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pass)).length
  if (classes >= 3) score++
  if (pass.length >= 16 && classes >= 3) score++
  return score // 0..4
}

const STRENGTH_COLORS = ['var(--evm-danger)', 'var(--evm-danger)', 'var(--evm-warning)', 'var(--evm-success)', 'var(--evm-accent)']
const STRENGTH_LABELS = ['', 'weak', 'fair', 'strong', 'very strong']

export function ExportModal({ open, entries, copiedKey, onCopy, onClose }: {
  open: boolean
  entries: Entry[]
  copiedKey: string | null
  onCopy: (key: string, text: string) => void
  onClose: () => void
}) {
  const [pass, setPass] = useState('')
  const [pass2, setPass2] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<string | null>(null)

  const preview = useMemo(() => (open ? buildMarkdown(entries) : ''), [open, entries])

  const invalidSeeds = entries.filter((e) => e.kind === 'seed' && !e.validation?.ok)
  const blocked = entries.length === 0 || invalidSeeds.length > 0
  const blockedMsg = entries.length === 0
    ? 'Nothing to export yet — add at least one seed phrase or text section.'
    : 'Cannot export: ' + invalidSeeds.length + ' seed entr' + (invalidSeeds.length > 1 ? 'ies are' : 'y is') +
      ' not valid yet (' + invalidSeeds.map((e) => '"' + (e.label || 'Untitled') + '"').join(', ') + '). Fix or delete before encrypting.'

  const strength = passStrength(pass)
  const passOk = pass.length >= 8 && pass === pass2
  const decryptCmd = `openssl enc -d -aes-256-cbc -pbkdf2 -iter ${KDF_ITERATIONS} -in seeds.md.enc -out seeds.md`

  const doEncrypt = async () => {
    setBusy(true)
    setDone(null)
    try {
      const bytes = await opensslEncrypt(buildMarkdown(entries), pass, KDF_ITERATIONS)
      if (!window.seedvault) throw new Error('save bridge unavailable')
      const res = await window.seedvault.saveEncrypted(bytes)
      setBusy(false)
      if (res.canceled) return
      setDone(`Encrypted ✓ — saved to ${res.path} (${bytes.length} bytes). Keep the passphrase in your head — without it the file is unreadable.`)
    } catch (err: any) {
      setBusy(false)
      setDone('Encryption failed: ' + (err?.message || String(err)))
    }
  }

  return (
    <Modal
      open={open}
      title="Encrypt & export"
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!passOk || blocked || busy} onClick={doEncrypt}>
            {busy ? 'Encrypting…' : 'Encrypt & save seeds.md.enc'}
          </Button>
        </>
      }
    >
      <div className="sv-export-body">
        {blocked && <div className="sv-banner sv-banner--danger">{blockedMsg}</div>}

        <div className="sv-stack-6">
          <div className="sv-preview-head">
            <span className="evm-field-label">
              Plaintext preview — <span style={{ fontFamily: 'var(--evm-font-mono)' }}>seeds.md</span>
            </span>
            <span className="sv-preview-size">{preview.length} chars</span>
          </div>
          <pre className="sv-preview">{preview}</pre>
        </div>

        <div className="sv-pass-row">
          <Field label="Encryption passphrase">
            <Input
              mono
              type="password"
              value={pass}
              onChange={(ev) => { setPass(ev.target.value); setDone(null) }}
              placeholder="min 8 characters"
            />
          </Field>
          <Field label="Repeat passphrase">
            <Input
              mono
              type="password"
              invalid={!!pass2 && pass2 !== pass}
              value={pass2}
              onChange={(ev) => { setPass2(ev.target.value); setDone(null) }}
              placeholder="type it again"
            />
          </Field>
        </div>

        <div className="sv-strength-row">
          <div className="sv-strength-segs">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="sv-strength-seg"
                style={{ background: strength >= i ? STRENGTH_COLORS[strength] : 'var(--evm-surface-3)' }}
              />
            ))}
          </div>
          <span className="sv-strength-label" style={{ color: STRENGTH_COLORS[strength] }}>
            {pass ? (pass.length < 8 ? 'too short' : STRENGTH_LABELS[strength]) : ''}
          </span>
        </div>

        <div className="sv-stack-6">
          <span className="evm-field-label">To decrypt later — any machine with OpenSSL</span>
          <div className="sv-cmd-row">
            <code className="sv-cmd">{decryptCmd}</code>
            <Button variant="ghost" size="sm" onClick={() => onCopy('cmd', decryptCmd)}>
              {copiedKey === 'cmd' ? '✓ copied' : 'copy'}
            </Button>
          </div>
          <span className="evm-field-hint">
            Encryption is AES-256-CBC with PBKDF2 ({KDF_ITERATIONS} iterations, SHA-256) — byte-identical
            to <span className="sv-cmd-hint-mono">openssl enc -aes-256-cbc -pbkdf2 -iter {KDF_ITERATIONS} -salt</span>.
          </span>
        </div>

        {done && (
          <div className={'sv-banner ' + (done.startsWith('Encrypted ✓') ? 'sv-banner--success' : 'sv-banner--danger')}>
            {done}
          </div>
        )}
      </div>
    </Modal>
  )
}
