import React from 'react'
import { Badge, Button, Card, Field, Input, Textarea } from 'evm-ui'
import { normalizeMnemonic } from '../lib/seedcrypto'
import type { ChainKey } from '../lib/seedcrypto'
import { passphraseOk, suggestSlip39 } from '../lib/slip39'
import type { Slip39Share, Slip39Status } from '../lib/slip39'
import type { Entry } from '../lib/types'
import { DerivationSection } from './DerivationSection'

type Tone = 'neutral' | 'success' | 'warning' | 'danger'

function shareBadge(info: Slip39Share | undefined, text: string): { tone: Tone; label: string } {
  if (!text.trim() || !info || !info.words.length) return { tone: 'neutral', label: 'empty' }
  if (info.ok) {
    return { tone: 'success', label: 'group ' + (info.groupIndex! + 1) + ' · member ' + (info.memberIndex! + 1) + ' · valid' }
  }
  if (info.looksLikeBip39) return { tone: 'danger', label: 'BIP39 phrase' }
  if (info.badWords.length) return { tone: 'danger', label: info.badWords.length + ' invalid word' + (info.badWords.length > 1 ? 's' : '') }
  if (!info.lengthOk) return { tone: 'warning', label: info.words.length + ' words' }
  if (!info.checksumOk) return { tone: 'danger', label: 'bad checksum' }
  return { tone: 'danger', label: 'invalid' }
}

function overallBadge(entry: Entry): { tone: Tone; label: string } {
  const anyText = entry.slip39Shares.some((t) => t.trim())
  if (!anyText) return { tone: 'neutral', label: 'empty' }
  const st = entry.slip39?.status
  if (!st) return { tone: 'warning', label: 'checking…' }
  if (st.error) return { tone: 'danger', label: 'inconsistent set' }
  if (st.complete) return { tone: 'success', label: 'master secret recovered · ' + st.strengthBits + '-bit' }
  return { tone: 'warning', label: st.missing || 'incomplete' }
}

export function Slip39Editor({
  entry, confirmingDelete, copiedKey,
  onLabelChange, onShareChange, onAddShare, onRemoveShare,
  onPassphraseChange, onNoteChange, onDelete,
  onChainChange, onCountChange, onDescChange,
  onRemoveSection, onAddSection, onCopy,
}: {
  entry: Entry
  confirmingDelete: boolean
  copiedKey: string | null
  onLabelChange: (v: string) => void
  onShareChange: (index: number, v: string) => void
  onAddShare: () => void
  onRemoveShare: (index: number) => void
  onPassphraseChange: (v: string) => void
  onNoteChange: (v: string) => void
  onDelete: () => void
  onChainChange: (derivId: string, chain: ChainKey) => void
  onCountChange: (derivId: string, count: string) => void
  onDescChange: (derivId: string, index: number, desc: string) => void
  onRemoveSection: (derivId: string) => void
  onAddSection: () => void
  onCopy: (key: string, text: string) => void
}) {
  const status = overallBadge(entry)
  const st = entry.slip39?.status
  const groupSummary = st && !st.error && st.groupCount && st.groupCount > 1
    ? st.groupThreshold + ' of ' + st.groupCount + ' groups required'
    : null
  const passBad = !passphraseOk(entry.passphrase)

  return (
    <>
      <div className="sv-label-row">
        <Field label="Label">
          <Input
            value={entry.label}
            onChange={(ev) => onLabelChange(ev.target.value)}
            placeholder="e.g. Trezor Shamir backup — office + bank vault shares"
            spellCheck={false}
          />
        </Field>
        <Button
          variant="ghost"
          style={{ color: confirmingDelete ? 'var(--evm-danger)' : 'var(--evm-text-3)' }}
          onClick={onDelete}
        >
          {confirmingDelete ? 'Really delete?' : 'Delete'}
        </Button>
      </div>

      <Card
        title="SLIP39 shares"
        subtitle="Shamir backup — each share is 20 or 33 words. Enter the shares you hold; addresses can be derived once a recoverable set is present."
        actions={<Badge tone={status.tone} dot>{status.label}</Badge>}
      >
        <div className="sv-card-stack">
          {entry.slip39Shares.map((text, i) => {
            const info = entry.slip39?.shares[i]
            const badge = shareBadge(info, text)
            const words = normalizeMnemonic(text)
            const badSet = new Set(info && normalizeMnemonic(text).length === info.words.length ? info.badWords : [])
            // autocomplete on the last, still-being-typed token
            let suggestions: string[] = []
            if (text && !/\s$/.test(text)) {
              const last = words[words.length - 1] || ''
              if (last) {
                const top2 = suggestSlip39(last, 2)
                if (!(top2.length === 1 && top2[0] === last)) {
                  suggestions = suggestSlip39(last, 8).filter((w) => w !== last)
                }
              }
            }
            return (
              <div key={i} className="sv-share">
                <div className="sv-share-head">
                  <span className="sv-share-label">Share {i + 1}</span>
                  <Badge tone={badge.tone} dot>{badge.label}</Badge>
                  <span className="sv-spacer" />
                  {entry.slip39Shares.length > 1 && (
                    <Button variant="ghost" size="sm" title="Remove this share"
                      style={{ color: 'var(--evm-text-3)' }} onClick={() => onRemoveShare(i)}>✕</Button>
                  )}
                </div>
                <Textarea
                  className="sv-mnemonic"
                  rows={2}
                  value={text}
                  onChange={(ev) => onShareChange(i, ev.target.value)}
                  placeholder="type or paste the 20 or 33 share words…"
                  spellCheck={false}
                  autoCapitalize="off"
                  autoCorrect="off"
                />
                {suggestions.length > 0 && (
                  <div className="sv-suggest-row">
                    <span className="sv-suggest-label">complete:</span>
                    {suggestions.map((w) => (
                      <button key={w} className="sv-suggestion evm-badge evm-badge--accent"
                        onClick={() => onShareChange(i, text.replace(/\S+$/, w) + ' ')}>
                        {w}
                      </button>
                    ))}
                  </div>
                )}
                {words.length > 0 && (
                  <div className="sv-chips">
                    {words.map((w, k) => (
                      <Badge key={k} tone={badSet.has(k) ? 'danger' : info?.ok ? 'success' : 'neutral'}>
                        <span className="sv-chip-n">{k + 1}</span>
                        {w}
                      </Badge>
                    ))}
                  </div>
                )}
                {info && !info.ok && info.error && text.trim() !== '' && (
                  <div className="sv-seed-msg sv-seed-msg--danger">{info.error}</div>
                )}
              </div>
            )
          })}

          <div>
            <Button variant="secondary" size="sm" onClick={onAddShare}>+ Add another share</Button>
          </div>

          {st?.error && <div className="sv-seed-msg sv-seed-msg--danger">{st.error}</div>}
          {st && !st.error && !st.complete && st.missing && (
            <div className="sv-seed-msg sv-seed-msg--warning">
              Not yet recoverable — {st.missing}.{groupSummary ? ' (' + groupSummary + ')' : ''}
            </div>
          )}
          {st && !st.error && st.complete && (
            <div className="sv-seed-msg sv-seed-msg--neutral">
              {st.strengthBits}-bit master secret recovered
              {st.id !== undefined ? ' (identifier ' + st.id + ')' : ''}
              {groupSummary ? ' — ' + groupSummary : ''}. The addresses below are derived from it — compare with your wallet.
            </div>
          )}

          <div className="sv-passphrase-field">
            <Field
              label={<>SLIP39 passphrase <span className="sv-label-optional">(optional)</span></>}
              hint="Changes every derived address. Any passphrase decrypts to some wallet — only the right one leads to your funds. Included in the encrypted file so the backup is complete."
            >
              <Input
                mono
                value={entry.passphrase}
                onChange={(ev) => onPassphraseChange(ev.target.value)}
                placeholder="leave empty if none"
                spellCheck={false}
                autoCapitalize="off"
              />
            </Field>
            {passBad && (
              <div className="sv-seed-msg sv-seed-msg--danger">
                SLIP39 passphrases must be printable ASCII (letters, digits, punctuation, spaces).
              </div>
            )}
          </div>
        </div>
      </Card>

      {entry.derivations.map((d) => (
        <DerivationSection
          key={d.id}
          deriv={d}
          removable={entry.derivations.length > 1}
          copiedKey={copiedKey}
          onChainChange={(chain) => onChainChange(d.id, chain)}
          onCountChange={(count) => onCountChange(d.id, count)}
          onDescChange={(index, desc) => onDescChange(d.id, index, desc)}
          onRemove={() => onRemoveSection(d.id)}
          onCopy={onCopy}
        />
      ))}
      <div>
        <Button variant="secondary" size="sm" onClick={onAddSection}>+ Add another asset type</Button>
      </div>

      <Card title="Notes" subtitle="Freeform — where each share lives, who holds one, what's on the wallet.">
        <Textarea
          rows={5}
          value={entry.note}
          onChange={(ev) => onNoteChange(ev.target.value)}
          placeholder="e.g. 2-of-3 backup. Share 1 here, share 2 with the lawyer, share 3 in the bank vault. Holds the long-term BTC."
        />
      </Card>
    </>
  )
}
