import React, { useRef } from 'react'
import { Badge, Button, Card, Field, Input, Textarea } from 'evm-ui'
import { normalizeMnemonic, suggest } from '../lib/seedcrypto'
import type { ChainKey } from '../lib/seedcrypto'
import type { Entry } from '../lib/types'
import { DerivationSection } from './DerivationSection'

type Tone = 'neutral' | 'success' | 'warning' | 'danger'

function seedView(e: Entry) {
  const words = normalizeMnemonic(e.mnemonic)
  const v = e.validation
  const badSet = new Set(v ? v.badWords : [])
  const chips = words.map((w, i) => ({
    n: i + 1, word: w,
    tone: (badSet.has(i) ? 'danger' : v?.ok ? 'success' : 'neutral') as Tone,
  }))
  let tone: Tone = 'neutral', status = 'empty', message = '', messageClass = 'neutral'
  if (!words.length) { tone = 'neutral'; status = 'empty' }
  else if (v?.ok) { tone = 'success'; status = 'checksum valid' }
  else if (v && v.badWords.length) {
    tone = 'danger'
    status = v.badWords.length + ' invalid word' + (v.badWords.length > 1 ? 's' : '')
    message = 'Not in the BIP39 wordlist: ' + v.badWords.map((i) => '#' + (i + 1) + ' "' + words[i] + '"').join(', ') + '. Fix the highlighted words.'
    messageClass = 'danger'
  } else if (v && !v.lengthOk) {
    tone = 'warning'
    status = words.length + ' words'
    message = 'A BIP39 phrase has 12, 15, 18, 21 or 24 words — currently ' + words.length + '.'
    messageClass = 'warning'
  } else if (v && !v.checksumOk) {
    tone = 'danger'
    status = 'bad checksum'
    message = 'All words are valid but the checksum fails — a word is wrong or two are swapped. Re-check against your paper copy.'
    messageClass = 'danger'
  } else { tone = 'warning'; status = 'checking…' }
  return { chips, tone, status, message, messageClass }
}

export function SeedEditor({
  entry, confirmingDelete, copiedKey,
  onLabelChange, onMnemonicChange, onPassphraseChange, onNoteChange, onDelete,
  onPickSuggestion, onChainChange, onCountChange, onDescChange,
  onRemoveSection, onAddSection, onCopy,
}: {
  entry: Entry
  confirmingDelete: boolean
  copiedKey: string | null
  onLabelChange: (v: string) => void
  onMnemonicChange: (v: string) => void
  onPassphraseChange: (v: string) => void
  onNoteChange: (v: string) => void
  onDelete: () => void
  onPickSuggestion: (nextMnemonic: string) => void
  onChainChange: (derivId: string, chain: ChainKey) => void
  onCountChange: (derivId: string, count: string) => void
  onDescChange: (derivId: string, index: number, desc: string) => void
  onRemoveSection: (derivId: string) => void
  onAddSection: () => void
  onCopy: (key: string, text: string) => void
}) {
  // evm-ui's Textarea doesn't forward refs; grab the DOM node via a wrapper.
  const mnemonicWrapRef = useRef<HTMLDivElement>(null)
  const { chips, tone, status, message, messageClass } = seedView(entry)

  // Autocomplete on the last, still-being-typed token.
  let suggestions: string[] = []
  const raw = entry.mnemonic
  if (raw && !/\s$/.test(raw)) {
    const last = normalizeMnemonic(raw).pop() || ''
    if (last) {
      const top2 = suggest(last, 2)
      if (!(top2.length === 1 && top2[0] === last)) {
        suggestions = suggest(last, 8).filter((w) => w !== last)
      }
    }
  }
  const pick = (word: string) => {
    onPickSuggestion(raw.replace(/\S+$/, word) + ' ')
    const ta = mnemonicWrapRef.current?.querySelector('textarea')
    if (ta) setTimeout(() => { ta.focus(); ta.selectionStart = ta.selectionEnd = ta.value.length }, 0)
  }

  return (
    <>
      <div className="sv-label-row">
        <Field label="Label">
          <Input
            value={entry.label}
            onChange={(ev) => onLabelChange(ev.target.value)}
            placeholder="e.g. Ledger — main cold storage"
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
        title="Seed phrase"
        subtitle="BIP39 mnemonic — 12, 15, 18, 21 or 24 words. Validated locally, never transmitted."
        actions={<Badge tone={tone} dot>{status}</Badge>}
      >
        <div className="sv-card-stack">
          <div ref={mnemonicWrapRef}>
            <Textarea
              className="sv-mnemonic"
              rows={3}
              value={entry.mnemonic}
              onChange={(ev) => onMnemonicChange(ev.target.value)}
              placeholder="type or paste the words…"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
            />
          </div>

          {suggestions.length > 0 && (
            <div className="sv-suggest-row">
              <span className="sv-suggest-label">complete:</span>
              {suggestions.map((w) => (
                <button key={w} className="sv-suggestion evm-badge evm-badge--accent" onClick={() => pick(w)}>
                  {w}
                </button>
              ))}
            </div>
          )}

          {chips.length > 0 && (
            <div className="sv-chips">
              {chips.map((c) => (
                <Badge key={c.n} tone={c.tone}>
                  <span className="sv-chip-n">{c.n}</span>
                  {c.word}
                </Badge>
              ))}
            </div>
          )}

          {message && <div className={`sv-seed-msg sv-seed-msg--${messageClass}`}>{message}</div>}

          <div className="sv-passphrase-field">
            <Field
              label={<>BIP39 passphrase <span className="sv-label-optional">(optional 25th word)</span></>}
              hint="Changes every derived address. Included in the encrypted file so the backup is complete."
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

      <Card title="Notes" subtitle="Freeform — where it's stored, which wallets use it, what's on it.">
        <Textarea
          rows={5}
          value={entry.note}
          onChange={(ev) => onNoteChange(ev.target.value)}
          placeholder="e.g. Metal plate in the safe. Used by the family multisig (key 2 of 3). Holds ~0.4 BTC as of 2026."
        />
      </Card>
    </>
  )
}
