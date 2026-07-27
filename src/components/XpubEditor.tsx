import React from 'react'
import { Badge, Button, Card, Field, Input, Textarea } from 'evm-ui'
import { CHAINS, XPUB_CHAINS } from '../lib/seedcrypto'
import type { ChainKey } from '../lib/seedcrypto'
import type { Entry } from '../lib/types'
import { DerivationSection } from './DerivationSection'

type Tone = 'neutral' | 'success' | 'warning' | 'danger'

function xpubView(e: Entry) {
  const info = e.xpubInfo
  let tone: Tone = 'neutral', status = 'empty', message = '', messageClass = 'neutral'
  if (!e.xpub.trim()) { tone = 'neutral'; status = 'empty' }
  else if (info?.ok) {
    tone = 'success'
    status = info.format + ' · watch-only'
    if (info.depth !== 3) {
      tone = 'warning'
      message = 'Depth ' + info.depth + ' — not an account-level key (depth 3). Addresses are derived from path 0/i relative to this key, which may not match your wallet.'
      messageClass = 'warning'
    } else if (info.defaultChain) {
      message = 'Account-level ' + info.format + ' — conventionally ' + CHAINS[info.defaultChain].name + '.'
      messageClass = 'neutral'
    }
  } else if (info) {
    tone = 'danger'
    status = 'invalid'
    message = info.error || 'Not a valid extended public key.'
    messageClass = 'danger'
  } else { tone = 'warning'; status = 'checking…' }
  return { tone, status, message, messageClass }
}

export function XpubEditor({
  entry, confirmingDelete, copiedKey,
  onLabelChange, onXpubChange, onNoteChange, onDelete,
  onChainChange, onCountChange, onDescChange,
  onRemoveSection, onAddSection, onCopy,
}: {
  entry: Entry
  confirmingDelete: boolean
  copiedKey: string | null
  onLabelChange: (v: string) => void
  onXpubChange: (v: string) => void
  onNoteChange: (v: string) => void
  onDelete: () => void
  onChainChange: (derivId: string, chain: ChainKey) => void
  onCountChange: (derivId: string, count: string) => void
  onDescChange: (derivId: string, index: number, desc: string) => void
  onRemoveSection: (derivId: string) => void
  onAddSection: () => void
  onCopy: (key: string, text: string) => void
}) {
  const { tone, status, message, messageClass } = xpubView(entry)

  return (
    <>
      <div className="sv-label-row">
        <Field label="Label">
          <Input
            value={entry.label}
            onChange={(ev) => onLabelChange(ev.target.value)}
            placeholder="e.g. Ledger BTC account — watch-only"
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
        title="Extended public key"
        subtitle="Account-level xpub / ypub / zpub — watch-only, derives addresses but can never spend. Validated locally, never transmitted."
        actions={<Badge tone={tone} dot>{status}</Badge>}
      >
        <div className="sv-card-stack">
          <Textarea
            className="sv-mnemonic sv-xpub-input"
            rows={2}
            value={entry.xpub}
            onChange={(ev) => onXpubChange(ev.target.value)}
            placeholder="paste the key — xpub6…, ypub6… or zpub6…"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
          {message && <div className={`sv-seed-msg sv-seed-msg--${messageClass}`}>{message}</div>}
        </div>
      </Card>

      {entry.derivations.map((d) => (
        <DerivationSection
          key={d.id}
          deriv={d}
          removable={entry.derivations.length > 1}
          copiedKey={copiedKey}
          chains={XPUB_CHAINS}
          watchOnly
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

      <Card title="Notes" subtitle="Freeform — which wallet holds the private keys, what this account is for.">
        <Textarea
          rows={5}
          value={entry.note}
          onChange={(ev) => onNoteChange(ev.target.value)}
          placeholder="e.g. Ledger main account — this key only watches balances; the seed is on the metal plate."
        />
      </Card>
    </>
  )
}
