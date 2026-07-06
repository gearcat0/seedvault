import React from 'react'
import { Badge, Button } from 'evm-ui'
import { normalizeMnemonic } from '../lib/seedcrypto'
import type { Entry } from '../lib/types'

type Tone = 'neutral' | 'success' | 'warning' | 'danger'

export function entryStatus(e: Entry): { tone: Tone; status: string; meta: string } {
  if (e.kind === 'note') {
    const trimmed = (e.note || '').trim()
    return {
      tone: 'neutral', status: 'text section',
      meta: trimmed ? trimmed.split(/\s+/).length + ' words' : 'empty',
    }
  }
  const words = normalizeMnemonic(e.mnemonic)
  let meta = words.length ? words.length + ' words' : ''
  if (e.passphrase) meta += ' · +passphrase'
  const v = e.validation
  if (!words.length) return { tone: 'neutral', status: 'empty', meta }
  if (v?.ok) return { tone: 'success', status: 'valid', meta }
  if (v && (v.badWords.length || !v.lengthOk)) return { tone: 'danger', status: 'invalid', meta }
  if (v && !v.checksumOk) return { tone: 'danger', status: 'bad checksum', meta }
  return { tone: 'warning', status: 'checking', meta }
}

export function Sidebar({ entries, selectedId, onSelect, onAddSeed, onAddNote }: {
  entries: Entry[]
  selectedId: number | null
  onSelect: (id: number) => void
  onAddSeed: () => void
  onAddNote: () => void
}) {
  return (
    <div className="sv-sidebar">
      <div className="sv-sidebar-head">
        <span className="sv-sidebar-head-label">Entries</span>
        <span className="sv-sidebar-count">{entries.length}</span>
      </div>
      <div className="sv-sidebar-list">
        {entries.length === 0 && <div className="sv-sidebar-empty">No entries yet.</div>}
        {entries.map((e) => {
          const { tone, status, meta } = entryStatus(e)
          return (
            <div
              key={e.id}
              className={'sv-entry' + (e.id === selectedId ? ' sv-entry--selected' : '')}
              onClick={() => onSelect(e.id)}
            >
              <span className="sv-entry-label">{e.label || 'Untitled'}</span>
              <div className="sv-entry-status">
                <Badge tone={tone} dot>{status}</Badge>
                <span className="sv-entry-meta">{meta}</span>
              </div>
            </div>
          )
        })}
      </div>
      <div className="sv-sidebar-foot">
        <Button variant="secondary" onClick={onAddSeed}>+ Seed phrase</Button>
        <Button variant="ghost" onClick={onAddNote}>+ Text-only section</Button>
      </div>
    </div>
  )
}
