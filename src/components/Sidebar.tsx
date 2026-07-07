import React, { useState } from 'react'
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

export function Sidebar({ entries, selectedId, onSelect, onReorder, onAddSeed, onAddNote }: {
  entries: Entry[]
  selectedId: number | null
  onSelect: (id: number) => void
  /** Move entry `id` to insertion point `insertIndex` (0..entries.length). */
  onReorder: (id: number, insertIndex: number) => void
  onAddSeed: () => void
  onAddNote: () => void
}) {
  const [dragId, setDragId] = useState<number | null>(null)
  const [dropIndex, setDropIndex] = useState<number | null>(null)

  const resetDrag = () => { setDragId(null); setDropIndex(null) }

  const overRow = (i: number) => (ev: React.DragEvent<HTMLDivElement>) => {
    if (dragId == null) return
    ev.preventDefault()
    ev.stopPropagation()
    const rect = ev.currentTarget.getBoundingClientRect()
    setDropIndex(ev.clientY < rect.top + rect.height / 2 ? i : i + 1)
  }

  const overList = (ev: React.DragEvent<HTMLDivElement>) => {
    if (dragId == null) return
    ev.preventDefault()
    setDropIndex(entries.length) // empty space below the rows → drop at the end
  }

  const drop = (ev: React.DragEvent<HTMLDivElement>) => {
    ev.preventDefault()
    if (dragId != null && dropIndex != null) onReorder(dragId, dropIndex)
    resetDrag()
  }

  return (
    <div className="sv-sidebar">
      <div className="sv-sidebar-head">
        <span className="sv-sidebar-head-label">Entries</span>
        <span className="sv-sidebar-count">{entries.length}</span>
      </div>
      <div className="sv-sidebar-list" onDragOver={overList} onDrop={drop}>
        {entries.length === 0 && <div className="sv-sidebar-empty">No entries yet.</div>}
        {entries.map((e, i) => {
          const { tone, status, meta } = entryStatus(e)
          return (
            <React.Fragment key={e.id}>
              {dropIndex === i && dragId != null && <div className="sv-drop-indicator" />}
              <div
                className={
                  'sv-entry' +
                  (e.id === selectedId ? ' sv-entry--selected' : '') +
                  (e.id === dragId ? ' sv-entry--dragging' : '')
                }
                onClick={() => onSelect(e.id)}
                draggable
                onDragStart={(ev) => {
                  ev.dataTransfer.effectAllowed = 'move'
                  ev.dataTransfer.setData('text/plain', String(e.id))
                  setDragId(e.id)
                }}
                onDragOver={overRow(i)}
                onDrop={drop}
                onDragEnd={resetDrag}
              >
                <span className="sv-entry-label">{e.label || 'Untitled'}</span>
                <div className="sv-entry-status">
                  <Badge tone={tone} dot>{status}</Badge>
                  <span className="sv-entry-meta">{meta}</span>
                </div>
              </div>
            </React.Fragment>
          )
        })}
        {dropIndex === entries.length && dragId != null && <div className="sv-drop-indicator" />}
      </div>
      <div className="sv-sidebar-foot">
        <Button variant="secondary" onClick={onAddSeed}>+ Seed phrase</Button>
        <Button variant="ghost" onClick={onAddNote}>+ Text-only section</Button>
      </div>
    </div>
  )
}
