import React from 'react'
import { Button, Card, Field, Input, Textarea } from 'evm-ui'
import type { Entry } from '../lib/types'

export function NoteEditor({ entry, confirmingDelete, onLabelChange, onNoteChange, onDelete }: {
  entry: Entry
  confirmingDelete: boolean
  onLabelChange: (v: string) => void
  onNoteChange: (v: string) => void
  onDelete: () => void
}) {
  return (
    <>
      <div className="sv-label-row">
        <Field label="Section title">
          <Input
            value={entry.label}
            onChange={(ev) => onLabelChange(ev.target.value)}
            placeholder="e.g. Exchange accounts / 2FA recovery codes"
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
      <Card title="Text" subtitle="A section with no seed phrase — goes into the encrypted file as-is.">
        <Textarea
          rows={14}
          value={entry.note}
          onChange={(ev) => onNoteChange(ev.target.value)}
          placeholder="Anything else that belongs in the backup…"
        />
      </Card>
    </>
  )
}
