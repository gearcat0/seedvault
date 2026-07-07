import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Badge, Button } from 'evm-ui'
import { StatusBar, StatusItem, StatusSpacer } from 'evm-ui'
import {
  ChainKey, CHAINS, deriveAddresses, mnemonicToSeed, normalizeMnemonic, validateMnemonic,
} from './lib/seedcrypto'
import { clampCount, Derivation, Entry, reorderEntries } from './lib/types'
import { Sidebar } from './components/Sidebar'
import { SeedEditor } from './components/SeedEditor'
import { NoteEditor } from './components/NoteEditor'
import { ExportModal } from './components/ExportModal'
import { EmptyState } from 'evm-ui'

const DEFAULT_CHAIN: ChainKey = 'btc-segwit'
const DEFAULT_COUNT = '10'

let derivSeq = 0
const newDeriv = (chain: ChainKey = DEFAULT_CHAIN): Derivation => ({
  id: 'd' + ++derivSeq,
  chain,
  count: DEFAULT_COUNT,
  addresses: null,
  deriving: false,
  descs: {},
})

export function App({ wordlistVerified }: { wordlistVerified: boolean }) {
  const [entries, setEntries] = useState<Entry[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [exportOpen, setExportOpen] = useState(false)

  const seq = useRef(1)
  const entriesRef = useRef(entries)
  entriesRef.current = entries
  const deriveTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({})
  const deriveTokens = useRef<Record<number, number>>({})
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  // Closing the window loses everything — let main warn the user.
  useEffect(() => { window.seedvault?.setHasEntries(entries.length > 0) }, [entries.length > 0])

  const updateEntry = useCallback((id: number, patch: Partial<Entry>) => {
    setEntries((es) => es.map((e) => (e.id === id ? { ...e, ...patch } : e)))
  }, [])

  const updateDeriv = useCallback((entryId: number, derivId: string, patch: Partial<Derivation>) => {
    setEntries((es) => es.map((e) => e.id !== entryId ? e : {
      ...e, derivations: e.derivations.map((d) => (d.id === derivId ? { ...d, ...patch } : d)),
    }))
  }, [])

  const runDerive = useCallback(async (id: number) => {
    const entry = entriesRef.current.find((e) => e.id === id)
    if (!entry) return
    const token = (deriveTokens.current[id] = (deriveTokens.current[id] || 0) + 1)
    const v = validateMnemonic(entry.mnemonic)
    if (!v.ok) {
      updateEntry(id, {
        validation: v,
        derivations: entry.derivations.map((d) => ({ ...d, addresses: null, deriving: false })),
      })
      return
    }
    updateEntry(id, { validation: v, derivations: entry.derivations.map((d) => ({ ...d, deriving: true })) })
    try {
      const seed = mnemonicToSeed(entry.mnemonic, entry.passphrase)
      for (const d of entry.derivations) {
        const addrs = await deriveAddresses(seed, d.chain, clampCount(d.count))
        if (deriveTokens.current[id] !== token) return
        updateDeriv(id, d.id, { addresses: addrs, deriving: false })
      }
    } catch (err) {
      if (deriveTokens.current[id] !== token) return
      const cur = entriesRef.current.find((e) => e.id === id)
      if (cur) updateEntry(id, {
        derivations: cur.derivations.map((d) => (d.deriving ? { ...d, addresses: null, deriving: false } : d)),
      })
      console.error(err)
    }
  }, [updateDeriv, updateEntry])

  const scheduleDerive = useCallback((id: number, delay = 400) => {
    clearTimeout(deriveTimers.current[id])
    deriveTimers.current[id] = setTimeout(() => runDerive(id), delay)
  }, [runDerive])

  const addEntry = useCallback((kind: 'seed' | 'note') => {
    const id = seq.current++
    const entry: Entry = {
      id, kind,
      label: kind === 'seed' ? 'Untitled seed ' + id : 'Untitled section ' + id,
      mnemonic: '', passphrase: '', note: '',
      validation: null,
      derivations: kind === 'seed' ? [newDeriv()] : [],
    }
    setEntries((es) => [...es, entry])
    setSelectedId(id)
    setConfirmDeleteId(null)
  }, [])

  const flashCopied = useCallback((key: string, text: string) => {
    if (window.seedvault) window.seedvault.copyText(text)
    else navigator.clipboard?.writeText(text)
    setCopiedKey(key)
    clearTimeout(copyTimer.current)
    copyTimer.current = setTimeout(() => setCopiedKey(null), 1200)
  }, [])

  const selected = entries.find((e) => e.id === selectedId) || null

  const onDelete = () => {
    if (!selected) return
    if (confirmDeleteId === selected.id) {
      setEntries((es) => es.filter((e) => e.id !== selected.id))
      setSelectedId(null)
      setConfirmDeleteId(null)
    } else setConfirmDeleteId(selected.id)
  }

  const addDerivSection = () => {
    if (!selected) return
    const used = new Set(selected.derivations.map((d) => d.chain))
    const nextChain = (Object.keys(CHAINS) as ChainKey[]).find((c) => !used.has(c)) || DEFAULT_CHAIN
    updateEntry(selected.id, { derivations: [...selected.derivations, newDeriv(nextChain)] })
    if (selected.validation?.ok) scheduleDerive(selected.id, 50)
  }

  const seedEntries = entries.filter((e) => e.kind === 'seed')
  const validSeeds = seedEntries.filter((e) => e.validation?.ok)
  const noteCount = entries.length - seedEntries.length
  const allValid = seedEntries.length > 0 && validSeeds.length === seedEntries.length

  return (
    <div className="sv-root">
      <div className="sv-header">
        <div className="sv-logo">SV</div>
        <div>
          <div className="sv-header-title">Seed Vault</div>
          <div className="sv-header-sub">Validate seed phrases offline · encrypt to a portable OpenSSL file</div>
        </div>
        <div className="sv-spacer" />
        <Badge tone="success" dot>offline — no network</Badge>
        <Button variant="primary" onClick={() => setExportOpen(true)}>Encrypt &amp; export…</Button>
      </div>

      <div className="sv-body">
        <Sidebar
          entries={entries}
          selectedId={selectedId}
          onSelect={(id) => { setSelectedId(id); setConfirmDeleteId(null) }}
          onReorder={(id, insertIndex) => setEntries((es) => reorderEntries(es, id, insertIndex))}
          onAddSeed={() => addEntry('seed')}
          onAddNote={() => addEntry('note')}
        />

        <div className="sv-main">
          <div className="sv-main-inner">
            {!selected && (
              <EmptyState
                icon={<div className="sv-empty-glyph">·· ·· ··</div>}
                title="Back up your seed phrases"
                description="Add each seed phrase, check the derived addresses against your wallet to rule out transcription errors, describe where it's used — then encrypt everything into a single file you can print, copy, or stash anywhere."
                action={
                  <div className="sv-empty-actions">
                    <Button variant="primary" onClick={() => addEntry('seed')}>Add a seed phrase</Button>
                    <Button variant="ghost" onClick={() => addEntry('note')}>Add a text-only section</Button>
                  </div>
                }
              />
            )}
            {selected?.kind === 'seed' && (
              <SeedEditor
                entry={selected}
                confirmingDelete={confirmDeleteId === selected.id}
                copiedKey={copiedKey}
                onLabelChange={(v) => updateEntry(selected.id, { label: v })}
                onMnemonicChange={(v) => { updateEntry(selected.id, { mnemonic: v }); scheduleDerive(selected.id) }}
                onPassphraseChange={(v) => { updateEntry(selected.id, { passphrase: v }); scheduleDerive(selected.id, 600) }}
                onNoteChange={(v) => updateEntry(selected.id, { note: v })}
                onDelete={onDelete}
                onPickSuggestion={(next) => { updateEntry(selected.id, { mnemonic: next }); scheduleDerive(selected.id, 50) }}
                onChainChange={(derivId, chain) => { updateDeriv(selected.id, derivId, { chain, addresses: null }); scheduleDerive(selected.id, 50) }}
                onCountChange={(derivId, count) => { updateDeriv(selected.id, derivId, { count }); scheduleDerive(selected.id, 600) }}
                onDescChange={(derivId, index, desc) => {
                  const d = selected.derivations.find((x) => x.id === derivId)
                  if (d) updateDeriv(selected.id, derivId, { descs: { ...d.descs, [index]: desc } })
                }}
                onRemoveSection={(derivId) => updateEntry(selected.id, { derivations: selected.derivations.filter((d) => d.id !== derivId) })}
                onAddSection={addDerivSection}
                onCopy={flashCopied}
              />
            )}
            {selected?.kind === 'note' && (
              <NoteEditor
                entry={selected}
                confirmingDelete={confirmDeleteId === selected.id}
                onLabelChange={(v) => updateEntry(selected.id, { label: v })}
                onNoteChange={(v) => updateEntry(selected.id, { note: v })}
                onDelete={onDelete}
              />
            )}
          </div>
        </div>
      </div>

      <StatusBar>
        <StatusItem label="Seeds" value={String(seedEntries.length)} />
        <span className={allValid ? 'sv-status-valid-all' : undefined}>
          <StatusItem label="Valid" value={String(validSeeds.length)} />
        </span>
        <StatusItem label="Text sections" value={String(noteCount)} />
        <StatusSpacer />
        {wordlistVerified && <span className="sv-status-accent">BIP39 wordlist · SHA-256 verified</span>}
        <span>no network · no temp files · in-memory only</span>
      </StatusBar>

      <ExportModal
        open={exportOpen}
        entries={entries}
        copiedKey={copiedKey}
        onCopy={flashCopied}
        onClose={() => setExportOpen(false)}
      />
    </div>
  )
}
