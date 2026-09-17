import type { ChainKey, DerivedAddress, Validation, XpubInfo } from './seedcrypto'
import type { Slip39Share, Slip39Status } from './slip39'
import { passphraseOk } from './slip39'

export interface Derivation {
  id: string
  chain: ChainKey
  /** kept as string while editing; clamped to 1–50 when deriving */
  count: string
  addresses: DerivedAddress[] | null
  /** account extended public key (null for ed25519 chains / not derived yet) */
  xpub: string | null
  deriving: boolean
  /** user descriptions per address index; included in the export */
  descs: Record<number, string>
}

export type EntryKind = 'seed' | 'slip39' | 'note' | 'xpub'

export interface Entry {
  id: number
  kind: EntryKind
  label: string
  mnemonic: string
  passphrase: string
  /** pasted extended public key (xpub entries only) */
  xpub: string
  xpubInfo: XpubInfo | null
  note: string
  validation: Validation | null
  /** SLIP39 share mnemonics, one per input box (slip39 entries only) */
  slip39Shares: string[]
  /** per-share validation + combined status (slip39 entries only) */
  slip39: { shares: Slip39Share[]; status: Slip39Status } | null
  derivations: Derivation[]
}

/** A slip39 entry is exportable when its non-empty shares are all valid,
    mutually consistent, and the passphrase is legal — completeness (enough
    shares to recover) is deliberately NOT required: holding fewer than the
    threshold in one place is the point of SLIP39. */
export const slip39EntryOk = (e: Entry): boolean =>
  !!e.slip39 && !e.slip39.status.error && passphraseOk(e.passphrase) &&
  e.slip39.shares.some((s) => s.ok) &&
  e.slip39.shares.every((s) => s.ok || s.words.length === 0)

export const clampCount = (raw: string) => Math.min(50, Math.max(1, parseInt(raw, 10) || 10))

/** Move the entry `id` so it sits at `insertIndex` (an insertion point in the
    current list, 0..length). Returns the same array if nothing changes. */
export function reorderEntries<T extends { id: number }>(list: T[], id: number, insertIndex: number): T[] {
  const from = list.findIndex((e) => e.id === id)
  if (from < 0) return list
  const to = insertIndex > from ? insertIndex - 1 : insertIndex
  if (to === from) return list
  const next = [...list]
  const [item] = next.splice(from, 1)
  next.splice(to, 0, item)
  return next
}
