import type { ChainKey, DerivedAddress, Validation } from './seedcrypto'

export interface Derivation {
  id: string
  chain: ChainKey
  /** kept as string while editing; clamped to 1–50 when deriving */
  count: string
  addresses: DerivedAddress[] | null
  deriving: boolean
  /** user descriptions per address index; included in the export */
  descs: Record<number, string>
}

export interface Entry {
  id: number
  kind: 'seed' | 'note'
  label: string
  mnemonic: string
  passphrase: string
  note: string
  validation: Validation | null
  derivations: Derivation[]
}

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
