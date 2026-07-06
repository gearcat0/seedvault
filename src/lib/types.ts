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
