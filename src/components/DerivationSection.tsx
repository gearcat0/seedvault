import React from 'react'
import { Button, Card, Input, Select, Spinner, Table } from 'evm-ui'
import { CHAINS } from '../lib/seedcrypto'
import type { ChainKey, DerivedAddress } from '../lib/seedcrypto'
import type { Derivation } from '../lib/types'

export function DerivationSection({
  deriv, removable, copiedKey, onChainChange, onCountChange, onDescChange, onRemove, onCopy,
}: {
  deriv: Derivation
  removable: boolean
  copiedKey: string | null
  onChainChange: (chain: ChainKey) => void
  onCountChange: (count: string) => void
  onDescChange: (index: number, desc: string) => void
  onRemove: () => void
  onCopy: (key: string, text: string) => void
}) {
  const hasAddresses = !!(deriv.addresses && deriv.addresses.length) && !deriv.deriving

  return (
    <Card
      title="Derived addresses"
      subtitle="Compare with your wallet — a match proves the phrase was entered correctly."
      actions={
        <>
          <Select
            value={deriv.chain}
            onChange={(ev) => onChainChange(ev.target.value as ChainKey)}
            style={{ width: 'auto', paddingRight: 32 }}
          >
            {(Object.keys(CHAINS) as ChainKey[]).map((c) => (
              <option key={c} value={c}>{CHAINS[c].name}</option>
            ))}
          </Select>
          <Input
            type="number"
            min={1}
            max={50}
            value={deriv.count}
            onChange={(ev) => onCountChange(ev.target.value)}
            style={{ width: 72 }}
            title="number of addresses (1–50)"
          />
          {removable && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onRemove}
              title="Remove this asset type"
              style={{ color: 'var(--evm-text-3)' }}
            >
              ✕
            </Button>
          )}
        </>
      }
    >
      {hasAddresses && (
        <div className="sv-addr-table">
          <Table
            zebra
            rowKey={(r: DerivedAddress) => r.index}
            columns={[
              { key: 'index', header: '#', render: (r: DerivedAddress) => <span className="sv-addr-index">{r.index}</span> },
              { key: 'path', header: 'Path', render: (r: DerivedAddress) => <span className="sv-addr-path">{r.path}</span> },
              { key: 'address', header: 'Address', render: (r: DerivedAddress) => <span className="sv-addr-address">{r.address}</span> },
              {
                key: 'desc', header: 'Description',
                render: (r: DerivedAddress) => (
                  <Input
                    className="sv-desc-input"
                    value={deriv.descs[r.index] || ''}
                    onChange={(ev) => onDescChange(r.index, ev.target.value)}
                    placeholder="optional"
                    spellCheck={false}
                  />
                ),
              },
              {
                key: 'copy', header: '', align: 'right',
                render: (r: DerivedAddress) => (
                  <Button variant="ghost" size="sm" onClick={() => onCopy('addr' + deriv.id + '_' + r.index, r.address)}>
                    {copiedKey === 'addr' + deriv.id + '_' + r.index ? '✓' : 'copy'}
                  </Button>
                ),
              },
            ]}
            rows={deriv.addresses!}
          />
        </div>
      )}
      {deriv.deriving && (
        <div className="sv-deriving">
          <Spinner size={14} label="deriving addresses" />
          deriving addresses…
        </div>
      )}
      {!deriv.deriving && !hasAddresses && (
        <div className="sv-no-derive">Enter a valid seed phrase above to derive addresses.</div>
      )}
    </Card>
  )
}
