import React from 'react'
import { createRoot } from 'react-dom/client'
import 'evm-ui/styles.css'
import './app.css'
import { selfTest } from './lib/seedcrypto'
import { slip39SelfTest } from './lib/slip39'
import { App } from './App'

const root = createRoot(document.getElementById('root')!)

// Refuse to run if any published test vector fails — a wrong address or a
// non-portable ciphertext is worse than no app at all.
Promise.all([selfTest(), slip39SelfTest()]).then(([a, b]) => {
  const r = { ...a, ...b }
  r.allPass = a.allPass && Object.values(b).every(Boolean)
  return r
}).then((r) => {
  if (r.allPass) {
    root.render(<App wordlistVerified={r.wordlist} />)
  } else {
    const failed = Object.entries(r).filter(([, ok]) => !ok).map(([k]) => k)
    root.render(
      <div className="sv-fatal">
        <div style={{ fontSize: 'var(--evm-text-lg)', fontWeight: 600 }}>Crypto self-test failed</div>
        <div style={{ color: 'var(--evm-text-2)', maxWidth: 480 }}>
          Seed Vault refuses to start because its cryptography did not reproduce the published
          test vectors on this machine. Do not trust addresses or encrypted output from this build.
        </div>
        <pre>{failed.join('\n')}</pre>
      </div>
    )
  }
})
