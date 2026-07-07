// Zoom defaults and keyboard zoom controls.
// removeMenu() drops the built-in zoom accelerators, so Ctrl+= / Ctrl+- /
// Ctrl+0 are handled here. Linux desktops commonly under-scale Chromium
// apps, so the default there is 2×.
const DEFAULT_ZOOM = process.platform === 'linux' ? 2.0 : 1.0
const ZOOM_MIN = 0.5
const ZOOM_MAX = 5.0

function attachZoomControls(win) {
  win.webContents.on('before-input-event', (e, input) => {
    if (input.type !== 'keyDown' || !(input.control || input.meta)) return
    const wc = win.webContents
    // snap to quarter steps — getZoomFactor() returns slightly off values
    const z = Math.round(wc.getZoomFactor() * 4) / 4
    if (input.key === '+' || input.key === '=') {
      wc.setZoomFactor(Math.min(ZOOM_MAX, z + 0.25))
      e.preventDefault()
    } else if (input.key === '-') {
      wc.setZoomFactor(Math.max(ZOOM_MIN, z - 0.25))
      e.preventDefault()
    } else if (input.key === '0') {
      wc.setZoomFactor(DEFAULT_ZOOM)
      e.preventDefault()
    }
  })
  // Chromium persists per-origin zoom across runs; pin the documented default.
  win.webContents.on('did-finish-load', () => win.webContents.setZoomFactor(DEFAULT_ZOOM))
}

module.exports = { DEFAULT_ZOOM, attachZoomControls }
