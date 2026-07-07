// Zoom defaults and keyboard zoom controls.
// removeMenu() drops the built-in zoom accelerators, so Ctrl+= / Ctrl+- /
// Ctrl+0 are handled here.
const ZOOM_MIN = 0.5
const ZOOM_MAX = 5.0

// Pick the default zoom for a display. Linux desktops frequently do NOT scale
// up high-DPI panels, so Chromium renders everything tiny; there we start at
// 2x. On normal-density displays (including 1080p) — where a 2x window would
// overflow the screen — and on every non-Linux platform, stay at 1x.
//
// `display` is an Electron Display ({ size: {width,height} in DIP, scaleFactor }).
function defaultZoomFor(display) {
  if (process.platform !== 'linux') return 1.0
  const sf = display.scaleFactor || 1
  const physicalW = Math.round(display.size.width * sf)
  const physicalH = Math.round(display.size.height * sf)
  // Only when the OS isn't already scaling (sf < 1.5) and the panel is dense
  // (roughly QHD+/4K). A 1920x1080 or 2560x1440 panel is left at 1x.
  const hiDpiUnscaled = sf < 1.5 && physicalW >= 2560 && physicalH >= 1600
  return hiDpiUnscaled ? 2.0 : 1.0
}

function attachZoomControls(win, defaultZoom) {
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
      wc.setZoomFactor(defaultZoom)
      e.preventDefault()
    }
  })
  // Chromium persists per-origin zoom across runs; pin the computed default.
  win.webContents.on('did-finish-load', () => win.webContents.setZoomFactor(defaultZoom))
}

module.exports = { defaultZoomFor, attachZoomControls }
