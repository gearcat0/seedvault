// Seed Vault — Electron main process.
// Enforces the app's promises: no network, no temp files, only the encrypted
// blob ever touches disk (via the save dialog).
const { app, BrowserWindow, dialog, ipcMain, session, clipboard } = require('electron')
const fs = require('fs/promises')
const path = require('path')

// The app loads only local files; kill every other protocol at the network layer.
const ALLOWED_URL = /^(file:|devtools:|chrome-extension:|about:blank)/

let hasEntries = false
let clipboardTimer = null

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#08080a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  })
  win.removeMenu()
  win.loadFile('index.html')

  win.on('close', (e) => {
    if (!hasEntries) return
    const choice = dialog.showMessageBoxSync(win, {
      type: 'warning',
      buttons: ['Stay', 'Discard and quit'],
      defaultId: 0,
      cancelId: 0,
      title: 'Unsaved entries',
      message: 'Entries are kept in memory only and will be lost.',
      detail: 'If you have not encrypted & exported yet, your entries are gone when the window closes.',
    })
    if (choice === 0) e.preventDefault()
  })
}

app.whenReady().then(() => {
  // Deny all network requests that are not local files — the "no network"
  // promise is enforced, not just observed.
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    callback({ cancel: !ALLOWED_URL.test(details.url) })
  })
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault())
  contents.setWindowOpenHandler(() => ({ action: 'deny' }))
})

app.on('window-all-closed', () => app.quit())

// Renderer tells us whether closing would lose data.
ipcMain.on('set-has-entries', (_e, v) => { hasEntries = !!v })

// Save the ciphertext (and nothing else) through the OS save dialog.
ipcMain.handle('save-encrypted', async (e, bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length < 16 ||
      Buffer.from(bytes.slice(0, 8)).toString('latin1') !== 'Salted__') {
    throw new Error('refusing to write: not an OpenSSL-encrypted payload')
  }
  const win = BrowserWindow.fromWebContents(e.sender)
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    defaultPath: 'seeds.md.enc',
    filters: [{ name: 'Encrypted backup', extensions: ['enc'] }],
  })
  if (canceled || !filePath) return { canceled: true }
  await fs.writeFile(filePath, Buffer.from(bytes))
  return { canceled: false, path: filePath, bytes: bytes.length }
})

// Copy to clipboard; auto-clear after 30s unless the user copied something else since.
ipcMain.on('copy-text', (_e, text) => {
  clipboard.writeText(String(text))
  if (clipboardTimer) clearTimeout(clipboardTimer)
  clipboardTimer = setTimeout(() => {
    if (clipboard.readText() === String(text)) clipboard.clear()
  }, 30000)
})
