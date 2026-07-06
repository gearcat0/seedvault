const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('seedvault', {
  /** Save the encrypted bytes via the OS save dialog. Ciphertext only. */
  saveEncrypted: (bytes) => ipcRenderer.invoke('save-encrypted', bytes),
  /** Copy text to the OS clipboard; main clears it ~30s later if unchanged. */
  copyText: (text) => ipcRenderer.send('copy-text', text),
  /** Tell main whether closing the window would lose entries. */
  setHasEntries: (v) => ipcRenderer.send('set-has-entries', v),
})
