const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('seedvault', {
  /** Open the OS save dialog; returns the chosen file name (path stays in main). */
  chooseSavePath: () => ipcRenderer.invoke('choose-save-path'),
  /** Write the encrypted bytes to the path chosen by chooseSavePath. Ciphertext only. */
  saveEncrypted: (bytes) => ipcRenderer.invoke('save-encrypted', bytes),
  /** Copy text to the OS clipboard; main clears it ~30s later if unchanged. */
  copyText: (text) => ipcRenderer.send('copy-text', text),
  /** Tell main whether closing the window would lose entries. */
  setHasEntries: (v) => ipcRenderer.send('set-has-entries', v),
})
