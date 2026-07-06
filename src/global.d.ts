export {}

declare global {
  interface Window {
    seedvault?: {
      saveEncrypted(bytes: Uint8Array): Promise<{ canceled: boolean; path?: string; bytes?: number }>
      copyText(text: string): void
      setHasEntries(v: boolean): void
    }
  }
}
