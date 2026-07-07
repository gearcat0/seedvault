export {}

declare global {
  interface Window {
    seedvault?: {
      chooseSavePath(): Promise<{ canceled: boolean; name?: string }>
      saveEncrypted(bytes: Uint8Array): Promise<{ canceled: boolean; path?: string; bytes?: number }>
      copyText(text: string): void
      setHasEntries(v: boolean): void
    }
  }
}
