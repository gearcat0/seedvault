// Build the renderer bundle (and, with --test, a Node-importable crypto bundle).
import { build } from 'esbuild'

const forTest = process.argv.includes('--test')

if (!forTest) {
  await build({
    entryPoints: ['src/renderer.tsx'],
    bundle: true,
    outfile: 'dist/renderer.js',
    format: 'iife',
    platform: 'browser',
    target: 'chrome130',
    loader: { '.css': 'css' },
    logLevel: 'info',
  })
} else {
  // ESM bundle of the crypto + markdown modules so node --test can exercise
  // exactly the code the app ships.
  await build({
    entryPoints: ['src/lib/seedcrypto.ts', 'src/lib/markdown.ts'],
    bundle: true,
    outdir: 'dist/test',
    outExtension: { '.js': '.mjs' },
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    target: 'node20',
    logLevel: 'info',
  })
}
