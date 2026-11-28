import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { defineConfig, type Plugin } from 'vitest/config'
import react from '@vitejs/plugin-react'

// In the browser (`npm run dev:web`, without Tauri) there is no Rust process to
// call, so the dev server answers POST /__mekiki/report itself by running the
// `report` example of unforge-report on the uploaded bytes. Dev server only;
// the app never uses this.
function devReport(): Plugin {
  const root = join(__dirname, '..')
  const exe = join(root, 'target', 'debug', 'examples', 'report')
  return {
    name: 'mekiki-dev-report',
    apply: 'serve',
    configureServer(server) {
      execFileSync('cargo', ['build', '-q', '-p', 'unforge-report', '--example', 'report'], { cwd: root, stdio: 'inherit' })
      server.middlewares.use('/__mekiki/report', (req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (c: Buffer) => chunks.push(c))
        req.on('end', () => {
          const dir = mkdtempSync(join(tmpdir(), 'mekiki-'))
          try {
            const file = join(dir, 'input')
            writeFileSync(file, Buffer.concat(chunks))
            const started = Date.now()
            const json = execFileSync(exe, [file], { maxBuffer: 1 << 30 }).toString()
            res.setHeader('content-type', 'application/json')
            res.setHeader('x-elapsed-ms', String(Date.now() - started))
            res.end(json)
          } catch (e) {
            res.statusCode = 500
            res.end(String(e))
          } finally {
            rmSync(dir, { recursive: true, force: true })
          }
        })
      })
    },
  }
}

export default defineConfig({
  base: './',
  plugins: [react(), devReport()],
  clearScreen: false,
  server: { watch: { ignored: ['**/src-tauri/**'] } },
  test: { environment: 'jsdom' },
})
