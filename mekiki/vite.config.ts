import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
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
      // The last uploaded file stays here so code_map / disasm can read it.
      const dir = mkdtempSync(join(tmpdir(), 'mekiki-'))
      const file = join(dir, 'input')
      // MEKIKI_SIG_DB=<file.db> applies a fingerprint database, like the app does.
      const sig = process.env.MEKIKI_SIG_DB ? ['--sigs', process.env.MEKIKI_SIG_DB] : []
      const run = (args: string[]) => execFileSync(exe, [...sig, ...args], { maxBuffer: 1 << 30 })
      const body = (req: import('node:http').IncomingMessage) =>
        new Promise<Buffer>((resolve) => {
          const chunks: Buffer[] = []
          req.on('data', (c: Buffer) => chunks.push(c))
          req.on('end', () => resolve(Buffer.concat(chunks)))
        })
      server.middlewares.use('/__mekiki/report', async (req, res) => {
        try {
          writeFileSync(file, await body(req))
          const started = Date.now()
          const json = run([file]).toString()
          res.setHeader('content-type', 'application/json')
          res.setHeader('x-elapsed-ms', String(Date.now() - started))
          // like the app: say which fingerprint databases were used
          res.end(sig.length ? json.replace(/^\{/, `{"signature_files":${JSON.stringify([sig[1].split('/').pop()])},`) : json)
        } catch (e) {
          res.statusCode = 500
          res.end(String(e))
        }
      })
      // A real Rust binary to practice on: the report example itself.
      server.middlewares.use('/__mekiki/sample', (_req, res) => {
        res.setHeader('content-type', 'application/octet-stream')
        res.end(readFileSync(exe))
      })
      // Decompile one function: a fresh helper per request (the app keeps one alive).
      const helper = join(root, 'mekiki', 'decompiler', 'target', 'release', 'mekiki-decomp')
      const specs = join(root, 'mekiki', 'decompiler', 'specs', 'x86')
      server.middlewares.use('/__mekiki/decompile', async (req, res) => {
        const [addrText, langText] = (await body(req)).toString().split(' ')
        const addr = Number(addrText)
        const setup = spawnSync(exe, [...sig, '--decomp-setup', file], { maxBuffer: 1 << 28 })
        if (setup.status !== 0) {
          res.statusCode = 400
          res.end('Decompiling is only available for x86 and x86-64 files for now.')
          return
        }
        const [lang, ...lines] = setup.stdout.toString().split('\n')
        const input = [...lines.filter(Boolean), `lang ${langText === 'c' ? 'c' : 'rust'}`, `decompile ${addr.toString(16)}`].join('\n') + '\n'
        const started = Date.now()
        const run = spawnSync(helper, [specs, file, lang], { input, maxBuffer: 1 << 28, timeout: 60000 })
        const out = run.stdout?.toString() ?? ''
        const end = /^@@END (\d+)ms\b/m.exec(out)
        const err = /^@@ERROR (.*)$/m.exec(out)
        if (!end) {
          res.statusCode = 500
          res.end(err ? `The decompiler could not handle this function: ${err[1]}` : `The decompiler stopped (status ${run.status}, signal ${run.signal}, ${run.error?.message ?? ''}).`)
          return
        }
        const code = spawnSync(exe, ['--annotate', file], { input: out.slice(0, end.index), maxBuffer: 1 << 28 }).stdout.toString()
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify({ code, ms: Number(end[1]), total_ms: Date.now() - started }))
      })
      server.middlewares.use('/__mekiki/code_map', (_req, res) => {
        try {
          res.setHeader('content-type', 'application/octet-stream')
          res.end(run(['--code-map', file]))
        } catch (e) {
          res.statusCode = 500
          res.end(String(e))
        }
      })
      server.middlewares.use('/__mekiki/disasm', async (req, res) => {
        try {
          const addrs = (JSON.parse((await body(req)).toString()) as number[]).map(String)
          res.setHeader('content-type', 'application/json')
          res.end(run(['--disasm', file, ...addrs]))
        } catch (e) {
          res.statusCode = 500
          res.end(String(e))
        }
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
