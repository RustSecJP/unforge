// Where files come from and how bytes are read: the Tauri app (Rust in the
// same process), or the browser during `npm run dev:web` (the dev server runs
// the report, and bytes are read from the File object).
import { toOutcome, type Outcome, type SignaturesApplied } from './report'

export interface Opened {
  name: string
  path: string | null
  elapsedMs: number
  outcome: Outcome
  /** null when no file could be analyzed */
  signatures: SignaturesApplied | null
  /** fingerprint database files in use */
  signatureFiles: string[]
  /** why those databases were chosen (rustc version match), if worth saying */
  signatureNote: string | null
  readRange: (offset: number, len: number) => Promise<Uint8Array>
  /** See unforge_report::code::code_map */
  codeMap: () => Promise<Uint8Array>
  disasmAt: (addrs: number[]) => Promise<(InsnText | null)[]>
  /** C-like code of the function at addr (Ghidra's decompiler, no Java) */
  decompile: (addr: number, lang: DecompLang) => Promise<Decompiled>
  cancelDecompile: () => Promise<void>
}

export type DecompLang = 'rust' | 'c'

export interface Decompiled {
  code: string
  ms: number
  total_ms: number
}

export interface InsnText {
  addr: number
  len: number
  mnemonic: string
  operands: string
  flow: 'next' | 'call' | 'jump' | 'cond_jump' | 'return' | 'interrupt' | 'invalid'
  target: number | null
}

const none = {
  readRange: async () => new Uint8Array(),
  codeMap: async () => new Uint8Array(),
  disasmAt: async (a: number[]) => a.map(() => null),
  decompile: async (): Promise<Decompiled> => {
    throw new Error('No file is open.')
  },
  cancelDecompile: async () => {},
}

export const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window

async function openPathInTauri(path: string, command = 'open_file'): Promise<Opened> {
  const { invoke } = await import('@tauri-apps/api/core')
  try {
    const r = await invoke<{ name: string; path: string; elapsed_ms: number; report: unknown; signatures: SignaturesApplied | null; signature_files: string[]; signature_note: string | null }>(
      command,
      command === 'open_file' ? { path } : {},
    )
    return {
      name: r.name,
      path: r.path,
      elapsedMs: r.elapsed_ms,
      outcome: toOutcome(r.report),
      signatures: r.signatures,
      signatureFiles: r.signature_files,
      signatureNote: r.signature_note,
      readRange: async (offset, len) => new Uint8Array(await invoke<ArrayBuffer>('read_range', { offset, len })),
      codeMap: async () => new Uint8Array(await invoke<ArrayBuffer>('code_map')),
      disasmAt: (addrs) => invoke<(InsnText | null)[]>('disasm_at', { addrs }),
      decompile: (addr, lang) => invoke<Decompiled>('decompile', { addr, lang }),
      cancelDecompile: async () => void (await invoke('cancel_decompile')),
    }
  } catch (e) {
    const name = path.split(/[\\/]/).pop() ?? path
    return { name, path, elapsedMs: 0, outcome: { ok: false, error: String(e) }, signatures: null, signatureFiles: [], signatureNote: null, ...none }
  }
}

async function openFileInBrowser(file: File): Promise<Opened> {
  const res = await fetch('/__mekiki/report', { method: 'POST', body: file })
  const body = res.ok ? await res.json() : null
  const outcome: Outcome = body ? toOutcome(body.report ?? body) : { ok: false, error: await res.text() }
  return {
    name: file.name,
    path: null,
    elapsedMs: Number(res.headers.get('x-elapsed-ms') ?? 0),
    outcome,
    signatures: body?.signatures ?? null,
    signatureFiles: body?.signature_files ?? [],
    signatureNote: body?.signature_note ?? null,
    readRange: async (offset, len) => new Uint8Array(await file.slice(offset, offset + len).arrayBuffer()),
    codeMap: async () => new Uint8Array(await (await fetch('/__mekiki/code_map')).arrayBuffer()),
    disasmAt: async (addrs) => (await fetch('/__mekiki/disasm', { method: 'POST', body: JSON.stringify(addrs) })).json(),
    decompile: async (addr, lang) => {
      const res = await fetch('/__mekiki/decompile', { method: 'POST', body: `${addr} ${lang}` })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    cancelDecompile: async () => {},
  }
}

/** Opens a sample Rust binary for the tutorial: Mekiki's own executable in
 * the app, or the dev server's report example in the browser preview. */
export async function openSample(): Promise<Opened | null> {
  if (isTauri) return openPathInTauri('mekiki', 'open_self')
  const res = await fetch('/__mekiki/sample')
  if (!res.ok) return null
  const blob = await res.blob()
  return openFileInBrowser(new File([blob], 'report (sample)'))
}

/** Shows the system's open dialog (or a file input in the browser). */
export async function pickAndOpen(input: HTMLInputElement | null): Promise<Opened | null> {
  if (isTauri) {
    const { open } = await import('@tauri-apps/plugin-dialog')
    const path = await open({ multiple: false, directory: false, title: 'Open a binary' })
    return typeof path === 'string' ? openPathInTauri(path) : null
  }
  if (!input) return null
  return new Promise((resolve) => {
    input.onchange = () => {
      const f = input.files?.[0]
      input.value = ''
      resolve(f ? openFileInBrowser(f) : null)
    }
    input.click()
  })
}

/** Calls `onOpen` for every file dropped on the window. */
export async function listenForDrops(onStart: (name: string) => void, onOpen: (o: Opened) => void, onHover: (on: boolean) => void): Promise<() => void> {
  if (isTauri) {
    const { getCurrentWebview } = await import('@tauri-apps/api/webview')
    return getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload
      if (p.type === 'enter' || p.type === 'over') onHover(true)
      else if (p.type === 'leave') onHover(false)
      else if (p.type === 'drop') {
        onHover(false)
        const path = p.paths[0]
        if (path) {
          onStart(path.split(/[\\/]/).pop() ?? path)
          void openPathInTauri(path).then(onOpen)
        }
      }
    })
  }
  const over = (e: DragEvent) => {
    if (!e.dataTransfer?.types.includes('Files')) return
    e.preventDefault()
    onHover(true)
  }
  const leave = (e: DragEvent) => e.relatedTarget === null && onHover(false)
  const drop = (e: DragEvent) => {
    e.preventDefault()
    onHover(false)
    const f = e.dataTransfer?.files[0]
    if (f) {
      onStart(f.name)
      void openFileInBrowser(f).then(onOpen)
    }
  }
  window.addEventListener('dragover', over)
  window.addEventListener('dragleave', leave)
  window.addEventListener('drop', drop)
  return () => {
    window.removeEventListener('dragover', over)
    window.removeEventListener('dragleave', leave)
    window.removeEventListener('drop', drop)
  }
}

export interface SignatureSummary {
  dir: string
  files: string[]
  broken: string[]
  fingerprints: number
}

/** Picks fingerprint database files and copies them into Mekiki's folder. */
export async function importSignatures(): Promise<SignatureSummary | null> {
  if (!isTauri) throw new Error('Loading fingerprint databases needs the desktop app.')
  const { open } = await import('@tauri-apps/plugin-dialog')
  const picked = await open({ multiple: true, directory: false, title: 'Load fingerprint databases', filters: [{ name: 'Fingerprint database', extensions: ['db'] }] })
  const paths = Array.isArray(picked) ? picked : picked ? [picked] : []
  if (paths.length === 0) return null
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<SignatureSummary>('import_signatures', { paths })
}

/** Adds the open file (with symbols) to the user's own database; returns names added. */
export async function addToSignatures(): Promise<number> {
  if (!isTauri) throw new Error('Building fingerprint databases needs the desktop app.')
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<number>('add_to_signatures')
}

/** Opens the current file again (after the databases changed). */
export async function reopenCurrent(): Promise<Opened | null> {
  if (!isTauri) return null
  const { invoke } = await import('@tauri-apps/api/core')
  const path = await invoke<string | null>('current_path')
  return path ? openPathInTauri(path) : null
}
