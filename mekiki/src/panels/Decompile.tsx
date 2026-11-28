import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { Decompiled, Opened } from '../backend'
import { shortName, type Model } from '../model'

type Entry = { kind: 'ok'; d: Decompiled } | { kind: 'error'; message: string }

const KEYWORDS = new Set(['if', 'else', 'while', 'do', 'for', 'return', 'break', 'continue', 'switch', 'case', 'default', 'goto', 'sizeof'])
const TYPE = /^(void|bool|char|float|double|float10|code|(u?int|xunknown|unkbyte|undefined)\d*|(u)?long|byte|word|dword|qword|wchar_t|string)$/
const TOKEN = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(\b0x[0-9a-fA-F]+\b|\b\d+\b)|([A-Za-z_][A-Za-z0-9_]*)|([\s\S])/g

/** Syntax-colors Ghidra's C output; names of known functions become links. */
function highlight(code: string, model: Model, onGo: (addr: number) => void): ReactNode[] {
  const out: ReactNode[] = []
  // Ghidra prints full Rust paths with `::` and generics; link the longest
  // known function name that starts at each position.
  const names = model.fnByName
  let i = 0
  let key = 0
  while (i < code.length) {
    // try a known function name here (names can contain spaces, `<`, `::`)
    const ch = code[i]
    if (/[A-Za-z_<]/.test(ch) && (i === 0 || !/[A-Za-z0-9_]/.test(code[i - 1]))) {
      const lineEnd = code.indexOf('\n', i)
      const rest = code.slice(i, lineEnd < 0 ? undefined : lineEnd)
      const paren = rest.indexOf('(')
      if (paren > 0) {
        const name = rest.slice(0, paren).trimEnd()
        const fi = names.get(name)
        if (fi !== undefined) {
          const start = model.report.function_rows[fi].start
          out.push(
            <a key={key++} className="d-fn" onClick={() => onGo(start)} title={`Go to ${name}`}>
              {name}
            </a>,
          )
          i += name.length
          continue
        }
      }
    }
    TOKEN.lastIndex = i
    const m = TOKEN.exec(code)
    if (!m) break
    const [text, comment, str, num, ident] = m
    if (comment) out.push(<span key={key++} className="d-comment">{text}</span>)
    else if (str) out.push(<span key={key++} className="d-str">{text}</span>)
    else if (num) out.push(<span key={key++} className="d-num">{text}</span>)
    else if (ident && KEYWORDS.has(ident)) out.push(<span key={key++} className="d-kw">{text}</span>)
    else if (ident && TYPE.test(ident)) out.push(<span key={key++} className="d-type">{text}</span>)
    else if (ident && /^(param|[a-z]Var|[a-z]{1,3}Var|[a-z]+Stack)_?\w*$/.test(ident)) out.push(<span key={key++} className="d-var">{text}</span>)
    else out.push(text)
    i = TOKEN.lastIndex
  }
  return out
}

export function Decompile({ model, opened, fi, onGo }: { model: Model; opened: Opened; fi: number; onGo: (addr: number) => void }) {
  const cache = useRef(new Map<number, Entry>())
  const busy = useRef(false)
  const [, bump] = useState(0)
  const [pending, setPending] = useState<number | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const f = fi >= 0 ? model.report.function_rows[fi] : null
  const start = f?.start ?? null

  // A new file: forget everything.
  useEffect(() => {
    cache.current = new Map()
    bump((n) => n + 1)
  }, [opened])

  // Decompile the function under the cursor once it stays there a moment.
  useEffect(() => {
    if (start === null || cache.current.has(start)) {
      setPending(null)
      return
    }
    let gone = false
    const t = window.setTimeout(async () => {
      if (busy.current) await opened.cancelDecompile()
      busy.current = true
      setPending(start)
      try {
        const d = await opened.decompile(start)
        cache.current.set(start, { kind: 'ok', d })
      } catch (e) {
        const message = String(e instanceof Error ? e.message : e)
        if (!gone || !/cancel/i.test(message)) cache.current.set(start, { kind: 'error', message })
      } finally {
        busy.current = false
        if (!gone) setPending(null)
        bump((n) => n + 1)
      }
    }, 250)
    return () => {
      gone = true
      window.clearTimeout(t)
    }
  }, [start, opened])

  useEffect(() => {
    if (pending === null) return
    const t0 = Date.now()
    setElapsed(0)
    const t = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500)
    return () => window.clearInterval(t)
  }, [pending])

  if (!f) return <p className="empty">Put the cursor inside a function in the Listing to decompile it.</p>
  const entry = cache.current.get(f.start)
  return (
    <div className="decompile">
      <div className="d-head">
        <span className="d-name" title={f.name ?? ''}>
          {shortName(f.name, f.start)}
        </span>
        {entry?.kind === 'ok' && <span className="d-meta">Ghidra decompiler · {entry.d.ms < 1 ? '<1' : entry.d.ms} ms</span>}
      </div>
      {!entry && (
        <div className="d-wait">
          <span className="spinner" />
          <p>
            Decompiling… {elapsed > 0 && `${elapsed} s`}
            {elapsed >= 3 && <><br /><span className="muted">Large functions can take a while (up to 60 s).</span></>}
          </p>
          {elapsed >= 2 && (
            <button type="button" onClick={() => void opened.cancelDecompile()}>
              Cancel
            </button>
          )}
        </div>
      )}
      {entry?.kind === 'error' && <p className="d-error">{entry.message}</p>}
      {entry?.kind === 'ok' && <pre className="d-code">{highlight(entry.d.code.replace(/^\n+/, ''), model, onGo)}</pre>}
    </div>
  )
}
