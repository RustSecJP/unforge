import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { DecompLang, Decompiled, Opened } from '../backend'
import { shortName, type Model } from '../model'

type Entry = { kind: 'ok'; d: Decompiled } | { kind: 'error'; message: string }

const KEYWORDS = new Set(['if', 'else', 'while', 'do', 'for', 'return', 'break', 'continue', 'switch', 'case', 'default', 'goto', 'sizeof', 'fn', 'let', 'mut', 'loop', 'as', 'match', 'true', 'false'])
const TYPE = /^(void|bool|char|float|double|float10|code|(u?int|xunknown|unkbyte|undefined)\d*|(u)?long|byte|word|dword|qword|wchar_t|string|[iu](8|16|32|64|128|size)|f(32|64|80))$/
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
    // `//` comments are Mekiki's explanations (strings, panic locations); `/* */` are Ghidra's
    if (comment) out.push(<span key={key++} className={text.startsWith('//') ? 'd-note' : 'd-comment'}>{text}</span>)
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

// Ghidra puts its own block comments (WARNING …) far to the right; indent
// them like the statement that follows instead.
export function tidy(code: string): string {
  const lines = code.replace(/^\n+/, '').split('\n')
  for (let i = lines.length - 2; i >= 0; i--) {
    const t = lines[i].trim()
    if (t.startsWith('/*') && t.endsWith('*/')) {
      const next = lines.slice(i + 1).find((l) => l.trim() !== '') ?? ''
      lines[i] = next.slice(0, next.length - next.trimStart().length) + t
    }
  }
  return lines.join('\n')
}

export function Decompile({ model, opened, fi, onGo }: { model: Model; opened: Opened; fi: number; onGo: (addr: number) => void }) {
  const cache = useRef(new Map<string, Entry>())
  const [lang, setLangState] = useState<DecompLang>(() => (localStorage.getItem('mekiki.decompLang') === 'c' ? 'c' : 'rust'))
  const setLang = (l: DecompLang) => {
    setLangState(l)
    localStorage.setItem('mekiki.decompLang', l)
  }
  const busy = useRef(false)
  const [, bump] = useState(0)
  const [pending, setPending] = useState<number | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const f = fi >= 0 ? model.report.function_rows[fi] : null
  const start = f?.start ?? null
  const key = start === null ? null : `${lang}:${start}`

  // A new file: forget everything.
  useEffect(() => {
    cache.current = new Map()
    bump((n) => n + 1)
  }, [opened])

  // Decompile the function under the cursor once it stays there a moment.
  useEffect(() => {
    if (start === null || key === null || cache.current.has(key)) {
      setPending(null)
      return
    }
    let gone = false
    const t = window.setTimeout(async () => {
      if (busy.current) await opened.cancelDecompile()
      busy.current = true
      setPending(start)
      try {
        const d = await opened.decompile(start, lang)
        cache.current.set(key, { kind: 'ok', d })
      } catch (e) {
        const message = String(e instanceof Error ? e.message : e)
        if (!gone || !/cancel/i.test(message)) cache.current.set(key, { kind: 'error', message })
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
  }, [start, key, lang, opened])

  useEffect(() => {
    if (pending === null) return
    const t0 = Date.now()
    setElapsed(0)
    const t = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 500)
    return () => window.clearInterval(t)
  }, [pending])

  if (!f) return <p className="empty">Put the cursor inside a function in the Listing to decompile it.</p>
  const entry = key ? cache.current.get(key) : undefined
  return (
    <div className="decompile">
      <div className="d-head">
        <span className="d-name" title={f.name ?? ''}>
          {shortName(f.name, f.start)}
        </span>
        {entry?.kind === 'ok' && <span className="d-meta">{entry.d.ms < 1 ? '<1' : entry.d.ms} ms</span>}
        <span className="d-lang" role="group" aria-label="Output language">
          <button type="button" className={lang === 'rust' ? 'on' : ''} onClick={() => setLang('rust')} title="Rust-style output">
            Rust
          </button>
          <button type="button" className={lang === 'c' ? 'on' : ''} onClick={() => setLang('c')} title="Ghidra's C output">
            C
          </button>
        </span>
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
      {entry?.kind === 'ok' && <pre className="d-code">{highlight(tidy(entry.d.code), model, onGo)}</pre>}
    </div>
  )
}
