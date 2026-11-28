import { ArrowLeft, ArrowRight, FolderOpen, FunctionSquare, MapPin, Package, Search, Folder } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Group, Panel, Separator } from 'react-resizable-panels'
import { isTauri, listenForDrops, openSample, pickAndOpen, type Opened } from './backend'
import { Tour, type TourStep } from './Tour'
import { formatBytes, formatCount, hex, parseAddress } from './format'
import { functionAt, loadedSections, parseCodeMap, rowOfAddress, RowKind } from './listing'
import { buildModel, shortName, type Model, type Selection } from './model'
import { Bottom, type BottomTab, type LogLine } from './panels/Bottom'
import { Decompile } from './panels/Decompile'
import { Inspector } from './panels/Inspector'
import { Listing, type ListingHandle } from './panels/Listing'
import { Pane } from './panels/Pane'
import { ProgramTree, SymbolTree } from './panels/Trees'

const REPO = 'https://github.com/RustSecJP/unforge'
const now = () => new Date().toLocaleTimeString('en-GB')

type Panes = { program: boolean; symbols: boolean; inspector: boolean; bottom: boolean }

interface MenuItem {
  label: string
  keys?: string
  run: () => void
  disabled?: boolean
  checked?: boolean
}

function MenuBar({ menus }: { menus: [string, MenuItem[]][] }) {
  const [open, setOpen] = useState<string | null>(null)
  useEffect(() => {
    if (!open) return
    const close = () => setOpen(null)
    window.addEventListener('mousedown', close)
    return () => window.removeEventListener('mousedown', close)
  }, [open])
  return (
    <nav className="menubar" aria-label="Menu">
      {menus.map(([name, items]) => (
        <div key={name} className="menu" onMouseDown={(e) => e.stopPropagation()}>
          <button type="button" className={open === name ? 'on' : ''} onClick={() => setOpen(open === name ? null : name)} onMouseEnter={() => open && setOpen(name)}>
            {name}
          </button>
          {open === name && (
            <div className="dropdown" role="menu">
              {items.map((it) => (
                <button
                  key={it.label}
                  type="button"
                  role="menuitem"
                  disabled={it.disabled}
                  onClick={() => {
                    setOpen(null)
                    it.run()
                  }}
                >
                  <span className="check">{it.checked ? '✓' : ''}</span>
                  <span>{it.label}</span>
                  <kbd>{it.keys ?? ''}</kbd>
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
    </nav>
  )
}

interface Suggestion {
  icon: React.ReactNode
  label: string
  hint: string
  run: () => void
}

/** The toolbar's one box: an address, a function, a section or a crate. */
function GoTo({ model, onGo, onSelect, inputRef, preset }: { model: Model | null; onGo: (a: number) => void; onSelect: (s: Selection) => void; inputRef: React.RefObject<HTMLInputElement | null>; preset: { text: string; n: number } }) {
  const [q, setQ] = useState('')
  const [active, setActive] = useState(0)
  const [open, setOpen] = useState(false)
  // The tutorial types into the box for the user.
  useEffect(() => {
    if (!preset.n) return
    setQ(preset.text)
    setActive(0)
    setOpen(true)
    inputRef.current?.focus()
  }, [preset, inputRef])
  const items = useMemo<Suggestion[]>(() => {
    if (!model || !q.trim()) return []
    const r = model.report
    const out: Suggestion[] = []
    const a = parseAddress(q)
    if (a !== null) out.push({ icon: <MapPin size={13} />, label: hex(a), hint: 'Go to address', run: () => onGo(a) })
    const t = q.trim().toLowerCase()
    for (const s of r.sections) {
      if (out.length > 6) break
      if (s.name && s.name.toLowerCase().includes(t) && s.flags.includes('A'))
        out.push({ icon: <Folder size={13} />, label: s.name, hint: `section · ${hex(s.addr)}`, run: () => (onGo(s.addr), onSelect({ kind: 'section', index: s.index })) })
    }
    r.crates.forEach((c, i) => {
      if (out.length < 12 && c.name.toLowerCase().includes(t))
        out.push({ icon: <Package size={13} className="ic-crate" />, label: c.name, hint: `crate · ${c.version ?? 'version unknown'}`, run: () => onSelect({ kind: 'crate', index: i }) })
    })
    // functions: prefix matches of the last path segment first, then any match
    const starts: number[] = []
    const contains: number[] = []
    for (let i = 0; i < model.lowerNames.length && starts.length < 40; i++) {
      const n = model.lowerNames[i]
      if (!n) continue
      const k = n.indexOf(t)
      if (k < 0) continue
      const last = n.lastIndexOf('::')
      if (k === last + 2 || k === 0) starts.push(i)
      else if (contains.length < 40) contains.push(i)
    }
    for (const fi of [...starts, ...contains].slice(0, 40)) {
      const f = r.function_rows[fi]
      out.push({ icon: <FunctionSquare size={13} className="ic-fn" />, label: shortName(f.name, f.start), hint: hex(f.start), run: () => (onSelect({ kind: 'function', index: fi }), onGo(f.start)) })
    }
    return out
  }, [model, q, onGo, onSelect])

  const choose = (s: Suggestion | undefined) => {
    if (!s) return
    s.run()
    setOpen(false)
    setQ('')
    inputRef.current?.blur()
  }
  return (
    <div className="goto" data-tour="goto">
      <Search size={13} />
      <input
        ref={inputRef}
        value={q}
        disabled={!model}
        placeholder={model ? 'Go to address, function, section or crate  (G)' : 'Open a file to search it'}
        onChange={(e) => {
          setQ(e.target.value)
          setActive(0)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 120)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') (e.preventDefault(), setActive((i) => Math.min(items.length - 1, i + 1)))
          else if (e.key === 'ArrowUp') (e.preventDefault(), setActive((i) => Math.max(0, i - 1)))
          else if (e.key === 'Enter') choose(items[active])
          else if (e.key === 'Escape') (setQ(''), inputRef.current?.blur())
        }}
        aria-label="Go to"
      />
      {open && model && q.trim() && items.length === 0 && (
        <div className="suggest">
          <div className="none">No address, function, section or crate matches “{q.trim()}”.</div>
        </div>
      )}
      {open && items.length > 0 && (
        <div className="suggest" role="listbox">
          {items.map((s, i) => (
            <div key={i} role="option" aria-selected={i === active} className={i === active ? 'on' : ''} onMouseDown={() => choose(s)} onMouseEnter={() => setActive(i)}>
              {s.icon}
              <span className="slabel">{s.label}</span>
              <span className="shint">{s.hint}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

const ja = typeof navigator !== 'undefined' && navigator.language.toLowerCase().startsWith('ja')
const t = (jaText: string, en: string) => (ja ? jaText : en)

export function App() {
  const [opened, setOpened] = useState<Opened | null>(null)
  const [model, setModel] = useState<Model | null>(null)
  const [loading, setLoading] = useState<string | null>(null)
  const [hover, setHover] = useState(false)
  const [sel, setSel] = useState<Selection | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [history, setHistory] = useState<{ list: number[]; at: number }>({ list: [], at: -1 })
  const [panes, setPanes] = useState<Panes>({ program: true, symbols: true, inspector: true, bottom: true })
  const [bottomTab, setBottomTab] = useState<BottomTab>('console')
  const [log, setLog] = useState<LogLine[]>([{ time: now(), text: `Mekiki ready${isTauri ? '' : ' (browser preview)'}. Open a binary with File → Open (Ctrl+O) or drop it on the window.` }])
  const fileInput = useRef<HTMLInputElement>(null)
  const listing = useRef<ListingHandle>(null)
  const gotoInput = useRef<HTMLInputElement>(null)
  // Row the Listing starts at for a newly opened file (the entry point).
  const [startRow, setStartRow] = useState(0)
  const [gotoPreset, setGotoPreset] = useState({ text: '', n: 0 })
  const [rightTab, setRightTab] = useState<'decompile' | 'inspector'>('decompile')
  const [touring, setTouring] = useState(() => localStorage.getItem('mekiki.tutorial.done') !== '1')

  const say = useCallback((text: string, tone?: LogLine['tone']) => setLog((l) => [...l.slice(-500), { time: now(), text, tone }]), [])

  const show = useCallback(
    async (o: Opened) => {
      if (!o.outcome.ok) {
        setLoading(null)
        say(`Could not read ${o.name}: ${o.outcome.error}`, 'error')
        setBottomTab('console')
        return
      }
      const r = o.outcome.report
      const started = performance.now()
      const code = parseCodeMap(await o.codeMap())
      const m = buildModel(r, code)
      setLoading(null)
      setOpened(o)
      setModel(m)
      setSel(null)
      say(
        `Opened ${o.name} (${formatBytes(r.file.size)}, ${r.file.class} ${r.file.machine} ${r.file.kind}) in ${o.elapsedMs} ms: ${formatCount(r.crates.length)} crates, ${formatCount(r.functions.total)} functions, ${formatCount(r.warnings.length + r.warnings_omitted)} warnings.`,
        'ok',
      )
      if (r.rustc_commit) say(`Built with rustc commit ${r.rustc_commit}.`)
      if (code.size > 0) {
        let n = 0
        for (const l of code.values()) n += l.length
        say(`Disassembled ${formatCount(code.size)} functions (${formatCount(n)} instructions) in ${Math.round(performance.now() - started)} ms.`)
      } else say(`No disassembly: ${r.file.machine} is not supported yet (x86 and x86-64 are).`)
      if (r.functions.total <= 1) say('Almost no functions were found: the file is probably stripped. Crates found from source paths are still listed.')
      // Start at the entry point when it is in a loaded section, else at the first row.
      const entryRow = r.file.entry ? rowOfAddress(m.listing, r.file.entry) : -1
      const start = entryRow >= 0 ? entryRow : 0
      setCursor(m.listing.count ? start : null)
      setStartRow(start)
      setHistory(m.listing.count ? { list: [m.listing.addr[start]], at: 0 } : { list: [], at: -1 })
    },
    [say],
  )

  const openDialog = useCallback(async () => {
    const o = await pickAndOpen(fileInput.current)
    if (o) await show(o)
  }, [show])

  useEffect(() => {
    let off: (() => void) | null = null
    void listenForDrops((name) => setLoading(name), (o) => void show(o), setHover).then((f) => (off = f))
    return () => off?.()
  }, [show])

  const goTo = useCallback(
    (a: number, record = true) => {
      if (!model) return
      const row = rowOfAddress(model.listing, a)
      if (row < 0) {
        say(`${hex(a)} is not inside a loaded section.`, 'error')
        return
      }
      setCursor(row)
      listing.current?.scrollToRow(row)
      const fi = model.fnByStart.get(a)
      setSel(fi !== undefined ? { kind: 'function', index: fi } : { kind: 'address', addr: a })
      if (record)
        setHistory((h) => {
          const list = [...h.list.slice(0, h.at + 1), a].slice(-200)
          return { list, at: list.length - 1 }
        })
    },
    [model, say],
  )

  const back = useCallback(() => {
    setHistory((h) => {
      if (h.at <= 0) return h
      goTo(h.list[h.at - 1], false)
      return { ...h, at: h.at - 1 }
    })
  }, [goTo])
  const forward = useCallback(() => {
    setHistory((h) => {
      if (h.at >= h.list.length - 1) return h
      goTo(h.list[h.at + 1], false)
      return { ...h, at: h.at + 1 }
    })
  }, [goTo])

  // Keyboard shortcuts (not while typing in a box)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.tagName === 'INPUT'
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') {
        e.preventDefault()
        void openDialog()
      } else if (e.altKey && e.key === 'ArrowLeft') {
        e.preventDefault()
        back()
      } else if (e.altKey && e.key === 'ArrowRight') {
        e.preventDefault()
        forward()
      } else if (!typing && (e.key === 'g' || e.key === 'G' || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k'))) {
        e.preventDefault()
        gotoInput.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [openDialog, back, forward])

  const onCursor = (row: number) => {
    setCursor(row)
    if (!model) return
    const m = model.listing
    if (m.kind[row] === RowKind.Function) setSel({ kind: 'function', index: m.func[row] })
    else setSel({ kind: 'address', addr: m.addr[row] })
  }

  const close = () => {
    setOpened(null)
    setModel(null)
    setSel(null)
    setCursor(null)
    say('Closed the file.')
  }

  const toggle = (k: keyof Panes) => setPanes((p) => ({ ...p, [k]: !p[k] }))
  const r = model?.report
  const cursorAddr = model && cursor !== null ? model.listing.addr[cursor] : null
  const cursorFn = model && cursorAddr !== null ? functionAt(model.report.function_rows, cursorAddr) : -1
  const cursorSec = model && cursorAddr !== null ? loadedSections(model.report).find((s) => cursorAddr >= s.addr && cursorAddr < s.addr + s.size) : undefined

  const menus: [string, MenuItem[]][] = [
    [
      'File',
      [
        { label: 'Open…', keys: 'Ctrl+O', run: () => void openDialog() },
        { label: 'Close File', run: close, disabled: !model },
      ],
    ],
    [
      'Navigation',
      [
        { label: 'Go To…', keys: 'G', run: () => gotoInput.current?.focus(), disabled: !model },
        { label: 'Back', keys: 'Alt+←', run: back, disabled: history.at <= 0 },
        { label: 'Forward', keys: 'Alt+→', run: forward, disabled: history.at >= history.list.length - 1 },
        { label: 'Go To Entry Point', run: () => r && goTo(r.file.entry), disabled: !r?.file.entry },
      ],
    ],
    [
      'Window',
      [
        { label: 'Program Tree', run: () => toggle('program'), checked: panes.program },
        { label: 'Symbol Tree', run: () => toggle('symbols'), checked: panes.symbols },
        { label: 'Decompile / Inspector', run: () => toggle('inspector'), checked: panes.inspector },
        { label: 'Console / Tables', run: () => toggle('bottom'), checked: panes.bottom },
        { label: 'Functions', run: () => (setPanes((p) => ({ ...p, bottom: true })), setBottomTab('functions')), disabled: !model },
        { label: 'Crates', run: () => (setPanes((p) => ({ ...p, bottom: true })), setBottomTab('crates')), disabled: !model },
        { label: 'Warnings', run: () => (setPanes((p) => ({ ...p, bottom: true })), setBottomTab('warnings')), disabled: !model },
      ],
    ],
    [
      'Help',
      [
        { label: ja ? 'Tutorial（使い方の案内）' : 'Tutorial', run: () => setTouring(true) },
        { label: 'unforge on GitHub', run: () => window.open(REPO, '_blank') },
        { label: 'About Mekiki', run: () => say('Mekiki 0.1 — a desktop UI for unforge, which reads Rust binaries as Rust. Files are analyzed on this computer only.') },
      ],
    ],
  ]

  const left = panes.program || panes.symbols
  const endTour = () => {
    setTouring(false)
    localStorage.setItem('mekiki.tutorial.done', '1')
  }
  const showMePanel = (k: keyof Panes) => setPanes((p) => ({ ...p, [k]: true }))
  const tourSteps: TourStep[] = [
    {
      title: t('Mekiki へようこそ', 'Welcome to Mekiki'),
      body: t(
        'Rust で作られたプログラム（バイナリ）の中身を見る道具です。まず練習用のファイルを開きましょう。Mekiki 自身も Rust のプログラムなので、それを開きます。',
        'Mekiki shows what is inside a program built with Rust. Let’s open a file to practice on: Mekiki itself, which is a Rust program too.',
      ),
      action: { label: t('練習用のファイルを開く', 'Open the practice file'), advance: true, run: async () => { const o = await openSample(); if (o) await show(o) } },
      ready: () => model !== null,
    },
    {
      target: '[data-tour=listing]',
      title: t('真ん中：プログラムの命令', 'Center: the program’s instructions'),
      body: t(
        'プログラムの中身を、上から順に1行ずつ表示します。左から「アドレス（場所）」「機械語のバイト」「命令」です。いまはプログラムが最初に動く場所（エントリポイント）にいます。青い太字の行は関数の始まりです。',
        'The program, one instruction per line: address, machine-code bytes, instruction. You start where the program starts running (the entry point). Bold blue lines are where functions begin.',
      ),
    },
    {
      target: '.l-xref',
      title: t('緑の「→ 名前」は飛び先', 'Green “→ name” is where it goes'),
      body: t(
        '命令が呼び出したり指したりしている関数の名前です。押すと、その関数へ移ります。下のボタンで、代わりに押してみます。',
        'The function an instruction calls or points to. Click it to go there — or let the button do it.',
      ),
      action: { label: t('押してみる', 'Show me'), advance: true, run: () => (document.querySelector('.l-xref') as HTMLElement | null)?.click() },
    },
    {
      target: '[data-tour=back]',
      title: t('戻る', 'Back'),
      body: t('移る前の場所へ戻ります。キーボードなら Alt+← です（進むは Alt+→）。', 'Returns to where you were. Keyboard: Alt+← (and Alt+→ to go forward).'),
      action: { label: t('戻ってみる', 'Show me'), run: back },
    },
    {
      target: '[data-tour=goto]',
      title: t('名前やアドレスで探す', 'Find by name or address'),
      body: t(
        'G キーを押すとここに入力できます。関数名・アドレス（例: 0x401000）・ライブラリ名を打つと候補が出て、Enter でそこへ移ります。',
        'Press G to type here: a function name, an address (like 0x401000) or a library name. Pick a suggestion with Enter.',
      ),
      action: { label: t('「main」を探してみる', 'Search for “main”'), run: () => setGotoPreset((p) => ({ text: 'main', n: p.n + 1 })) },
    },
    {
      target: '[data-tour=symbols]',
      title: t('左下：関数を持ち主ごとに', 'Lower left: functions by owner'),
      body: t(
        '「Program」はこのプログラム自身のコード、「Crates」は使っているライブラリ（名前と版）、「Standard library」は Rust の標準ライブラリです。怪しいプログラムを調べるときは、まず Program の中を見るのが近道です。',
        '“Program” is the program’s own code, “Crates” the libraries it uses (with versions), “Standard library” Rust’s own. When checking a suspicious program, start with Program.',
      ),
      action: { label: t('表示する', 'Show it'), run: () => showMePanel('symbols') },
    },
    {
      target: '[data-tour=inspector]',
      title: t('右：選んだものの詳しい情報', 'Right: details of what you pick'),
      body: t(
        '選んだ関数やライブラリの詳しい情報が出ます。ライブラリなら crates.io（Rust のライブラリの置き場）へのリンクもあります。',
        'Details of the selected function or library, with links to crates.io for libraries.',
      ),
      action: { label: t('表示する', 'Show it'), run: () => showMePanel('inspector') },
    },
    {
      target: '[data-tour=bottom]',
      title: t('下：一覧表', 'Bottom: tables'),
      body: t(
        '「Functions」は関数の一覧です。見出しの「Size」を押して大きい順に並べると、大きな処理が見つかります。「Crates」はライブラリと版の一覧、「Warnings」はファイルの作りの怪しい点です。',
        '“Functions” lists every function — click “Size” to find the big ones. “Crates” lists libraries and versions; “Warnings” lists odd things about the file’s structure.',
      ),
      action: { label: t('関数の一覧を開く', 'Open Functions'), run: () => (showMePanel('bottom'), setBottomTab('functions')) },
    },
    {
      title: t('これで一通りです', 'That’s the tour'),
      body: t(
        '自分のファイルは Ctrl+O か、ウィンドウにドロップすると開けます。この案内は、メニューの Help → Tutorial でいつでも見直せます。',
        'Open your own files with Ctrl+O or by dropping them on the window. Replay this any time from Help → Tutorial.',
      ),
    },
  ]
  return (
    <div className="app">
      <MenuBar menus={menus} />
      <div className="toolbar">
        <button type="button" title="Open (Ctrl+O)" onClick={() => void openDialog()}>
          <FolderOpen size={16} />
        </button>
        <span className="tsep" />
        <button type="button" title="Back (Alt+←)" onClick={back} disabled={history.at <= 0} data-tour="back">
          <ArrowLeft size={16} />
        </button>
        <button type="button" title="Forward (Alt+→)" onClick={forward} disabled={history.at >= history.list.length - 1}>
          <ArrowRight size={16} />
        </button>
        <span className="tsep" />
        <GoTo model={model} onGo={goTo} onSelect={setSel} inputRef={gotoInput} preset={gotoPreset} />
      </div>
      <input ref={fileInput} type="file" hidden />

      <Group orientation="vertical" className="work">
        <Panel minSize={200}>
          <Group orientation="horizontal">
            {left && (
              <>
                <Panel defaultSize={270} minSize={170}>
                  <Group orientation="vertical">
                    {panes.program && (
                      <Panel minSize={80} defaultSize="38">
                        <Pane title="Program Tree">{model && opened ? <ProgramTree model={model} name={opened.name} sel={sel} onSelect={setSel} onGo={goTo} /> : <p className="empty">No file</p>}</Pane>
                      </Panel>
                    )}
                    {panes.program && panes.symbols && <Separator className="sep-h" />}
                    {panes.symbols && (
                      <Panel minSize={100}>
                        <Pane title="Symbol Tree" tour="symbols">{model ? <SymbolTree model={model} sel={sel} onSelect={setSel} onGo={goTo} /> : <p className="empty">No file</p>}</Pane>
                      </Panel>
                    )}
                  </Group>
                </Panel>
                <Separator className="sep-v" />
              </>
            )}
            <Panel minSize={360}>
              <Pane tour="listing" title={opened ? `Listing: ${opened.name}` : 'Listing'} tools={cursorAddr !== null ? <code>{hex(cursorAddr)}</code> : undefined}>
                {model && opened ? (
                  <Listing ref={listing} model={model} readRange={opened.readRange} disasmAt={opened.disasmAt} onGo={goTo} initialRow={startRow} cursorRow={cursor} onCursor={onCursor} onOpenFunction={(fi) => setSel({ kind: 'function', index: fi })} />
                ) : (
                  <div className="welcome">
                    {loading ? (
                      <>
                        <span className="spinner" />
                        <p>Reading {loading}…</p>
                      </>
                    ) : (
                      <>
                        <h1>Mekiki</h1>
                        <p>Open a Rust binary to see which crates and functions are inside it.</p>
                        <button type="button" className="primary" onClick={() => void openDialog()}>
                          <FolderOpen size={15} /> Open a file… <kbd>Ctrl+O</kbd>
                        </button>
                        <p className="muted">or drop it anywhere on this window. Nothing leaves this computer.</p>
                      </>
                    )}
                  </div>
                )}
              </Pane>
            </Panel>
            {panes.inspector && (
              <>
                <Separator className="sep-v" />
                <Panel defaultSize={420} minSize={220}>
                  <section className="pane" tabIndex={-1} data-tour="inspector">
                    <header className="pane-title tabs">
                      <button type="button" className={rightTab === 'decompile' ? 'on' : ''} onClick={() => setRightTab('decompile')}>
                        Decompile
                      </button>
                      <button type="button" className={rightTab === 'inspector' ? 'on' : ''} onClick={() => setRightTab('inspector')}>
                        Inspector
                      </button>
                    </header>
                    <div className="pane-body">
                      {!model || !opened ? (
                        <p className="empty">No file</p>
                      ) : rightTab === 'decompile' ? (
                        <Decompile model={model} opened={opened} fi={cursorFn} onGo={goTo} />
                      ) : (
                        <Inspector model={model} sel={sel} />
                      )}
                    </div>
                  </section>
                </Panel>
              </>
            )}
          </Group>
        </Panel>
        {panes.bottom && (
          <>
            <Separator className="sep-h" />
            <Panel defaultSize={220} minSize={90}>
              <Bottom model={model} tab={bottomTab} onTab={setBottomTab} log={log} sel={sel} onSelect={setSel} onGo={goTo} />
            </Panel>
          </>
        )}
      </Group>

      <footer className="statusbar">
        <span>{opened ? opened.name : 'No file'}</span>
        {r && (
          <span>
            {r.file.class} · {r.file.machine} · {r.file.kind} · {formatBytes(r.file.size)}
            {r.file.stripped ? ' · stripped' : ''}
          </span>
        )}
        <span className="grow" />
        {cursorSec && <span>{cursorSec.name}</span>}
        {cursorFn >= 0 && model && <span className="sfn">{shortName(model.report.function_rows[cursorFn].name, model.report.function_rows[cursorFn].start)}</span>}
        {cursorAddr !== null && <code>{hex(cursorAddr)}</code>}
      </footer>
      {hover && <div className="drop-overlay">Drop to open</div>}
      {touring && (
        <Tour
          steps={tourSteps}
          onClose={endTour}
          labels={{ next: t('次へ', 'Next'), back: t('戻る', 'Back'), done: t('終わる', 'Done'), skip: t('閉じる', 'Close'), of: '/' }}
        />
      )}
    </div>
  )
}
