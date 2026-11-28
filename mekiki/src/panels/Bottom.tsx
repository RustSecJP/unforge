import { useVirtualizer } from '@tanstack/react-virtual'
import { AlertTriangle, ArrowDown, ArrowUp, Search } from 'lucide-react'
import { useMemo, useRef, useState, type ReactNode } from 'react'
import { formatBytes, formatCount, hex } from '../format'
import { crateOfFunction, ownerLabel, shortName, type Model, type Selection } from '../model'

export interface LogLine {
  time: string
  text: string
  tone?: 'error' | 'ok'
}

interface Column<T> {
  key: string
  label: string
  width: string
  num?: boolean
  value: (row: T) => string | number
  render?: (row: T) => ReactNode
}

/** A sortable, filterable, virtualized table (Ghidra's table windows). */
function VTable<T>({
  rows,
  columns,
  selected,
  onSelect,
  onActivate,
  filterText,
  initialSort,
}: {
  rows: T[]
  columns: Column<T>[]
  selected: (row: T) => boolean
  onSelect: (row: T) => void
  onActivate?: (row: T) => void
  filterText: (row: T) => string
  initialSort: { key: string; desc: boolean }
}) {
  const [sort, setSort] = useState(initialSort)
  const [filter, setFilter] = useState('')
  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase()
    const list = q ? rows.filter((r) => filterText(r).toLowerCase().includes(q)) : rows.slice()
    const col = columns.find((c) => c.key === sort.key)
    if (col) {
      list.sort((a, b) => {
        const x = col.value(a)
        const y = col.value(b)
        const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))
        return sort.desc ? -c : c
      })
    }
    return list
  }, [rows, columns, sort, filter, filterText])
  const el = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: shown.length, getScrollElement: () => el.current, estimateSize: () => 20, overscan: 20 })
  const template = columns.map((c) => c.width).join(' ')
  return (
    <div className="vtable">
      <div className="vthead" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => (
          <button
            key={c.key}
            type="button"
            className={c.num ? 'num' : ''}
            onClick={() => setSort((s) => ({ key: c.key, desc: s.key === c.key ? !s.desc : !!c.num }))}
          >
            {c.label}
            {sort.key === c.key && (sort.desc ? <ArrowDown size={11} /> : <ArrowUp size={11} />)}
          </button>
        ))}
      </div>
      <div className="vtbody" ref={el}>
        <div style={{ height: v.getTotalSize(), position: 'relative' }}>
          {v.getVirtualItems().map((it) => {
            const row = shown[it.index]
            return (
              <div
                key={it.index}
                className={`vtrow ${selected(row) ? 'sel' : ''}`}
                style={{ transform: `translateY(${it.start}px)`, gridTemplateColumns: template }}
                onClick={() => onSelect(row)}
                onDoubleClick={() => onActivate?.(row)}
              >
                {columns.map((c) => (
                  <span key={c.key} className={c.num ? 'num' : ''}>
                    {c.render ? c.render(row) : c.value(row)}
                  </span>
                ))}
              </div>
            )
          })}
        </div>
      </div>
      <label className="table-filter">
        <Search size={12} />
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter" aria-label="Filter table" />
        <span className="thint">
          {formatCount(shown.length)} / {formatCount(rows.length)}
        </span>
      </label>
    </div>
  )
}

export type BottomTab = 'console' | 'functions' | 'crates' | 'warnings'

export function Bottom({
  model,
  tab,
  onTab,
  log,
  sel,
  onSelect,
  onGo,
}: {
  model: Model | null
  tab: BottomTab
  onTab: (t: BottomTab) => void
  log: LogLine[]
  sel: Selection | null
  onSelect: (s: Selection) => void
  onGo: (addr: number) => void
}) {
  const r = model?.report
  const tabs: [BottomTab, string, number | null][] = [
    ['console', 'Console', null],
    ['functions', 'Functions', r ? r.functions.total : null],
    ['crates', 'Crates', r ? r.crates.length : null],
    ['warnings', 'Warnings', r ? r.warnings.length + r.warnings_omitted : null],
  ]
  const fnIdx = useMemo(() => (r ? r.function_rows.map((_, i) => i) : []), [r])
  const crIdx = useMemo(() => (r ? r.crates.map((_, i) => i) : []), [r])
  const wIdx = useMemo(() => (r ? r.warnings.map((_, i) => i) : []), [r])

  return (
    <section className="pane bottom" tabIndex={-1} data-tour="bottom">
      <header className="pane-title tabs">
        {tabs.map(([k, label, n]) => (
          <button key={k} type="button" className={tab === k ? 'on' : ''} onClick={() => onTab(k)} disabled={k !== 'console' && !r}>
            {k === 'warnings' && n ? <AlertTriangle size={12} className="ic-warn" /> : null}
            {label}
            {n !== null && <span className="tcount">{formatCount(n)}</span>}
          </button>
        ))}
      </header>
      <div className="pane-body">
        {tab === 'console' && (
          <div className="console">
            {log.map((l, i) => (
              <p key={i} className={l.tone ?? ''}>
                <span className="ctime">{l.time}</span> {l.text}
              </p>
            ))}
          </div>
        )}
        {tab === 'functions' && model && r && (
          <VTable
            rows={fnIdx}
            initialSort={{ key: 'addr', desc: false }}
            filterText={(i) => r.function_rows[i].name ?? ''}
            selected={(i) => sel?.kind === 'function' && sel.index === i}
            onSelect={(i) => {
              onSelect({ kind: 'function', index: i })
              onGo(r.function_rows[i].start)
            }}
            columns={[
              { key: 'addr', label: 'Address', width: '120px', value: (i) => r.function_rows[i].start, render: (i) => <code>{hex(r.function_rows[i].start)}</code> },
              { key: 'name', label: 'Name', width: 'minmax(200px, 1fr)', value: (i) => shortName(r.function_rows[i].name, r.function_rows[i].start) },
              { key: 'size', label: 'Size', width: '90px', num: true, value: (i) => r.function_rows[i].size },
              {
                key: 'owner',
                label: 'Owner',
                width: '200px',
                value: (i) => {
                  const c = crateOfFunction(model, i)
                  return c ? c.name : ownerLabel(r.function_rows[i].owner)
                },
              },
            ]}
          />
        )}
        {tab === 'crates' && r && (
          <VTable
            rows={crIdx}
            initialSort={{ key: 'name', desc: false }}
            filterText={(i) => `${r.crates[i].name} ${r.crates[i].version ?? ''}`}
            selected={(i) => sel?.kind === 'crate' && sel.index === i}
            onSelect={(i) => onSelect({ kind: 'crate', index: i })}
            columns={[
              { key: 'name', label: 'Crate', width: 'minmax(180px, 1fr)', value: (i) => r.crates[i].name },
              { key: 'version', label: 'Version', width: '140px', value: (i) => r.crates[i].version ?? '' },
              { key: 'functions', label: 'Functions', width: '100px', num: true, value: (i) => r.crates[i].functions },
              { key: 'bytes', label: 'Code size', width: '100px', num: true, value: (i) => r.crates[i].bytes, render: (i) => (r.crates[i].bytes ? formatBytes(r.crates[i].bytes) : '—') },
              {
                key: 'found',
                label: 'Found in',
                width: '140px',
                value: (i) => ({ both: 'path + symbols', path: 'source path', symbols: 'symbols only' })[r.crates[i].found_in],
              },
            ]}
          />
        )}
        {tab === 'warnings' && r && (
          <VTable
            rows={wIdx}
            initialSort={{ key: 'sev', desc: true }}
            filterText={(i) => `${r.warnings[i].message} ${r.warnings[i].kind}`}
            selected={(i) => sel?.kind === 'warning' && sel.index === i}
            onSelect={(i) => onSelect({ kind: 'warning', index: i })}
            columns={[
              {
                key: 'sev',
                label: 'Severity',
                width: '120px',
                value: (i) => ({ note: 0, warning: 1, 'would not load': 2 })[r.warnings[i].severity] ?? 0,
                render: (i) => <span className={`sev-${r.warnings[i].severity.replace(/ /g, '-')}`}>{r.warnings[i].severity}</span>,
              },
              { key: 'msg', label: 'Finding', width: 'minmax(300px, 1fr)', value: (i) => r.warnings[i].message },
              { key: 'cat', label: 'Category', width: '110px', value: (i) => r.warnings[i].category },
              { key: 'off', label: 'Offset', width: '100px', num: true, value: (i) => r.warnings[i].offset ?? -1, render: (i) => (r.warnings[i].offset === null ? '—' : <code>{hex(r.warnings[i].offset!)}</code>) },
            ]}
          />
        )}
      </div>
    </section>
  )
}
