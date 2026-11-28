import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronDown, ChevronRight, Cpu, File, Folder, FunctionSquare, Layers, Package, Search } from 'lucide-react'
import { useMemo, useRef, useState, type ReactNode } from 'react'
import { addr as fmtAddr, formatBytes, formatCount } from '../format'
import { normalizeCrate } from '../report'
import { shortName, type Model, type Selection } from '../model'

export interface TreeRow {
  id: string
  depth: number
  icon: ReactNode
  label: ReactNode
  hint?: ReactNode
  /** undefined: leaf */
  open?: boolean
  muted?: boolean
  selected?: boolean
  onSelect: () => void
  onActivate?: () => void
}

function VTree({ rows, onToggle, label }: { rows: TreeRow[]; onToggle: (id: string) => void; label: string }) {
  const el = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => el.current, estimateSize: () => 20, overscan: 20 })
  return (
    <div className="tree" ref={el} role="tree" aria-label={label}>
      <div style={{ height: v.getTotalSize(), position: 'relative' }}>
        {v.getVirtualItems().map((it) => {
          const r = rows[it.index]
          return (
            <div
              key={r.id}
              role="treeitem"
              aria-expanded={r.open}
              aria-selected={r.selected}
              className={`trow ${r.selected ? 'sel' : ''} ${r.muted ? 'muted' : ''}`}
              style={{ transform: `translateY(${it.start}px)`, paddingLeft: 4 + r.depth * 14 }}
              onClick={() => {
                if (r.open !== undefined) onToggle(r.id)
                r.onSelect()
              }}
              onDoubleClick={r.onActivate}
            >
              <span className="twisty">{r.open === undefined ? null : r.open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
              <span className="ticon">{r.icon}</span>
              <span className="tlabel">{r.label}</span>
              {r.hint !== undefined && <span className="thint">{r.hint}</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function useOpenSet(initial: string[]) {
  const [open, setOpen] = useState(() => new Set(initial))
  const toggle = (id: string) =>
    setOpen((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  return [open, toggle] as const
}

export function ProgramTree({ model, name, sel, onSelect, onGo }: { model: Model; name: string; sel: Selection | null; onSelect: (s: Selection) => void; onGo: (addr: number) => void }) {
  const [open, toggle] = useOpenSet(['root', 'sections'])
  const r = model.report
  const rows: TreeRow[] = []
  rows.push({ id: 'root', depth: 0, icon: <File size={14} />, label: name, open: open.has('root'), onSelect: () => {} })
  if (open.has('root')) {
    rows.push({ id: 'segments', depth: 1, icon: <Layers size={14} />, label: 'Segments', hint: r.segments.length, open: open.has('segments'), onSelect: () => {} })
    if (open.has('segments'))
      for (const s of r.segments)
        rows.push({
          id: `seg${s.index}`,
          depth: 2,
          icon: <Cpu size={13} />,
          label: `${s.kind} ${s.flags}`,
          hint: s.kind === 'LOAD' ? fmtAddr(s.vaddr) : undefined,
          muted: s.kind !== 'LOAD',
          selected: sel?.kind === 'segment' && sel.index === s.index,
          onSelect: () => onSelect({ kind: 'segment', index: s.index }),
          onActivate: s.kind === 'LOAD' ? () => (onGo(s.vaddr), onSelect({ kind: 'segment', index: s.index })) : undefined,
        })
    rows.push({ id: 'sections', depth: 1, icon: <Folder size={14} />, label: 'Sections', hint: r.sections.length, open: open.has('sections'), onSelect: () => {} })
    if (open.has('sections'))
      for (const s of r.sections) {
        if (s.index === 0 && s.kind === 'NULL') continue
        const loaded = s.flags.includes('A') && s.addr > 0
        rows.push({
          id: `sec${s.index}`,
          depth: 2,
          icon: <Folder size={13} />,
          label: s.name || `[${s.index}]`,
          hint: formatBytes(s.size),
          muted: !loaded,
          selected: sel?.kind === 'section' && sel.index === s.index,
          onSelect: () => {
            if (loaded) onGo(s.addr)
            onSelect({ kind: 'section', index: s.index })
          },
        })
      }
  }
  return <VTree rows={rows} onToggle={toggle} label="Program tree" />
}

export function SymbolTree({ model, sel, onSelect, onGo }: { model: Model; sel: Selection | null; onSelect: (s: Selection) => void; onGo: (addr: number) => void }) {
  const [open, toggle] = useOpenSet(['functions', 'crates'])
  const [filter, setFilter] = useState('')
  const r = model.report
  const fns = r.function_rows

  const fnRow = (fi: number, depth: number, idPrefix: string): TreeRow => {
    const f = fns[fi]
    return {
      id: `${idPrefix}f${fi}`,
      depth,
      icon: <FunctionSquare size={13} className="ic-fn" />,
      label: f.named_by === 'signature' ? <span className="sig-name" title="Named by a fingerprint match">≈ {shortName(f.name, f.start)}</span> : shortName(f.name, f.start),
      selected: sel?.kind === 'function' && sel.index === fi,
      onSelect: () => {
        onSelect({ kind: 'function', index: fi })
        onGo(f.start)
      },
    }
  }

  const matches = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return null
    const out: number[] = []
    let total = 0
    for (let i = 0; i < model.lowerNames.length; i++) {
      if (model.lowerNames[i].includes(q)) {
        total++
        if (out.length < 5000) out.push(i)
      }
    }
    return { out, total }
  }, [filter, model])

  const rows: TreeRow[] = []
  if (matches) {
    for (const fi of matches.out) rows.push(fnRow(fi, 0, 'm'))
  } else {
    const group = (id: string, label: string, list: number[], depth = 1) => {
      rows.push({ id, depth, icon: <Folder size={14} />, label, hint: formatCount(list.length), open: open.has(id), onSelect: () => {} })
      if (open.has(id)) for (const fi of list) rows.push(fnRow(fi, depth + 1, id))
    }
    rows.push({ id: 'functions', depth: 0, icon: <Folder size={14} />, label: 'Functions', hint: formatCount(r.functions.total), open: open.has('functions'), onSelect: () => {} })
    if (open.has('functions')) {
      group('user', 'Program', model.groups.user)
      rows.push({ id: 'crates', depth: 1, icon: <Folder size={14} />, label: 'Crates', hint: r.crates.length, open: open.has('crates'), onSelect: () => {} })
      if (open.has('crates'))
        r.crates.forEach((c, ci) => {
          const list = model.groups.byCrate.get(normalizeCrate(c.name)) ?? []
          // several versions of one crate share the symbol list: show it under the first
          const first = model.crateByName.get(normalizeCrate(c.name)) === ci
          const id = `crate${ci}`
          rows.push({
            id,
            depth: 2,
            icon: <Package size={14} className="ic-crate" />,
            label: (
              <>
                {c.name} <span className="tver">{c.version ?? ''}</span>
              </>
            ),
            hint: first && list.length ? formatCount(list.length) : undefined,
            open: first && list.length ? open.has(id) : undefined,
            selected: sel?.kind === 'crate' && sel.index === ci,
            onSelect: () => onSelect({ kind: 'crate', index: ci }),
          })
          if (first && open.has(id)) for (const fi of list) rows.push(fnRow(fi, 3, id))
        })
      group('std', 'Standard library', model.groups.std)
      group('unknown', 'Unknown owner', model.groups.unknown)
    }
  }
  return (
    <div className="tree-wrap">
      <VTree rows={rows} onToggle={toggle} label="Symbol tree" />
      <label className="tree-filter">
        <Search size={12} />
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter functions" aria-label="Filter functions" />
        {matches && <span className="thint">{formatCount(matches.total)}</span>}
      </label>
    </div>
  )
}
