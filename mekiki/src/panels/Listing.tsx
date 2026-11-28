import { useVirtualizer } from '@tanstack/react-virtual'
import { useCallback, useEffect, useImperativeHandle, useRef, useState, type Ref } from 'react'
import { addr as fmtAddr, asciiOf, byteHex, formatBytes } from '../format'
import { fileOffset, RowKind } from '../listing'
import { crateOfFunction, ownerLabel, shortName, type Model } from '../model'

export const ROW_HEIGHT = 18
const CHUNK = 1 << 16

export interface ListingHandle {
  scrollToRow: (row: number) => void
  focus: () => void
}

/** Reads the file in 64 KB chunks as rows come into view. */
function useChunks(readRange: (offset: number, len: number) => Promise<Uint8Array>) {
  const cache = useRef(new Map<number, Uint8Array>())
  const pending = useRef(new Set<number>())
  const [, bump] = useState(0)
  useEffect(() => {
    cache.current = new Map()
    pending.current = new Set()
    bump((n) => n + 1)
  }, [readRange])
  const byte = useCallback(
    (offset: number): number | undefined => {
      const ci = Math.floor(offset / CHUNK)
      const chunk = cache.current.get(ci)
      if (chunk) {
        const b = chunk[offset - ci * CHUNK]
        return b
      }
      if (!pending.current.has(ci)) {
        pending.current.add(ci)
        void readRange(ci * CHUNK, CHUNK).then((bytes) => {
          cache.current.set(ci, bytes)
          pending.current.delete(ci)
          bump((n) => n + 1)
        })
      }
      return undefined
    },
    [readRange],
  )
  return byte
}

export function Listing({
  model,
  readRange,
  cursorRow,
  onCursor,
  onOpenFunction,
  ref,
}: {
  model: Model
  readRange: (offset: number, len: number) => Promise<Uint8Array>
  cursorRow: number | null
  onCursor: (row: number) => void
  onOpenFunction: (fi: number) => void
  ref: Ref<ListingHandle>
}) {
  const m = model.listing
  const fns = model.report.function_rows
  const width = Math.max(8, (m.count ? m.addr[m.count - 1] : 0).toString(16).length)
  const scroller = useRef<HTMLDivElement>(null)
  const byte = useChunks(readRange)
  const v = useVirtualizer({ count: m.count, getScrollElement: () => scroller.current, estimateSize: () => ROW_HEIGHT, overscan: 30 })

  useImperativeHandle(ref, () => ({
    scrollToRow: (row) => v.scrollToIndex(row, { align: 'center' }),
    focus: () => scroller.current?.focus(),
  }))

  const move = (delta: number) => {
    const next = Math.max(0, Math.min(m.count - 1, (cursorRow ?? 0) + delta))
    onCursor(next)
    v.scrollToIndex(next, { align: 'auto' })
  }

  const onKey = (e: React.KeyboardEvent) => {
    const page = Math.max(1, Math.floor((scroller.current?.clientHeight ?? 400) / ROW_HEIGHT) - 2)
    const keys: Record<string, () => void> = {
      ArrowDown: () => move(1),
      ArrowUp: () => move(-1),
      PageDown: () => move(page),
      PageUp: () => move(-page),
      Home: () => move(-(cursorRow ?? 0)),
      End: () => move(m.count),
    }
    const k = keys[e.key]
    if (k) {
      e.preventDefault()
      k()
    }
  }

  return (
    <div className="listing" ref={scroller} tabIndex={0} onKeyDown={onKey} role="grid" aria-label="Listing">
      <div style={{ height: v.getTotalSize(), position: 'relative' }}>
        {v.getVirtualItems().map((it) => {
          const r = it.index
          const kind = m.kind[r]
          const a = m.addr[r]
          const b = m.blocks[m.block[r]]
          const style = { transform: `translateY(${it.start}px)`, height: ROW_HEIGHT }
          const cls = `lrow ${cursorRow === r ? 'cur' : ''}`
          if (kind === RowKind.Block) {
            return (
              <div key={r} className={`${cls} lblock`} style={style} onMouseDown={() => onCursor(r)}>
                <span className="l-comment">
                  // {b.name || '(unnamed)'} &nbsp;ram:{fmtAddr(b.addr, width)}-{fmtAddr(b.addr + b.size - 1, width)} &nbsp;{b.kind} {b.flags} &nbsp;
                  {formatBytes(b.size)}
                </span>
              </div>
            )
          }
          if (kind === RowKind.NoBits) {
            return (
              <div key={r} className={cls} style={style} onMouseDown={() => onCursor(r)}>
                <span className="l-addr">{fmtAddr(a, width)}</span>
                <span className="l-comment">?? × {b.size.toLocaleString('en-US')} bytes, zero-filled at load time (not in the file)</span>
              </div>
            )
          }
          if (kind === RowKind.Function) {
            const fi = m.func[r]
            const f = fns[fi]
            const crate = crateOfFunction(model, fi)
            return (
              <div key={r} className={`${cls} lfunc`} style={style} onMouseDown={() => onCursor(r)} onDoubleClick={() => onOpenFunction(fi)}>
                <span className="l-addr">{fmtAddr(a, width)}</span>
                <span className="l-fn">{shortName(f.name, f.start)}</span>
                <span className="l-owner" data-owner={f.owner ?? 'unknown'}>
                  {crate ? `${crate.name}${crate.version ? ` ${crate.version}` : ''}` : ownerLabel(f.owner)}
                </span>
                {f.size > 0 && <span className="l-comment"> {f.size.toLocaleString('en-US')} bytes</span>}
              </div>
            )
          }
          // Bytes
          const n = m.len[r]
          const off = fileOffset(b, a)
          const hexes: string[] = []
          let ascii = ''
          for (let i = 0; i < n; i++) {
            const x = byte(off + i)
            hexes.push(x === undefined ? '··' : byteHex(x))
            ascii += x === undefined ? ' ' : asciiOf(x)
          }
          return (
            <div key={r} className={cls} style={style} onMouseDown={() => onCursor(r)}>
              <span className="l-addr">{fmtAddr(a, width)}</span>
              <span className="l-bytes">{hexes.join(' ')}</span>
              <span className="l-ascii">{ascii}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
