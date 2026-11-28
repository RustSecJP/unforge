import { useVirtualizer } from '@tanstack/react-virtual'
import { useCallback, useEffect, useImperativeHandle, useLayoutEffect, useRef, useState, type Ref } from 'react'
import type { InsnText } from '../backend'
import { addr as fmtAddr, asciiOf, byteHex, formatBytes } from '../format'
import { absoluteOperand, fileOffset, RowKind } from '../listing'
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

/** Instruction text for the rows on screen, fetched in one batch per render. */
function useInsnText(disasmAt: (addrs: number[]) => Promise<(InsnText | null)[]>) {
  const cache = useRef(new Map<number, InsnText | null>())
  const want = useRef(new Set<number>())
  const inFlight = useRef(new Set<number>())
  const [, bump] = useState(0)
  useEffect(() => {
    cache.current = new Map()
    inFlight.current = new Set()
    bump((n) => n + 1)
  }, [disasmAt])
  const get = (a: number) => {
    if (cache.current.has(a)) return cache.current.get(a)
    if (!inFlight.current.has(a)) want.current.add(a)
    return undefined
  }
  useEffect(() => {
    if (want.current.size === 0) return
    const addrs = [...want.current].slice(0, 2048)
    want.current = new Set()
    for (const a of addrs) inFlight.current.add(a)
    void disasmAt(addrs).then((out) => {
      addrs.forEach((a, i) => {
        cache.current.set(a, out[i] ?? null)
        inFlight.current.delete(a)
      })
      bump((n) => n + 1)
    })
  })
  return get
}

export function Listing({
  model,
  readRange,
  disasmAt,
  onGo,
  initialRow,
  cursorRow,
  onCursor,
  onOpenFunction,
  ref,
}: {
  model: Model
  readRange: (offset: number, len: number) => Promise<Uint8Array>
  disasmAt: (addrs: number[]) => Promise<(InsnText | null)[]>
  onGo: (addr: number) => void
  /** Row to show centered when a file is opened */
  initialRow: number
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
  const insnText = useInsnText(disasmAt)
  const v = useVirtualizer({ count: m.count, getScrollElement: () => scroller.current, estimateSize: () => ROW_HEIGHT, overscan: 30 })

  // Every row has the same height, so scrolling is plain arithmetic. This also
  // works right after mounting, before the virtualizer has measured anything.
  const scrollTo = (row: number, align: 'center' | 'auto') => {
    const el = scroller.current
    if (!el) return
    const top = row * ROW_HEIGHT
    if (align === 'center') el.scrollTop = Math.max(0, top - el.clientHeight / 2 + ROW_HEIGHT / 2)
    else if (top < el.scrollTop) el.scrollTop = top
    else if (top + ROW_HEIGHT > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW_HEIGHT - el.clientHeight
  }

  useLayoutEffect(() => {
    scrollTo(initialRow, 'center')
    scroller.current?.focus({ preventScroll: true })
    // only when a new file (model) arrives
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model])

  useImperativeHandle(ref, () => ({
    scrollToRow: (row) => scrollTo(row, 'center'),
    focus: () => scroller.current?.focus({ preventScroll: true }),
  }))

  const move = (delta: number) => {
    const next = Math.max(0, Math.min(m.count - 1, (cursorRow ?? 0) + delta))
    onCursor(next)
    scrollTo(next, 'auto')
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
                <span className={`l-fn ${f.named_by === 'signature' ? 'sig' : ''}`} title={f.named_by === 'signature' ? 'Named by a fingerprint match' : undefined}>
                  {f.named_by === 'signature' ? '≈ ' : ''}
                  {shortName(f.name, f.start)}
                </span>
                <span className="l-owner" data-owner={f.owner ?? 'unknown'}>
                  {crate ? `${crate.name}${crate.version ? ` ${crate.version}` : ''}` : ownerLabel(f.owner)}
                </span>
                {f.size > 0 && <span className="l-comment"> {f.size.toLocaleString('en-US')} bytes</span>}
              </div>
            )
          }
          if (kind === RowKind.Insn) {
            const n = m.len[r]
            const off = fileOffset(b, a)
            const hexes: string[] = []
            for (let i = 0; i < Math.min(n, 8); i++) {
              const x = byte(off + i)
              hexes.push(x === undefined ? '··' : byteHex(x))
            }
            const t = insnText(a)
            const targetFn = t?.target != null ? model.fnByStart.get(t.target) : undefined
            // A call through an import slot: `call [rip+slot]` has the slot
            // as its target; 32-bit `call dword ptr [0x41f278]` only names it.
            const slot = t ? (t.target ?? absoluteOperand(t.operands)) : null
            const imported = targetFn === undefined && slot != null ? model.importBySlot.get(slot) : undefined
            const branch = t && (t.flow === 'call' || t.flow === 'jump' || t.flow === 'cond_jump')
            return (
              <div key={r} className={cls} style={style} onMouseDown={() => onCursor(r)}>
                <span className="l-addr">{fmtAddr(a, width)}</span>
                <span className="l-ibytes">
                  {hexes.join(' ')}
                  {n > 8 ? ' …' : ''}
                </span>
                {t ? (
                  <>
                    <span className={`l-mn flow-${t.flow}`}>{t.mnemonic}</span>
                    <span className="l-ops">
                      {branch && t.target != null ? (
                        <a className="l-target" onMouseDown={(e) => e.stopPropagation()} onClick={() => onGo(t.target!)} title="Go to target">
                          {t.operands}
                        </a>
                      ) : (
                        t.operands
                      )}
                    </span>
                    {targetFn !== undefined && (
                      <a className="l-xref" onMouseDown={(e) => e.stopPropagation()} onClick={() => onGo(t.target!)}>
                        ; → {shortName(fns[targetFn].name, fns[targetFn].start)}
                      </a>
                    )}
                    {imported !== undefined && <span className="l-xref">; → {imported}</span>}
                  </>
                ) : (
                  <span className="l-comment">{t === null ? '??' : ''}</span>
                )}
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
