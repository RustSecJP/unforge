// The rows of the Listing: every loaded section, in address order, as a
// header row, then function header rows and rows of up to 16 bytes that never
// cross the start of a function. Kept in flat typed arrays: a 20 MB binary has
// over a million rows.
import type { FunctionRow, Report, SectionRow } from './report'

export const RowKind = { Block: 0, Function: 1, Bytes: 2, NoBits: 3, Insn: 4 } as const
export type RowKind = (typeof RowKind)[keyof typeof RowKind]

export interface ListingModel {
  count: number
  kind: Uint8Array
  addr: Float64Array
  len: Uint8Array
  /** Index into `blocks` */
  block: Uint16Array
  /** Index into report.function_rows for Function rows, else -1 */
  func: Int32Array
  blocks: SectionRow[]
}

export const BYTES_PER_ROW = 16

/** function start -> instruction lengths (see unforge_report::code::code_map) */
export type CodeMap = Map<number, Uint8Array>

export function parseCodeMap(bytes: Uint8Array): CodeMap {
  const out: CodeMap = new Map()
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let p = 0
  while (p + 12 <= bytes.length) {
    const start = Number(view.getBigUint64(p, true))
    const count = view.getUint32(p + 8, true)
    if (p + 12 + count > bytes.length) break
    out.set(start, bytes.subarray(p + 12, p + 12 + count))
    p += 12 + count
  }
  return out
}

export function loadedSections(report: Report): SectionRow[] {
  return report.sections
    .filter((s) => s.flags.includes('A') && s.size > 0 && s.addr > 0)
    .sort((a, b) => a.addr - b.addr || a.index - b.index)
    .slice(0, 65535)
}

export function buildListing(report: Report, code: CodeMap = new Map(), maxRows = 12_000_000): ListingModel {
  const blocks = loadedSections(report)
  const fns = report.function_rows
  // Rough upper bound for the arrays; grown if needed.
  let cap = 1024
  for (const b of blocks) cap += b.nobits ? 2 : Math.ceil(b.size / BYTES_PER_ROW) + 1
  for (const lens of code.values()) cap += lens.length
  cap = Math.min(cap + fns.length * 2, maxRows)
  let kind = new Uint8Array(cap)
  let addr = new Float64Array(cap)
  let len = new Uint8Array(cap)
  let block = new Uint16Array(cap)
  let func = new Int32Array(cap)
  let n = 0
  const push = (k: RowKind, a: number, l: number, b: number, f: number) => {
    if (n >= cap) {
      if (cap >= maxRows) return false
      cap = Math.min(cap * 2, maxRows)
      const grow = <T extends Uint8Array | Float64Array | Uint16Array | Int32Array>(old: T, make: (c: number) => T) => {
        const x = make(cap)
        x.set(old)
        return x
      }
      kind = grow(kind, (c) => new Uint8Array(c))
      addr = grow(addr, (c) => new Float64Array(c))
      len = grow(len, (c) => new Uint8Array(c))
      block = grow(block, (c) => new Uint16Array(c))
      func = grow(func, (c) => new Int32Array(c))
    }
    kind[n] = k
    addr[n] = a
    len[n] = l
    block[n] = b
    func[n] = f
    n++
    return true
  }

  // function_rows are sorted by start
  let fi = 0
  outer: for (let bi = 0; bi < blocks.length; bi++) {
    const b = blocks[bi]
    const end = b.addr + b.size
    if (!push(RowKind.Block, b.addr, 0, bi, -1)) break
    while (fi < fns.length && fns[fi].start < b.addr) fi++
    if (b.nobits) {
      if (!push(RowKind.NoBits, b.addr, 0, bi, -1)) break
      continue
    }
    let pos = b.addr
    let next = fi
    while (pos < end) {
      while (next < fns.length && fns[next].start < pos) next++
      let lens: Uint8Array | undefined
      if (next < fns.length && fns[next].start === pos) {
        if (!push(RowKind.Function, pos, 0, bi, next)) break outer
        lens = code.get(pos)
        next++
        while (next < fns.length && fns[next].start === pos) next++
      }
      const boundary = next < fns.length && fns[next].start < end ? fns[next].start : end
      if (lens) {
        // Instructions, up to the next function or the end of the section.
        for (let k = 0; k < lens.length && pos + lens[k] <= boundary; k++) {
          if (!push(RowKind.Insn, pos, lens[k], bi, -1)) break outer
          pos += lens[k]
        }
        if (pos >= boundary) continue
      }
      const l = Math.min(BYTES_PER_ROW, boundary - pos)
      if (!push(RowKind.Bytes, pos, l, bi, -1)) break outer
      pos += l
    }
    fi = next
  }
  return { count: n, kind, addr, len, block, func, blocks }
}

/** The row showing `target` (its Function row when one starts there), or -1. */
export function rowOfAddress(m: ListingModel, target: number): number {
  let lo = 0
  let hi = m.count - 1
  let best = -1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (m.addr[mid] <= target) {
      best = mid
      lo = mid + 1
    } else hi = mid - 1
  }
  if (best < 0) return -1
  // Rows that share an address: Block, Function, then Bytes. Prefer the
  // Function header when `target` is its start, else the Bytes row.
  let r = best
  while (r > 0 && m.addr[r - 1] === m.addr[r]) r--
  for (let i = r; i < m.count && m.addr[i] === m.addr[best]; i++) {
    if (m.kind[i] === RowKind.Function && m.addr[i] === target) return i
  }
  // Inside an instruction, its row; else the row whose bytes hold `target`.
  const k = m.kind[best]
  const b = m.blocks[m.block[best]]
  if (target >= b.addr + b.size && k !== RowKind.Block) return -1
  return best
}

/** The function containing `addr` (by start and size), or -1. */
export function functionAt(fns: FunctionRow[], addr: number): number {
  let lo = 0
  let hi = fns.length - 1
  let best = -1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (fns[mid].start <= addr) {
      best = mid
      lo = mid + 1
    } else hi = mid - 1
  }
  if (best < 0) return -1
  const f = fns[best]
  return f.start === addr || addr < f.start + Math.max(f.size, 1) ? best : -1
}

/** File offset of `addr` inside block `b` (no bytes for NOBITS). */
export const fileOffset = (b: SectionRow, addr: number) => b.offset + (addr - b.addr)

/** The address of a bare absolute memory operand (`dword ptr [0x41f278]`),
 * as 32-bit code calls through an import slot; null when there is none. */
export function absoluteOperand(operands: string): number | null {
  const m = /\[0x([0-9a-f]+)\]/i.exec(operands)
  return m ? parseInt(m[1], 16) : null
}
