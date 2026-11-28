import { describe, expect, it } from 'vitest'
import { parseAddress } from './format'
import { buildListing, functionAt, rowOfAddress, RowKind } from './listing'
import type { FunctionRow, Report, SectionRow } from './report'

const sec = (index: number, name: string, addr: number, size: number, extra: Partial<SectionRow> = {}): SectionRow => ({
  index,
  name,
  kind: 'PROGBITS',
  flags: 'AX',
  addr,
  offset: addr - 0x1000,
  size,
  nobits: false,
  ...extra,
})
const fn = (start: number, size: number, name: string | null = null): FunctionRow => ({ start, size, name, owner: null })

function report(sections: SectionRow[], fns: FunctionRow[]): Report {
  return {
    version: 2,
    file: { size: 0, class: 'ELF64', endian: 'little', machine: 'x86-64', kind: 'executable', entry: 0, stripped: false, sections: sections.length, segments: 0 },
    rustc_commit: null,
    functions: { total: fns.length, user: 0, dependency: 0, std: 0, unknown: fns.length },
    function_rows: fns,
    functions_omitted: 0,
    sections,
    segments: [],
    crates: [],
    warnings: [],
    warnings_omitted: 0,
  }
}

const rows = (m: ReturnType<typeof buildListing>) => Array.from({ length: m.count }, (_, i) => [m.kind[i], m.addr[i], m.len[i]])

describe('Listing rows', () => {
  it('splits bytes at function starts and section ends', () => {
    const m = buildListing(report([sec(1, '.text', 0x2000, 40)], [fn(0x2000, 10, 'a'), fn(0x2014, 20, 'b')]))
    expect(rows(m)).toEqual([
      [RowKind.Block, 0x2000, 0],
      [RowKind.Function, 0x2000, 0],
      [RowKind.Bytes, 0x2000, 16],
      [RowKind.Bytes, 0x2010, 4],
      [RowKind.Function, 0x2014, 0],
      [RowKind.Bytes, 0x2014, 16],
      [RowKind.Bytes, 0x2024, 4],
    ])
  })

  it('skips unloaded sections, orders by address and shows NOBITS as one row', () => {
    const m = buildListing(
      report(
        [sec(1, '.data', 0x5000, 8, { flags: 'WA' }), sec(2, '.comment', 0, 30, { flags: 'MS' }), sec(3, '.bss', 0x6000, 4096, { flags: 'WA', kind: 'NOBITS', nobits: true }), sec(4, '.text', 0x2000, 4)],
        [],
      ),
    )
    expect(m.blocks.map((b) => b.name)).toEqual(['.text', '.data', '.bss'])
    expect(rows(m).filter((r) => r[0] === RowKind.NoBits)).toEqual([[RowKind.NoBits, 0x6000, 0]])
  })

  it('finds the row of an address, preferring a function header at its start', () => {
    const m = buildListing(report([sec(1, '.text', 0x2000, 64)], [fn(0x2020, 8, 'f')]))
    expect(m.kind[rowOfAddress(m, 0x2020)]).toBe(RowKind.Function)
    const r = rowOfAddress(m, 0x2005)
    expect([m.kind[r], m.addr[r]]).toEqual([RowKind.Bytes, 0x2000])
    expect(rowOfAddress(m, 0x1000)).toBe(-1)
    expect(rowOfAddress(m, 0x9000)).toBe(-1)
  })

  it('finds the function containing an address', () => {
    const fns = [fn(0x10, 0x10), fn(0x30, 0), fn(0x40, 0x8)]
    expect(functionAt(fns, 0x15)).toBe(0)
    expect(functionAt(fns, 0x25)).toBe(-1)
    expect(functionAt(fns, 0x30)).toBe(1)
    expect(functionAt(fns, 0x47)).toBe(2)
    expect(functionAt(fns, 0x48)).toBe(-1)
  })
})

describe('parseAddress', () => {
  it('reads hex in the usual spellings', () => {
    expect(parseAddress('0x401000')).toBe(0x401000)
    expect(parseAddress('401000h')).toBe(0x401000)
    expect(parseAddress(' 1A2b ')).toBe(0x1a2b)
    expect(parseAddress('main')).toBeNull()
    expect(parseAddress('')).toBeNull()
  })
})
