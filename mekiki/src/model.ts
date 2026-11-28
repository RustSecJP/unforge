// Indexes derived once from a report, shared by all panes.
import { buildListing, type CodeMap, type ListingModel } from './listing'
import { normalizeCrate, ownerCrate, type CrateRow, type Report } from './report'

export type Selection =
  | { kind: 'address'; addr: number }
  | { kind: 'function'; index: number }
  | { kind: 'section'; index: number }
  | { kind: 'segment'; index: number }
  | { kind: 'crate'; index: number }
  | { kind: 'warning'; index: number }

export interface Model {
  report: Report
  listing: ListingModel
  /** normalized crate name -> index into report.crates (first version) */
  crateByName: Map<string, number>
  /** function indices per owner group */
  groups: { user: number[]; std: number[]; unknown: number[]; byCrate: Map<string, number[]> }
  /** lowercased function names, '' when unnamed */
  lowerNames: string[]
  /** function start -> index into report.function_rows */
  fnByStart: Map<number, number>
  /** exact function name -> index (first) */
  fnByName: Map<string, number>
  /** PE: IAT slot address -> `dll!function` */
  importBySlot: Map<number, string>
  /** functions that have instructions */
  codeFunctions: number
}

export function buildModel(report: Report, code: CodeMap = new Map()): Model {
  const crateByName = new Map<string, number>()
  report.crates.forEach((c, i) => {
    const k = normalizeCrate(c.name)
    if (!crateByName.has(k)) crateByName.set(k, i)
  })
  const groups = { user: [] as number[], std: [] as number[], unknown: [] as number[], byCrate: new Map<string, number[]>() }
  const lowerNames: string[] = new Array(report.function_rows.length)
  report.function_rows.forEach((f, i) => {
    lowerNames[i] = f.name?.toLowerCase() ?? ''
    const c = ownerCrate(f.owner)
    if (c) {
      const k = normalizeCrate(c)
      let list = groups.byCrate.get(k)
      if (!list) groups.byCrate.set(k, (list = []))
      list.push(i)
    } else if (f.owner === 'user') groups.user.push(i)
    else if (f.owner === 'std') groups.std.push(i)
    else groups.unknown.push(i)
  })
  const fnByStart = new Map<number, number>()
  report.function_rows.forEach((f, i) => fnByStart.set(f.start, i))
  const fnByName = new Map<string, number>()
  report.function_rows.forEach((f, i) => {
    if (f.name && !fnByName.has(f.name)) fnByName.set(f.name, i)
  })
  const importBySlot = new Map<number, string>()
  for (const i of report.imports ?? []) importBySlot.set(i.slot, `${i.dll}!${i.name}`)
  return { report, listing: buildListing(report, code), crateByName, groups, lowerNames, fnByStart, fnByName, importBySlot, codeFunctions: code.size }
}

export function crateOfFunction(m: Model, fi: number): CrateRow | null {
  const c = ownerCrate(m.report.function_rows[fi]?.owner ?? null)
  if (!c) return null
  const i = m.crateByName.get(normalizeCrate(c))
  return i === undefined ? null : m.report.crates[i]
}

export function ownerLabel(owner: string | null): string {
  if (owner === 'user') return 'program'
  if (owner === 'std') return 'std'
  return ownerCrate(owner) ?? 'unknown'
}

/** Shortest readable name: drop the leading crate path when long. */
export function shortName(name: string | null, start: number): string {
  if (!name) return `FUN_${start.toString(16).padStart(8, '0')}`
  return name
}
