// The JSON of `unforge_report::Report` (crates/unforge-report/src/lib.rs).
// Keep in step with `REPORT_VERSION` there.

export const REPORT_VERSION = 2

export interface FileSummary {
  size: number
  class: string
  endian: string
  machine: string
  kind: string
  entry: number
  stripped: boolean
  sections: number
  segments: number
}

export interface FunctionCounts {
  total: number
  user: number
  dependency: number
  std: number
  unknown: number
}

export interface FunctionRow {
  start: number
  size: number
  name: string | null
  /** `user`, `std`, `dep:<crate>` or null */
  owner: string | null
}

export interface SectionRow {
  index: number
  name: string
  kind: string
  flags: string
  addr: number
  offset: number
  size: number
  nobits: boolean
}

export interface SegmentRow {
  index: number
  kind: string
  flags: string
  offset: number
  vaddr: number
  filesz: number
  memsz: number
}

export type FoundIn = 'path' | 'symbols' | 'both'

export interface CrateRow {
  name: string
  version: string | null
  functions: number
  bytes: number
  found_in: FoundIn
}

export interface Warning {
  severity: string
  category: string
  kind: string
  message: string
  offset: number | null
}

export interface Report {
  version: number
  file: FileSummary
  rustc_commit: string | null
  functions: FunctionCounts
  function_rows: FunctionRow[]
  functions_omitted: number
  sections: SectionRow[]
  segments: SegmentRow[]
  crates: CrateRow[]
  warnings: Warning[]
  warnings_omitted: number
}

export type Outcome = { ok: true; report: Report } | { ok: false; error: string }

export function toOutcome(v: unknown): Outcome {
  const o = v as Partial<Report> & { error?: string }
  if (!o || typeof o !== 'object') return { ok: false, error: 'The analyzer returned nothing.' }
  if (typeof o.error === 'string') return { ok: false, error: o.error }
  if (o.version !== REPORT_VERSION) return { ok: false, error: `Unexpected report version ${String(o.version)}.` }
  return { ok: true, report: o as Report }
}

/** The crate name of an owner label, `dep:serde_json` -> `serde_json`. */
export const ownerCrate = (owner: string | null) => (owner?.startsWith('dep:') ? owner.slice(4) : null)

export const normalizeCrate = (name: string) => name.replace(/-/g, '_')
