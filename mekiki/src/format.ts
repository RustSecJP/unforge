export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export const formatCount = (n: number) => n.toLocaleString('en-US')

/** `0x1a2b` */
export const hex = (n: number) => `0x${n.toString(16)}`

/** Zero-padded address without 0x, Ghidra style: `00401a2b` */
export const addr = (n: number, width = 8) => n.toString(16).padStart(width, '0')

export const byteHex = (b: number) => b.toString(16).padStart(2, '0')

export const asciiOf = (b: number) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')

/** Parses `0x401000`, `401000h`, `401000` (hex) or returns null. */
export function parseAddress(s: string): number | null {
  const t = s.trim().toLowerCase().replace(/^0x/, '').replace(/h$/, '')
  if (!/^[0-9a-f]{1,16}$/.test(t)) return null
  const v = Number.parseInt(t, 16)
  return Number.isSafeInteger(v) ? v : null
}

export const cratesIoUrl = (name: string, version: string | null) =>
  `https://crates.io/crates/${encodeURIComponent(name)}${version ? `/${encodeURIComponent(version)}` : ''}`

export const docsRsUrl = (name: string, version: string | null) =>
  `https://docs.rs/${encodeURIComponent(name)}/${version ? encodeURIComponent(version) : 'latest'}`

export const rustcCommitUrl = (commit: string) => `https://github.com/rust-lang/rust/commit/${encodeURIComponent(commit)}`
