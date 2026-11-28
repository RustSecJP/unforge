import { AlertTriangle, ExternalLink, FunctionSquare, Lightbulb, MapPin, Package } from 'lucide-react'
import type { ReactNode } from 'react'
import { cratesIoUrl, docsRsUrl, formatBytes, formatCount, hex } from '../format'
import { fileOffset, functionAt, loadedSections } from '../listing'
import { crateOfFunction, ownerLabel, shortName, type Model, type Selection } from '../model'
import type { CrateRow, FoundIn } from '../report'

function Props({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <table className="props">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th>{k}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const HOW_FOUND: Record<FoundIn, string> = {
  signatures: 'Only fingerprints point to it: functions in this file match known code of this crate. The version is unknown.',
  both: 'Found from a source path that carries the exact version, and from function names in the symbols.',
  path: 'Found from a source path like …/registry/src/…/name-1.2.3/… left in panic messages or debug info. No function name points to it — common in stripped binaries.',
  symbols: 'Only function names point to it. No source path with a version was found, so the version is unknown.',
}

function CrateLinks({ c }: { c: CrateRow }) {
  return (
    <p className="links">
      <a href={cratesIoUrl(c.name, c.version)} target="_blank" rel="noreferrer">
        crates.io <ExternalLink size={11} />
      </a>
      <a href={docsRsUrl(c.name, c.version)} target="_blank" rel="noreferrer">
        docs.rs <ExternalLink size={11} />
      </a>
    </p>
  )
}

const CATEGORY_HELP: Record<string, string> = {
  format: 'The bytes break the ELF format rules (header fields, table bounds or entry sizes). Other tools may read this file differently.',
  inference: 'unforge had to choose how to read part of the file. Other tools might choose differently.',
  consistency: 'Two views of the file disagree, for example sections and segments. Common in packed or tampered binaries.',
  loader: 'About what a Linux loader (the kernel or ld.so) would do with the file.',
  audit: 'About the check itself, for example findings that were cut off.',
}

function FunctionInfo({ model, fi }: { model: Model; fi: number }) {
  const f = model.report.function_rows[fi]
  const crate = crateOfFunction(model, fi)
  return (
    <>
      <h3>
        <FunctionSquare size={15} className="ic-fn" /> {shortName(f.name, f.start)}
      </h3>
      <Props
        rows={[
          ['Address', <code>{hex(f.start)}</code>],
          ['Size', f.size ? `${formatCount(f.size)} bytes` : 'unknown'],
          ['Owner', crate ? `${crate.name} ${crate.version ?? ''}` : ownerLabel(f.owner)],
          [
            'Named',
            f.named_by === 'symbols'
              ? 'from symbols'
              : f.named_by === 'signature'
                ? f.signature?.status === 'same_generic'
                  ? 'by fingerprint (same generic function, type unknown)'
                  : 'by fingerprint (one match)'
                : f.signature?.status === 'ambiguous'
                  ? 'no — fingerprints disagree'
                  : 'no — unnamed',
          ],
        ]}
      />
      {f.named_by === 'signature' && (
        <div className="tip">
          <Lightbulb size={14} />
          <p>This name is inferred: the function's code matches a function in a fingerprint database. Identical code under another name is possible.</p>
        </div>
      )}
      {f.signature && f.signature.candidates.length > 1 && (
        <div className="cands">
          <p className="muted">Fingerprint candidates{f.signature.more ? ` (and ${f.signature.more} more)` : ''}:</p>
          <ul>
            {f.signature.candidates.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
      {crate && <CrateLinks c={crate} />}
    </>
  )
}

export function Inspector({ model, sel }: { model: Model; sel: Selection | null }) {
  const r = model.report
  if (!sel) {
    return (
      <div className="inspector">
        <p className="muted">Select a function, crate, section or a line in the Listing to see its details here.</p>
      </div>
    )
  }
  let body: ReactNode = null
  switch (sel.kind) {
    case 'function':
      body = <FunctionInfo model={model} fi={sel.index} />
      break
    case 'address': {
      const fi = functionAt(r.function_rows, sel.addr)
      const sec = loadedSections(r).find((s) => sel.addr >= s.addr && sel.addr < s.addr + s.size)
      body = (
        <>
          <h3>
            <MapPin size={15} /> {hex(sel.addr)}
          </h3>
          <Props
            rows={[
              ['Section', sec ? sec.name : '—'],
              ['File offset', sec && !sec.nobits ? <code>{hex(fileOffset(sec, sel.addr))}</code> : 'not in the file'],
              ['Function', fi >= 0 ? shortName(r.function_rows[fi].name, r.function_rows[fi].start) : 'none known'],
            ]}
          />
          {fi >= 0 && <FunctionInfo model={model} fi={fi} />}
        </>
      )
      break
    }
    case 'crate': {
      const c = r.crates[sel.index]
      body = (
        <>
          <h3>
            <Package size={15} className="ic-crate" /> {c.name}
          </h3>
          <Props
            rows={[
              ['Version', c.version ?? 'unknown'],
              ['Functions', formatCount(c.functions)],
              ['Code size', c.bytes ? formatBytes(c.bytes) : '—'],
            ]}
          />
          <CrateLinks c={c} />
          <div className="tip">
            <Lightbulb size={14} />
            <p>{HOW_FOUND[c.found_in]}</p>
          </div>
        </>
      )
      break
    }
    case 'section': {
      const s = r.sections[sel.index]
      body = (
        <>
          <h3>{s.name || `section ${s.index}`}</h3>
          <Props
            rows={[
              ['Type', s.kind],
              ['Flags', s.flags || '—'],
              ['Address', <code>{hex(s.addr)}</code>],
              ['File offset', <code>{hex(s.offset)}</code>],
              ['Size', `${formatCount(s.size)} bytes`],
              ['Loaded', s.flags.includes('A') ? 'yes' : 'no'],
            ]}
          />
        </>
      )
      break
    }
    case 'segment': {
      const s = r.segments[sel.index]
      body = (
        <>
          <h3>
            {s.kind} {s.flags}
          </h3>
          <Props
            rows={[
              ['Virtual address', <code>{hex(s.vaddr)}</code>],
              ['File offset', <code>{hex(s.offset)}</code>],
              ['Size in file', `${formatCount(s.filesz)} bytes`],
              ['Size in memory', `${formatCount(s.memsz)} bytes`],
            ]}
          />
        </>
      )
      break
    }
    case 'warning': {
      const w = r.warnings[sel.index]
      body = (
        <>
          <h3 className={`sev-${w.severity.replace(/ /g, '-')}`}>
            <AlertTriangle size={15} /> {w.severity}
          </h3>
          <p>{w.message}</p>
          <Props
            rows={[
              ['Kind', <code>{w.kind}</code>],
              ['Category', w.category],
              ['File offset', w.offset === null ? '—' : <code>{hex(w.offset)}</code>],
            ]}
          />
          <div className="tip">
            <Lightbulb size={14} />
            <p>{CATEGORY_HELP[w.category] ?? 'A finding from the unforge audit.'}</p>
          </div>
        </>
      )
      break
    }
  }
  return <div className="inspector">{body}</div>
}
