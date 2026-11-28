import type { ReactNode } from 'react'

/** A Ghidra-style docked window: a title bar and a body. */
export function Pane({ title, tools, children, className }: { title: ReactNode; tools?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`pane ${className ?? ''}`} tabIndex={-1}>
      <header className="pane-title">
        <span className="pane-name">{title}</span>
        {tools && <span className="pane-tools">{tools}</span>}
      </header>
      <div className="pane-body">{children}</div>
    </section>
  )
}
