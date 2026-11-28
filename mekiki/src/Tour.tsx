import { X } from 'lucide-react'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'

export interface TourStep {
  /** CSS selector of the thing to point at; none = centered card */
  target?: string
  title: string
  body: string
  /** Does the step for the user ("Show me") */
  action?: { label: string; run: () => void | Promise<void>; advance?: boolean }
  /** Next stays disabled until this is true */
  ready?: () => boolean
}

const PAD = 6
const CARD_W = 340

type Rect = { top: number; left: number; width: number; height: number }

function rectOf(selector: string | undefined): Rect | null {
  if (!selector) return null
  const el = document.querySelector(selector)
  if (!el) return null
  const r = el.getBoundingClientRect()
  if (r.width === 0 && r.height === 0) return null
  return { top: r.top - PAD, left: r.left - PAD, width: r.width + PAD * 2, height: r.height + PAD * 2 }
}

/** Where the card goes: beside the spot if there is room, else below/above. */
function place(r: Rect | null, cardH: number): { top: number; left: number } {
  const vw = window.innerWidth
  const vh = window.innerHeight
  if (!r) return { top: Math.max(20, vh / 2 - cardH / 2), left: vw / 2 - CARD_W / 2 }
  const clampTop = (t: number) => Math.min(Math.max(10, t), vh - cardH - 10)
  const clampLeft = (l: number) => Math.min(Math.max(10, l), vw - CARD_W - 10)
  if (r.left + r.width + 14 + CARD_W < vw) return { top: clampTop(r.top), left: r.left + r.width + 14 }
  if (r.left - 14 - CARD_W > 0) return { top: clampTop(r.top), left: r.left - 14 - CARD_W }
  if (r.top + r.height + 14 + cardH < vh) return { top: r.top + r.height + 14, left: clampLeft(r.left) }
  return { top: clampTop(r.top - 14 - cardH), left: clampLeft(r.left) }
}

export function Tour({ steps, onClose, labels }: { steps: TourStep[]; onClose: () => void; labels: { next: string; back: string; done: string; skip: string; of: string } }) {
  const [i, setI] = useState(0)
  const [rect, setRect] = useState<Rect | null>(null)
  const [busy, setBusy] = useState(false)
  const [, tick] = useState(0)
  const card = useRef<HTMLDivElement>(null)
  const step = steps[i]

  // Follow the target while it moves (layout changes, scrolling, resizing).
  useLayoutEffect(() => {
    const update = () => setRect(rectOf(step.target))
    update()
    const t = window.setInterval(() => {
      update()
      tick((n) => n + 1)
    }, 250)
    window.addEventListener('resize', update)
    return () => {
      window.clearInterval(t)
      window.removeEventListener('resize', update)
    }
  }, [step])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const last = i === steps.length - 1
  const canNext = !step.ready || step.ready()
  const pos = place(rect, card.current?.offsetHeight ?? 200)
  const run = async () => {
    if (!step.action) return
    setBusy(true)
    try {
      await step.action.run()
    } finally {
      setBusy(false)
    }
    if (step.action.advance && !last) setI(i + 1)
  }

  return (
    <div className="tour" role="dialog" aria-label={step.title}>
      {rect ? <div className="tour-spot" style={rect} /> : <div className="tour-dim" />}
      <div className="tour-card" ref={card} style={{ top: pos.top, left: pos.left, width: CARD_W }}>
        <button type="button" className="tour-x" onClick={onClose} aria-label={labels.skip}>
          <X size={14} />
        </button>
        <p className="tour-count">
          {i + 1} {labels.of} {steps.length}
        </p>
        <h2>{step.title}</h2>
        <p className="tour-body">{step.body}</p>
        <div className="tour-buttons">
          {step.action && (
            <button type="button" className="tour-action" onClick={() => void run()} disabled={busy}>
              {busy ? '…' : step.action.label}
            </button>
          )}
          <span className="grow" />
          {i > 0 && (
            <button type="button" onClick={() => setI(i - 1)}>
              {labels.back}
            </button>
          )}
          <button type="button" className="tour-next" onClick={() => (last ? onClose() : setI(i + 1))} disabled={!canNext}>
            {last ? labels.done : labels.next}
          </button>
        </div>
      </div>
    </div>
  )
}
