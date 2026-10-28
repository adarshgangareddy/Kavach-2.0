import { useRef } from 'react'
import { useEffects } from './effects.jsx'

export const MAX_TILT = 6  // degrees: a hint of depth, not a wobble

const canHover = () => typeof window !== 'undefined' && window.matchMedia?.('(hover: hover)').matches

/**
 * Renders `as` (default div) and tilts it gently toward the mouse. Off for touch, keyboard-only use,
 * Reduce effects and reduced motion. Other props pass straight through.
 */
export default function Tilt({ as: Tag = 'div', className = '', children, ...rest }) {
  const { motion } = useEffects()
  const ref = useRef(null)
  const active = motion && canHover()

  function move(e) {
    if (!active || e.pointerType === 'touch' || e.pointerType === 'pen' || !ref.current) return
    const r = ref.current.getBoundingClientRect()
    const x = (e.clientX - r.left) / r.width - 0.5
    const y = (e.clientY - r.top) / r.height - 0.5
    ref.current.style.transform = `perspective(800px) rotateX(${(-y * 2 * MAX_TILT).toFixed(2)}deg) rotateY(${(x * 2 * MAX_TILT).toFixed(2)}deg)`
  }

  function leave() {
    if (ref.current) ref.current.style.transform = ''
  }

  return (
    <Tag ref={ref} className={`${className} ${active ? 'tilt' : ''}`.trim()} {...rest}
         onPointerMove={(e) => { move(e); rest.onPointerMove?.(e) }}
         onPointerLeave={(e) => { leave(); rest.onPointerLeave?.(e) }}>
      {children}
    </Tag>
  )
}
