import { useEffect, useRef, useState } from 'react'
import { useEffects } from './effects.jsx'

const ease = (t) => 1 - (1 - t) ** 3  // ease-out cubic: fast start, calm finish

/**
 * A number that counts up from zero when it first appears, then follows changes.
 * Screen readers get the final value at once; the counting digits are hidden from them.
 */
export default function CountUp({ value, duration = 700 }) {
  const { motion } = useEffects()
  const [shown, setShown] = useState(motion ? 0 : value)
  const from = useRef(motion ? 0 : value)

  useEffect(() => {
    if (!motion) {
      setShown(value)
      from.current = value
      return undefined
    }
    const start = performance.now()
    const begin = from.current
    let frame
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration)
      setShown(Math.round(begin + (value - begin) * ease(t)))
      if (t < 1) frame = requestAnimationFrame(step)
      else from.current = value
    }
    frame = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frame)
  }, [value, motion, duration])

  return (
    <>
      <span aria-hidden="true">{shown}</span>
      <span className="sr-only">{value}</span>
    </>
  )
}
