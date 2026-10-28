import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'

/**
 * Calls onSlow once if the frame rate stays under `min` fps for `seconds` in a row.
 *
 * It only measures while the view animates continuously (`enabled`). A canvas that renders on
 * demand draws single frames seconds apart, on hover or click; counting those would look like
 * a very low frame rate. Warm-up time (shaders compiling, the page loading), a hidden tab and
 * long pauses are not counted either.
 */
export function useFpsGuard(onSlow, { min = 40, seconds = 2, warmup = 1.5, enabled = true } = {}) {
  const state = useRef({ elapsed: 0, frames: 0, window: 0, slowFor: 0, done: false })
  const on = useRef(enabled)
  on.current = enabled
  useFrame((_, delta) => {
    const s = state.current
    if (s.done) return
    if (!on.current || delta > 0.25 || (typeof document !== 'undefined' && document.hidden)) {
      s.elapsed = 0  // start over: the next stretch of animation gets its own warm-up
      s.frames = 0
      s.window = 0
      s.slowFor = 0
      return
    }
    s.elapsed += delta
    if (s.elapsed < warmup) return
    s.frames += 1
    s.window += delta
    if (s.window < 0.5) return
    const fps = s.frames / s.window
    s.slowFor = fps < min ? s.slowFor + s.window : 0
    s.frames = 0
    s.window = 0
    if (s.slowFor >= seconds) {
      s.done = true
      onSlow()
    }
  })
}
