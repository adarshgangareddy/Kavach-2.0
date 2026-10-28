import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'

/**
 * Calls onSlow once if the frame rate stays under `min` fps for `seconds` in a row.
 * The first second is ignored (shaders compiling), and so are long pauses such as a
 * hidden tab, which would otherwise look like one very slow frame.
 */
export function useFpsGuard(onSlow, { min = 40, seconds = 2, warmup = 1 } = {}) {
  const state = useRef({ elapsed: 0, frames: 0, window: 0, slowFor: 0, done: false })
  useFrame((_, delta) => {
    const s = state.current
    if (s.done || delta > 0.25) return
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
