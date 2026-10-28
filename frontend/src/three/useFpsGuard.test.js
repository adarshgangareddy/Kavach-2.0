import { describe, expect, it, vi } from 'vitest'

// Drive the guard's frame callback by hand instead of running a real render loop.
let frame
vi.mock('@react-three/fiber', () => ({ useFrame: (fn) => { frame = fn } }))
vi.mock('react', async (load) => ({ ...(await load()), useRef: (v) => ({ current: v }) }))

const { useFpsGuard } = await import('./useFpsGuard.js')

function run(fps, seconds) {
  for (let i = 0; i < fps * seconds; i += 1) frame(null, 1 / fps)
}

describe('useFpsGuard', () => {
  it('gives up after 2 seconds under 40 fps', () => {
    const onSlow = vi.fn()
    useFpsGuard(onSlow)
    run(60, 1)    // warm-up
    run(30, 1.5)
    expect(onSlow).not.toHaveBeenCalled()
    run(30, 1)
    expect(onSlow).toHaveBeenCalledTimes(1)
  })

  it('stays on at 60 fps, and ignores a hidden-tab pause', () => {
    const onSlow = vi.fn()
    useFpsGuard(onSlow)
    run(60, 4)
    frame(null, 5)  // tab was hidden for 5 seconds
    run(60, 2)
    expect(onSlow).not.toHaveBeenCalled()
  })
})
