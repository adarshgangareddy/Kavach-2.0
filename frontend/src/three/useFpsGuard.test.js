import { beforeEach, describe, expect, it, vi } from 'vitest'

// Drive the guard's frame callback by hand instead of running a real render loop.
let frame
vi.mock('@react-three/fiber', () => ({ useFrame: (fn) => { frame = fn } }))
vi.mock('react', async (load) => ({ ...(await load()), useRef: (v) => ({ current: v }) }))

const { useFpsGuard } = await import('./useFpsGuard.js')

// jsdom reports every page as hidden; a real, visible tab is what these tests model.
const setHidden = (hidden) => Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden })
beforeEach(() => setHidden(false))

function run(fps, seconds) {
  for (let i = 0; i < fps * seconds; i += 1) frame(null, 1 / fps)
}

describe('useFpsGuard', () => {
  it('gives up after 2 seconds under 40 fps', () => {
    const onSlow = vi.fn()
    useFpsGuard(onSlow)
    run(60, 1.5)  // warm-up: never counted
    run(30, 1.5)  // 1.5 s slow: not yet
    expect(onSlow).not.toHaveBeenCalled()
    run(30, 1)    // past 2 s slow: give up
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

  it('ignores sparse on-demand frames (hover, click) while the view is not animating', () => {
    const onSlow = vi.fn()
    useFpsGuard(onSlow, { enabled: false })
    for (let i = 0; i < 100; i += 1) frame(null, 0.2)  // one redraw every 0.2 s looks like "5 fps"
    expect(onSlow).not.toHaveBeenCalled()
  })

  it('does not count time while the tab is hidden', () => {
    const onSlow = vi.fn()
    useFpsGuard(onSlow)
    setHidden(true)
    run(20, 5)
    setHidden(false)
    expect(onSlow).not.toHaveBeenCalled()
  })
})
