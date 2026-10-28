import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EFFECTS_KEY, EffectsProvider, useEffects } from './effects.jsx'
import HeroBackdrop from './HeroBackdrop.jsx'
import ReduceEffectsToggle from './ReduceEffectsToggle.jsx'
import Safe3D from './Safe3D.jsx'

// jsdom has no WebGL: the real 3D scene is replaced by a marker. The fallback logic is what is tested.
vi.mock('../three/CodeGraph3D.jsx', () => ({ default: () => <div data-testid="code-graph-3d" /> }))

function mockMedia({ reducedMotion = false, small = false } = {}) {
  window.matchMedia = (query) => ({
    matches: (query.includes('reduce') && reducedMotion) || (query.includes('max-width') && small),
    addEventListener: () => {}, removeEventListener: () => {},
  })
}

function renderHero({ variant = 'home', webgl = true } = {}) {
  return render(
    <EffectsProvider detectWebGL={() => webgl}>
      <ReduceEffectsToggle />
      <HeroBackdrop variant={variant} />
    </EffectsProvider>,
  )
}

beforeEach(() => {
  window.localStorage.clear()
  mockMedia()
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('hero code graph', () => {
  it('shows 3D when effects are on and WebGL works', async () => {
    renderHero()
    expect(await screen.findByTestId('code-graph-3d')).toBeTruthy()
  })

  it('shows the 2D version when Reduce effects is on', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    renderHero()
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
    expect(screen.queryByTestId('code-graph-3d')).toBeNull()
  })

  it('switches to 2D when the toggle is clicked, and remembers it', async () => {
    renderHero()
    await screen.findByTestId('code-graph-3d')
    fireEvent.click(screen.getByRole('button', { name: /reduce effects/i }))
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
    expect(window.localStorage.getItem(EFFECTS_KEY)).toBe('1')
    expect(screen.getByRole('button', { name: /effects off/i }).getAttribute('aria-pressed')).toBe('true')
  })

  it('shows 2D when the system asks for reduced motion', () => {
    mockMedia({ reducedMotion: true })
    renderHero()
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
  })

  it('shows 2D when WebGL is unavailable', () => {
    renderHero({ webgl: false })
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
  })

  it('uses 2D on phones, except for the login hero', async () => {
    mockMedia({ small: true })
    const { unmount } = renderHero({ variant: 'home' })
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
    unmount()
    renderHero({ variant: 'login' })
    expect(await screen.findByTestId('code-graph-3d')).toBeTruthy()
  })

  it('still renders when localStorage is blocked', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    renderHero()
    expect(await screen.findByTestId('code-graph-3d')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /reduce effects/i }))
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
  })
})

describe('Safe3D', () => {
  it('shows the 2D fallback when a 3D view throws', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const Broken = () => { throw new Error('no GPU') }
    render(
      <EffectsProvider detectWebGL={() => true}>
        <Safe3D fallback={<p>flat version</p>}><Broken /></Safe3D>
      </EffectsProvider>,
    )
    expect(screen.getByText('flat version')).toBeTruthy()
  })

  it('falls back to 2D after the frame-rate guard gives up', async () => {
    let effects
    const Probe = () => { effects = useEffects(); return null }
    render(
      <EffectsProvider detectWebGL={() => true}>
        <Probe />
        <HeroBackdrop />
      </EffectsProvider>,
    )
    await screen.findByTestId('code-graph-3d')
    act(() => effects.disable3D('slow'))
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
  })
})

describe('3D paused', () => {
  it('says why 3D switched off by itself, and one click brings it back', async () => {
    let effects
    const Probe = () => { effects = useEffects(); return null }
    render(
      <EffectsProvider detectWebGL={() => true}>
        <Probe />
        <ReduceEffectsToggle />
        <HeroBackdrop />
      </EffectsProvider>,
    )
    await screen.findByTestId('code-graph-3d')
    vi.spyOn(console, 'info').mockImplementation(() => {})
    act(() => effects.disable3D('slow'))
    const paused = screen.getByRole('button', { name: /3d paused/i })
    expect(paused.title).toMatch(/under 40 frames a second/)
    expect(screen.getByTestId('code-graph-2d')).toBeTruthy()
    fireEvent.click(paused)
    expect(await screen.findByTestId('code-graph-3d')).toBeTruthy()
    expect(screen.getByRole('button', { name: /reduce effects/i })).toBeTruthy()
  })

  it('explains a missing WebGL in the toggle tooltip', () => {
    renderHero({ webgl: false })
    expect(screen.getByRole('button', { name: /reduce effects/i }).title).toMatch(/cannot draw 3D/)
  })
})
