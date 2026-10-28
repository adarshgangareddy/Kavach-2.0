import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CountUp from './CountUp.jsx'
import { EFFECTS_KEY, EffectsProvider } from './effects.jsx'
import PageTransition from './PageTransition.jsx'
import SeverityViz from './SeverityViz.jsx'
import Tilt, { MAX_TILT } from './Tilt.jsx'

vi.mock('../three/SeverityBars3D.jsx', () => ({
  default: ({ rows }) => <div data-testid="severity-3d">{rows.map((r) => r.key).join(',')}</div>,
}))

const wrap = (ui) => render(<EffectsProvider detectWebGL={() => true}>{ui}</EffectsProvider>)
const effectsOff = () => window.localStorage.setItem(EFFECTS_KEY, '1')
const FINDINGS = [{ severity: 9.3 }, { severity: 9.1 }, { severity: 7.5 }, { severity: 5 }]

beforeEach(() => {
  window.localStorage.clear()
  window.matchMedia = (q) => ({ matches: q.includes('hover'), addEventListener: () => {}, removeEventListener: () => {} })
})
afterEach(cleanup)

describe('CountUp', () => {
  it('counts up from zero, while screen readers get the final number at once', async () => {
    const { container } = wrap(<CountUp value={12} duration={50} />)
    expect(container.querySelector('.sr-only').textContent).toBe('12')
    expect(container.querySelector('[aria-hidden]').textContent).toBe('0')
    await waitFor(() => expect(container.querySelector('[aria-hidden]').textContent).toBe('12'))
  })

  it('shows the final number straight away when effects are off', () => {
    effectsOff()
    const { container } = wrap(<CountUp value={12} />)
    expect(container.querySelector('[aria-hidden]').textContent).toBe('12')
  })
})

describe('Tilt', () => {
  const card = () => screen.getByText('card')
  // jsdom has no PointerEvent, so send a mouse event named pointermove: it carries clientX/Y.
  const point = (x, y) => fireEvent(card(), new MouseEvent('pointermove', { bubbles: true, clientX: x, clientY: y }))
  const box = { left: 0, top: 0, width: 100, height: 100, right: 100, bottom: 100 }

  it(`tilts toward the mouse, never more than ${MAX_TILT} degrees`, () => {
    wrap(<Tilt>card</Tilt>)
    card().getBoundingClientRect = () => box
    point(100, 0)  // top-right corner: the strongest tilt
    const degrees = [...card().style.transform.matchAll(/(-?[\d.]+)deg/g)].map((m) => Math.abs(Number(m[1])))
    expect(Math.max(...degrees)).toBeLessThanOrEqual(MAX_TILT)
    expect(Math.max(...degrees)).toBeGreaterThan(0)
    fireEvent.pointerLeave(card())
    expect(card().style.transform).toBe('')
  })

  it('stays flat when effects are off, and passes other props through', () => {
    effectsOff()
    wrap(<Tilt as="button" type="button" aria-pressed="true">card</Tilt>)
    card().getBoundingClientRect = () => box
    point(100, 0)
    expect(card().style.transform).toBe('')
    expect(card().tagName).toBe('BUTTON')
    expect(card().getAttribute('aria-pressed')).toBe('true')
  })
})

describe('SeverityViz', () => {
  it('shows the 3D bars when effects allow', async () => {
    wrap(<SeverityViz findings={FINDINGS} selected="" onSelect={() => {}} />)
    expect((await screen.findByTestId('severity-3d')).textContent).toBe('critical,high,medium')
  })

  it('falls back to the 2D bar chart, which still filters', () => {
    effectsOff()
    const onSelect = vi.fn()
    wrap(<SeverityViz findings={FINDINGS} selected="" onSelect={onSelect} />)
    expect(screen.queryByTestId('severity-3d')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /critical\s*2/i }))
    expect(onSelect).toHaveBeenCalledWith('critical')
  })

  it('renders nothing without open issues', () => {
    const { container } = wrap(<SeverityViz findings={[]} selected="" onSelect={() => {}} />)
    expect(container.querySelector('.severity-viz')).toBeNull()
  })
})

describe('PageTransition', () => {
  it('renders the page with effects on and off', async () => {
    wrap(<PageTransition routeKey="/a"><p>page A</p></PageTransition>)
    expect(await screen.findByText('page A')).toBeTruthy()
    cleanup()
    effectsOff()
    wrap(<PageTransition routeKey="/a"><p>page A</p></PageTransition>)
    expect(screen.getByText('page A')).toBeTruthy()
  })
})
