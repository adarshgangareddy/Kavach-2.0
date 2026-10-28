import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EFFECTS_KEY, EffectsProvider } from './effects.jsx'
import ShieldLock from './ShieldLock.jsx'
import VerifiedBadge, { isProven } from './VerifiedBadge.jsx'

const wrap = (ui) => render(<EffectsProvider detectWebGL={() => true}>{ui}</EffectsProvider>)

beforeEach(() => {
  window.localStorage.clear()
  window.matchMedia = () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })
})
afterEach(cleanup)

describe('proof-confirmed moment', () => {
  it('only proof-confirmed findings count as proven', () => {
    expect(isProven({ confidence_tier: 'proof-confirmed' })).toBe(true)
    expect(isProven({ confidence_tier: 'reachable' })).toBe(false)
    expect(isProven({ confidence_tier: 'pattern-match' })).toBe(false)
    expect(isProven(null)).toBe(false)
  })

  it('plays the shield-lock animation when effects are on', () => {
    wrap(<ShieldLock />)
    expect(screen.getByTestId('shield-lock').getAttribute('class')).toContain('animate')
  })

  it('shows the finished shield, without animating, when Reduce effects is on', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    wrap(<ShieldLock />)
    const cls = screen.getByTestId('shield-lock').getAttribute('class')
    expect(cls).toContain('static')
    expect(cls).not.toContain('animate')
  })

  it('the badge says Verified in words, and the shield is hidden from screen readers', () => {
    wrap(<><ShieldLock /><VerifiedBadge /></>)
    expect(screen.getByText('Verified')).toBeTruthy()
    expect(screen.getByTestId('shield-lock').getAttribute('aria-hidden')).toBe('true')
  })
})

// The finding page shows the moment only for a proof-confirmed finding.
const base = { id: 'F-0000bbbb-001', scan_id: 'S-0000bbbb', file: 'app.py', line: 2, cwe: 'CWE-89',
  owasp: '', source: 'request.args', path: ['f()', 'db.execute'], sink: 'db.execute', detector: 'taint',
  ml_rank: 0.9, severity: 9.8, severity_factors: { base: 6 }, fix_suggestion: 'x', status: 'open' }
let current = base
vi.mock('../api.js', async (load) => ({
  ...(await load()),
  api: {
    finding: async () => current, findings: async () => [current],
    source: async () => 'def f():\n    db.execute(q)\n', patch: async () => ({ available: false, reason: 'test' }),
  },
}))

describe('finding page', () => {
  beforeEach(() => { Element.prototype.scrollIntoView = () => {} })

  it.each([['proof-confirmed', true], ['reachable', false]])('tier %s shows the Verified moment: %s', async (tier, shown) => {
    current = { ...base, confidence_tier: tier }
    const { default: FindingView } = await import('../pages/FindingView.jsx')
    wrap(<FindingView findingId={base.id} />)
    await screen.findByText(/how to fix it/i)
    expect(Boolean(screen.queryByText('Verified'))).toBe(shown)
    expect(Boolean(screen.queryByTestId('shield-lock'))).toBe(shown)
  })
})
