import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { EFFECTS_KEY, EffectsProvider } from '../components/effects.jsx'
import FindingView from './FindingView.jsx'

const FILE = ['from flask import request', '', '@app.route("/l")', 'def lookup():',
  '    name = request.args.get("n")', '    return db.execute("SELECT " + name)'].join('\n')
const FINDING = { id: 'F-0000aaaa-001', scan_id: 'S-0000aaaa', file: 'app.py', line: 6, cwe: 'CWE-89',
  owasp: 'A03:2021 Injection', source: 'request.args', path: ['lookup()', 'db.execute'], sink: 'db.execute',
  detector: 'taint', ml_rank: 0.9, severity: 9.3, severity_factors: { base: 6 }, confidence_tier: 'reachable',
  fix_suggestion: 'Use parameters.', status: 'open' }

vi.mock('../api.js', async (load) => ({
  ...(await load()),
  api: {
    finding: async () => FINDING,
    findings: async () => [FINDING],
    source: async () => FILE,
    patch: async () => ({ available: false, reason: 'test' }),
  },
}))

beforeEach(() => {
  window.localStorage.setItem(EFFECTS_KEY, '1')  // 2D: jsdom has no WebGL
  window.matchMedia = () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })
  Element.prototype.scrollIntoView = () => {}
})
afterEach(cleanup)

it('clicking a path step highlights its line in the code panel', async () => {
  render(<EffectsProvider detectWebGL={() => false}><FindingView findingId={FINDING.id} /></EffectsProvider>)
  fireEvent.click(await screen.findByRole('button', { name: 'step lookup(), line 4' }))
  const current = document.querySelector('.code [aria-current="true"]')
  expect(current.textContent).toContain('def lookup():')
  fireEvent.click(screen.getByRole('button', { name: 'source request.args, line 5' }))
  expect(document.querySelector('.code [aria-current="true"]').textContent).toContain('request.args.get')
})
