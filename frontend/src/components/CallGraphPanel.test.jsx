import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CallGraphPanel from './CallGraphPanel.jsx'
import { EFFECTS_KEY, EffectsProvider } from './effects.jsx'

vi.mock('../three/CallGraph3D.jsx', () => ({ default: ({ mode }) => <div data-testid="call-graph-3d">{mode}</div> }))

const done = { status: 'done' }
const traced = (over) => ({ id: 'F-1', cwe: 'CWE-89', severity: 9.3, file: 'helpers.py', line: 16, status: 'open',
  source: 'request.args', path: ['lookup()', 'db.execute'], sink: 'db.execute', ...over })

function show(scan, findings, { webgl = true } = {}) {
  return render(<EffectsProvider detectWebGL={() => webgl}><CallGraphPanel scan={scan} findings={findings} /></EffectsProvider>)
}

beforeEach(() => {
  window.localStorage.clear()
  window.matchMedia = () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })
})
afterEach(cleanup)

describe('scan call graph', () => {
  it('builds in 3D while the scan runs, with a status line', async () => {
    show({ status: 'running' }, null)
    expect((await screen.findByTestId('call-graph-3d')).textContent).toBe('building')
    expect(screen.getByText(/following user input/i)).toBeTruthy()
  })

  it('shows the real traced paths in 3D, and the same paths as a table', async () => {
    show(done, [traced(), traced({ id: 'F-2', line: 30, path: ['save()', 'open'], cwe: 'CWE-22', severity: 8.3 })])
    expect((await screen.findByTestId('call-graph-3d')).textContent).toBe('result')
    const rows = within(screen.getByRole('table')).getAllByRole('row')
    expect(rows).toHaveLength(3)  // header + 2 paths
    expect(rows[1].textContent).toContain('request.args')
    expect(rows[1].textContent).toContain('db.execute')
    expect(screen.getByRole('link', { name: 'helpers.py:16' }).getAttribute('href')).toBe('#/findings/F-1')
  })

  it('renders the 2D version when Reduce effects is on, keeping the table', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    show(done, [traced()])
    expect(screen.getByTestId('call-graph-2d')).toBeTruthy()
    expect(screen.queryByTestId('call-graph-3d')).toBeNull()
    expect(screen.getByRole('table')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Replay' })).toBeNull()
  })

  it('renders the 2D building view when Reduce effects is on during a scan', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    show({ status: 'queued' }, null)
    expect(screen.getByTestId('call-graph-2d')).toBeTruthy()
  })

  it('renders 2D without WebGL', () => {
    show(done, [traced()], { webgl: false })
    expect(screen.getByTestId('call-graph-2d')).toBeTruthy()
  })

  it('is left out when no finding has a traced path', () => {
    const { container } = show(done, [traced({ source: '', path: [] })])
    expect(container.querySelector('.callgraph-card')).toBeNull()
  })
})
