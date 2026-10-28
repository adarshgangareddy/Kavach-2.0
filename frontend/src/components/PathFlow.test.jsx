import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EFFECTS_KEY, EffectsProvider } from './effects.jsx'
import PathFlow from './PathFlow.jsx'

vi.mock('../three/PathChain3D.jsx', () => ({
  default: ({ chain, onSelect }) => (
    <div data-testid="path-chain-3d">{chain.map((s, i) => <span key={i} onClick={() => onSelect(i)}>{s.label}</span>)}</div>
  ),
}))

const CHAIN = [
  { label: 'request.args', kind: 'source', line: 5 },
  { label: 'lookup()', kind: 'function', line: 4 },
  { label: 'db.execute', kind: 'sink', line: 9 },
]

function show(chain = CHAIN, onSelect = () => {}) {
  return render(<EffectsProvider detectWebGL={() => true}><PathFlow chain={chain} selected={null} onSelect={onSelect} /></EffectsProvider>)
}

beforeEach(() => {
  window.localStorage.clear()
  window.matchMedia = () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })
})
afterEach(cleanup)

describe('finding path view', () => {
  it('shows the 3D chain, a Play button and the step list', async () => {
    show()
    expect(await screen.findByTestId('path-chain-3d')).toBeTruthy()
    expect(screen.getByRole('button', { name: /play the data flow/i })).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /line \d/ })).toHaveLength(3)
  })

  it('renders only the 2D step list when Reduce effects is on', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    show()
    expect(screen.queryByTestId('path-chain-3d')).toBeNull()
    expect(screen.queryByRole('button', { name: /play/i })).toBeNull()
    expect(screen.getByRole('button', { name: 'sink db.execute, line 9' })).toBeTruthy()
  })

  it('picks a step from the list or from a 3D node', async () => {
    const onSelect = vi.fn()
    show(CHAIN, onSelect)
    fireEvent.click(screen.getByRole('button', { name: 'step lookup(), line 4' }))
    fireEvent.click(within3D(await screen.findByTestId('path-chain-3d'), 'db.execute'))
    expect(onSelect.mock.calls).toEqual([[1], [2]])
  })

  it('says when a step is in another file', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    show([CHAIN[0], { label: 'helpers.other()', kind: 'function', line: null }, CHAIN[2]])
    expect(screen.getByRole('button', { name: 'step helpers.other(), in another file' })).toBeTruthy()
  })

  it('skips 3D for a single-step (pattern-only) finding', () => {
    show([{ label: 'open', kind: 'sink', line: 3 }])
    expect(screen.queryByTestId('path-chain-3d')).toBeNull()
  })
})

function within3D(root, text) {
  return [...root.querySelectorAll('span')].find((s) => s.textContent === text)
}
