import { cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { EFFECTS_KEY, EffectsProvider } from './effects.jsx'
import PatternWaves from './PatternWaves.jsx'

describe('PatternWaves Component', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })
  afterEach(cleanup)

  it('renders canvas element when motion is enabled', () => {
    const { container } = render(
      <EffectsProvider detectWebGL={() => true}>
        <PatternWaves />
      </EffectsProvider>,
    )
    expect(container.querySelector('.pattern-waves-canvas')).toBeTruthy()
    expect(container.querySelector('.pattern-waves-static-fallback')).toBeNull()
  })

  it('renders static fallback when reduce-effects is active', () => {
    window.localStorage.setItem(EFFECTS_KEY, '1')
    const { container } = render(
      <EffectsProvider detectWebGL={() => true}>
        <PatternWaves />
      </EffectsProvider>,
    )
    expect(container.querySelector('.pattern-waves-static-fallback')).toBeTruthy()
    expect(container.querySelector('.pattern-waves-canvas')).toBeNull()
  })
})
