import { Component, Suspense } from 'react'
import { useEffects } from './effects.jsx'

class Boundary extends Component {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch(error) {
    console.warn('A 3D view failed; showing its 2D version instead.', error)
    this.props.onFail?.()
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children
  }
}

/**
 * Renders a 3D view only when effects allow it. Otherwise, while it loads, or if it throws,
 * renders `fallback`, the plain 2D version, so the screen is never blank.
 */
export default function Safe3D({ fallback, allowSmall = false, children }) {
  const effects = useEffects()
  if (!effects.allow3D({ allowSmall })) return fallback
  return (
    <Boundary fallback={fallback} onFail={() => effects.disable3D('error')}>
      <Suspense fallback={fallback}>{children}</Suspense>
    </Boundary>
  )
}
