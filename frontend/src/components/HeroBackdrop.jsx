import { lazy } from 'react'
import CodeGraph2D from './CodeGraph2D.jsx'
import Safe3D from './Safe3D.jsx'

const CodeGraph3D = lazy(() => import('../three/CodeGraph3D.jsx'))

/**
 * Decorative code graph behind the login card (variant "login", fills the screen) or the home
 * hero (variant "home"). The login hero keeps 3D on phones; everything else uses 2D there.
 */
export default function HeroBackdrop({ variant = 'home' }) {
  return (
    <div className={`hero-backdrop ${variant}`} aria-hidden="true">
      <Safe3D allowSmall={variant === 'login'} fallback={<CodeGraph2D />}>
        <CodeGraph3D distance={variant === 'login' ? 7.5 : 4.6} />
      </Safe3D>
      <div className="hero-veil" />
    </div>
  )
}
