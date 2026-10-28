import { AnimatePresence, LazyMotion, m } from 'framer-motion'
import { useEffects } from './effects.jsx'

// The animation code loads in its own chunk after the first paint, so it does not slow the first page.
const loadFeatures = () => import('./motionFeatures.js').then((mod) => mod.default)

const VARIANTS = {
  enter: { opacity: 0, y: 8 },
  shown: { opacity: 1, y: 0, transition: { duration: 0.22, ease: [0.2, 0.8, 0.2, 1] } },
  leave: { opacity: 0, y: -6, transition: { duration: 0.14, ease: 'easeIn' } },
}

/** A short fade and lift between pages. With effects off, pages swap instantly. */
export default function PageTransition({ routeKey, children }) {
  const { motion } = useEffects()
  if (!motion) return <div className="page">{children}</div>
  return (
    <LazyMotion features={loadFeatures} strict>
      <AnimatePresence mode="wait" initial={false}>
        <m.div key={routeKey} className="page" variants={VARIANTS} initial="enter" animate="shown" exit="leave">
          {children}
        </m.div>
      </AnimatePresence>
    </LazyMotion>
  )
}
