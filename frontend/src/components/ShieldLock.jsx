import { useEffects } from './effects.jsx'

/**
 * A shield that draws itself and locks shut in one second, for a proof-confirmed finding.
 * With effects off it shows the finished, locked shield straight away. Decorative: the
 * Verified badge next to it says the same thing in words.
 */
export default function ShieldLock({ size = 44 }) {
  const { motion } = useEffects()
  return (
    <svg className={`shield-lock ${motion ? 'animate' : 'static'}`} data-testid="shield-lock" width={size} height={size}
         viewBox="0 0 48 48" aria-hidden="true" focusable="false">
      <path className="shield-outline" pathLength="1" fill="none" strokeWidth="2.5" strokeLinejoin="round"
            d="M24 4 8 10v12c0 10.5 6.8 19.3 16 22 9.2-2.7 16-11.5 16-22V10L24 4Z" />
      <rect className="lock-body" x="17" y="22" width="14" height="11" rx="2.5" />
      <path className="lock-shackle" fill="none" strokeWidth="2.5" strokeLinecap="round"
            d="M20 22v-3.5a4 4 0 0 1 8 0V22" />
      <circle className="lock-keyhole" cx="24" cy="27.5" r="1.6" />
    </svg>
  )
}
