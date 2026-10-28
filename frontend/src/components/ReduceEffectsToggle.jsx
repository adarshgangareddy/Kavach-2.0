import { useEffects } from './effects.jsx'

/** Header switch: turns every 3D view and animation into its plain 2D version. */
export default function ReduceEffectsToggle() {
  const { reduceEffects, setReduceEffects, prefersReduced } = useEffects()
  const off = reduceEffects || prefersReduced
  return (
    <button type="button" className="small-button effects-toggle" aria-pressed={off}
            disabled={prefersReduced}
            title={prefersReduced ? 'Your system asks for reduced motion, so effects stay off' : undefined}
            onClick={() => setReduceEffects(!reduceEffects)}>
      <span className="effects-dot" aria-hidden="true" />
      {off ? 'Effects off' : 'Reduce effects'}
    </button>
  )
}
