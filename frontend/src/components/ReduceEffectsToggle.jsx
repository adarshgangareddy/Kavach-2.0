import { useEffects } from './effects.jsx'

/**
 * Header switch: turns every 3D view and animation into its plain 2D version. When Kavach turned
 * 3D off by itself (slow frames, an error, a graphics reset), it says "3D paused", tells why in its
 * tooltip, and a click brings 3D back without reloading.
 */
export default function ReduceEffectsToggle() {
  const { reduceEffects, setReduceEffects, prefersReduced, disabled, retry3D, offMessage } = useEffects()
  if (disabled && !reduceEffects && !prefersReduced) {
    return (
      <button type="button" className="small-button effects-toggle paused" aria-pressed="true"
              title={`${offMessage} Click to try 3D again.`} onClick={retry3D}>
        <span className="effects-dot" aria-hidden="true" />
        3D paused
      </button>
    )
  }
  const off = reduceEffects || prefersReduced
  return (
    <button type="button" className="small-button effects-toggle" aria-pressed={off}
            disabled={prefersReduced} title={off || offMessage ? offMessage : undefined}
            onClick={() => setReduceEffects(!reduceEffects)}>
      <span className="effects-dot" aria-hidden="true" />
      {off ? 'Effects off' : 'Reduce effects'}
    </button>
  )
}
