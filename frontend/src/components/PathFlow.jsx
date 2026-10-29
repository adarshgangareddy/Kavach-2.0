import { lazy, useState } from 'react'
import { useEffects } from './effects.jsx'
import Safe3D from './Safe3D.jsx'

const PathChain3D = lazy(() => import('../three/PathChain3D.jsx'))
const KIND_LABEL = { source: 'source', function: 'step', sink: 'sink' }

/**
 * How the data gets there: a 3D chain (when effects allow) above a list of the same steps.
 * The list is always shown: it is the 2D version, and the way to use this with a keyboard.
 * Picking a step, in either, highlights its line in the code panel.
 */
export default function PathFlow({ chain, selected, onSelect }) {
  const { allow3D } = useEffects()
  const [playKey, setPlayKey] = useState(0)
  const [playing, setPlaying] = useState(false)
  const show3D = chain.length >= 2 && allow3D()

  function play() {
    setPlaying(true)
    setPlayKey((n) => n + 1)
  }

  return (
    <div className="pathflow">
      {show3D && (
        <>
          <div className="pathchain-stage">
            <Safe3D fallback={null}>
              <PathChain3D chain={chain} selected={selected} onSelect={onSelect} playKey={playKey}
                           onPlayed={() => setPlaying(false)} />
            </Safe3D>
          </div>
          <div className="pathflow-actions">
            <button type="button" className="small-button" onClick={play} disabled={playing}>
              {playing ? 'Playing…' : '▶ Play the data flow'}
            </button>
            <span className="muted small">Click a step to see its line in the code.</span>
          </div>
        </>
      )}
      <ol className="chain" aria-label="Path from user input to the risky call">
        {chain.map((step, i) => (
          <li key={i} className={`step ${step.kind}`}>
            <small>{step.tag ?? (i === 0 && step.kind === 'source' ? 'source' : step.kind === 'sink' ? 'sink' : `step ${i}`)}</small>
            <button type="button" className={`step-button ${i === selected ? 'selected' : ''}`}
                    aria-pressed={i === selected} onClick={() => onSelect(i)}
                    aria-label={`${step.tag ?? KIND_LABEL[step.kind]} ${step.label}, ${step.line ? `line ${step.line}` : 'in another file'}`}>
              <code>{step.label}</code>
              <span className="muted small">{step.line ? `line ${step.line}` : 'in another file'}</span>
            </button>
          </li>
        ))}
      </ol>
    </div>
  )
}
