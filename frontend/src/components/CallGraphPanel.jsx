import { lazy, useMemo, useState } from 'react'
import { SeverityPill } from '../components.jsx'
import { buildCallGraph } from '../three/callGraph.js'
import CallGraph2D from './CallGraph2D.jsx'
import { useEffects } from './effects.jsx'
import Safe3D from './Safe3D.jsx'

const CallGraph3D = lazy(() => import('../three/CallGraph3D.jsx'))
const SHOWN_PATHS = 10

/** Every traced path as text: the table version of what the graph animates. */
function TracedPaths({ paths }) {
  const [all, setAll] = useState(false)
  const shown = all ? paths : paths.slice(0, SHOWN_PATHS)
  return (
    <div className="table-wrap">
      <table className="traced-paths">
        <caption className="muted small">Traced paths: where user input goes, from source to sink</caption>
        <thead><tr><th>Severity</th><th>Path</th><th>Where</th></tr></thead>
        <tbody>
          {shown.map((p) => (
            <tr key={p.findingId}>
              <td><SeverityPill score={p.severity} /></td>
              <td>
                <ol className="chain-inline" aria-label="Path">
                  {p.labels.map((label, i) => (
                    <li key={i} className={i === 0 ? 'source' : i === p.labels.length - 1 ? 'sink' : ''}>
                      <code>{label}</code>
                    </li>
                  ))}
                </ol>
              </td>
              <td><a className="mono" href={`#/findings/${p.findingId}`}>{p.file}:{p.line}</a></td>
            </tr>
          ))}
        </tbody>
      </table>
      {paths.length > SHOWN_PATHS && (
        <button type="button" className="link small" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${paths.length} paths`}
        </button>
      )}
    </div>
  )
}

/**
 * The scan page's call graph: grows while the scan runs, then replays each real traced path
 * as data flowing from source to sink. The table below carries the same information as text.
 */
export default function CallGraphPanel({ scan, findings }) {
  const { allow3D } = useEffects()
  const [replay, setReplay] = useState(0)
  const graph = useMemo(() => (findings ? buildCallGraph(findings) : null), [findings])
  const building = !findings && (scan.status === 'queued' || scan.status === 'running')
  if (!building && (!graph || graph.paths.length === 0)) return null
  const mode = building ? 'building' : 'result'

  return (
    <section className="card callgraph-card" aria-labelledby="callgraph-title">
      <div className="section-head">
        <h2 id="callgraph-title">Call graph</h2>
        {mode === 'result' && allow3D() && (
          <button type="button" className="small-button" onClick={() => setReplay((n) => n + 1)}>Replay</button>
        )}
      </div>
      <p className="muted small" aria-live="polite">
        {building
          ? 'Scanning: following user input through the functions in your code…'
          : `${graph.paths.length} traced ${graph.paths.length === 1 ? 'path' : 'paths'} from user input to a risky call.`}
      </p>
      <div className="callgraph-stage">
        <Safe3D fallback={<CallGraph2D mode={mode} graph={graph} />}>
          <CallGraph3D key={`${mode}-${replay}`} mode={mode} graph={graph} />
        </Safe3D>
      </div>
      {mode === 'result' && (
        <>
          <ul className="cg-legend" aria-hidden="true">
            <li className="source">Source (user input)</li>
            <li className="function">Your functions</li>
            <li className="sink">Sink (risky call)</li>
          </ul>
          <TracedPaths paths={graph.paths} />
        </>
      )}
    </section>
  )
}
