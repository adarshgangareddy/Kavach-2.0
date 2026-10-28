import { useMemo } from 'react'
import { layoutCallGraph } from '../three/callGraph.js'

const UNIT = 90          // pixels per layout unit
const PAD = 70
const LABEL_CHARS = 18

const short = (label) => (label.length > LABEL_CHARS ? `${label.slice(0, LABEL_CHARS - 1)}…` : label)

/** Flat version of the scan's call graph: the same layout as 3D, drawn once in SVG. */
export default function CallGraph2D({ mode, graph }) {
  const layout = useMemo(() => (graph ? layoutCallGraph(graph) : null), [graph])
  if (mode === 'building' || !graph) {
    return (
      <div className="callgraph-2d building" data-testid="call-graph-2d">
        <span className="build-dots" aria-hidden="true"><i /><i /><i /><i /><i /></span>
      </div>
    )
  }
  const points = [...layout.values()]
  const xs = points.map((p) => p[0])
  const ys = points.map((p) => p[1])
  const minX = Math.min(...xs)
  const minY = Math.min(...ys)
  const width = (Math.max(...xs) - minX) * UNIT + PAD * 2
  const height = (Math.max(...ys) - minY) * UNIT + PAD * 2
  const at = (id) => {
    const [x, y] = layout.get(id)
    return [(x - minX) * UNIT + PAD, height - ((y - minY) * UNIT + PAD)]
  }
  return (
    <svg className="callgraph-2d" data-testid="call-graph-2d" viewBox={`0 0 ${width} ${height}`}
         preserveAspectRatio="xMidYMid meet" aria-hidden="true" focusable="false">
      {graph.edges.map(([a, b]) => {
        const [x1, y1] = at(a)
        const [x2, y2] = at(b)
        return <line key={`${a}>${b}`} className="cg-edge" x1={x1} y1={y1} x2={x2} y2={y2} />
      })}
      {graph.nodes.map((n) => {
        const [x, y] = at(n.id)
        return (
          <g key={n.id} className={`cg-node ${n.kind}`}>
            <circle cx={x} cy={y} r={n.kind === 'function' ? 7 : 9} />
            <text x={x} y={y + 24} textAnchor="middle"><title>{n.label}</title>{short(n.label)}</text>
          </g>
        )
      })}
    </svg>
  )
}
