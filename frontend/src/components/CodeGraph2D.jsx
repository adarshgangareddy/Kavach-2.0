import { useMemo } from 'react'
import { makeGraph } from '../three/graphData.js'

const W = 800
const H = 460

/** The hero graph drawn flat in SVG: the fallback when 3D is off, unsupported or failed. */
export default function CodeGraph2D() {
  const { nodes, edges, risky } = useMemo(() => makeGraph(), [])
  const point = (n) => {  // simple perspective so it matches the 3D view's shape
    const scale = 6 / (6 + n.z)
    return [W / 2 + n.x * 78 * scale, H / 2 + n.y * 78 * scale, scale]
  }
  return (
    <svg className="graph-2d" data-testid="code-graph-2d" viewBox={`0 0 ${W} ${H}`}
         preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">
      <g className="graph-2d-lines">
        {edges.map(([a, b]) => {
          const [x1, y1] = point(nodes[a])
          const [x2, y2] = point(nodes[b])
          return <line key={`${a}-${b}`} x1={x1} y1={y1} x2={x2} y2={y2} />
        })}
      </g>
      {nodes.map((n, i) => {
        const [x, y, s] = point(n)
        return risky.has(i)
          ? <circle key={i} className="graph-2d-risky" cx={x} cy={y} r={4.2 * s} />
          : <circle key={i} className="graph-2d-node" cx={x} cy={y} r={2.6 * s} />
      })}
    </svg>
  )
}
