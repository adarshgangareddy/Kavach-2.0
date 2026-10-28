import { lazy } from 'react'
import { BarChart, severityRows } from '../components.jsx'
import Safe3D from './Safe3D.jsx'

const SeverityBars3D = lazy(() => import('../three/SeverityBars3D.jsx'))

/**
 * Severity of the open issues: 3D bars when effects allow, otherwise the plain bar chart.
 * Both filter the list when clicked; the severity chips above carry the same numbers as text.
 */
export default function SeverityViz({ findings, selected, onSelect }) {
  const rows = severityRows(findings).filter((r) => r.value > 0)
  if (rows.length === 0) return null
  return (
    <div className="severity-viz">
      <Safe3D fallback={<BarChart title="Open issues by severity" rows={rows} selected={selected} onSelect={onSelect} />}>
        <div className="sevbars-stage">
          <SeverityBars3D rows={rows} selected={selected} onSelect={onSelect} />
        </div>
      </Safe3D>
    </div>
  )
}
