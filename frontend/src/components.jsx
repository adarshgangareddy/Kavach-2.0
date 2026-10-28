import { SEVERITY_ORDER, severityLabel } from './api.js'

export function SeverityPill({ score }) {
  const label = severityLabel(score)
  return (
    <span className={`pill sev-${label}`}>
      {label} <strong>{score.toFixed(1)}</strong>
    </span>
  )
}

export function TierPill({ tier }) {
  return <span className={`pill tier tier-${tier}`}>{tier}</span>
}

export function StatusPill({ status }) {
  return <span className={`pill status-${status}`}>{status}</span>
}

export function ErrorBox({ error }) {
  return error ? <div className="alert error" role="alert">{error}</div> : null
}

export function Spinner({ label = 'Loading' }) {
  return <div className="muted spinner" aria-live="polite">{label}…</div>
}

/** Horizontal bar chart: rows of {key, label, value, className}. */
export function BarChart({ title, rows, onSelect, selected }) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <section className="card chart">
      <h3>{title}</h3>
      {rows.length === 0 && <p className="muted">No data</p>}
      <ul>
        {rows.map((r) => (
          <li key={r.key}>
            <button type="button" className={`bar-row ${selected === r.key ? 'selected' : ''}`}
                    onClick={() => onSelect?.(selected === r.key ? '' : r.key)}
                    disabled={!onSelect}>
              <span className="bar-label">{r.label}</span>
              <span className="bar-track">
                <span className={`bar-fill ${r.className ?? ''}`}
                      style={{ width: r.value ? `max(3px, ${(r.value / max) * 100}%)` : 0 }} />
              </span>
              <span className="bar-value">{r.value}</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function severityRows(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]))
  findings.forEach((f) => counts[severityLabel(f.severity)]++)
  return SEVERITY_ORDER.filter((s) => s !== 'info' || counts.info)
    .map((s) => ({ key: s, label: s, value: counts[s], className: `sev-${s}` }))
}
