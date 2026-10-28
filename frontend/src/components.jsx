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

/** One plain-English sentence: what the finding means. */
export function plainSummary(f) {
  const steps = f.path.slice(0, -1)
  if (f.source && steps.length) {
    const via = steps.length > 1 ? ` through ${steps.slice(1).join(' → ')}` : ` in ${steps[0]}`
    const start = f.source.includes('(') ? `${f.source}` : `${f.source} (user input)`
    const clean = f.severity_factors.sanitizer_present < 0
      ? ' A cleaning function is on the path, so it is probably safe: check it.'
      : ' Nothing cleans it on the way.'
    return `Data from ${start} reaches ${f.sink}${via}.${clean}`
  }
  return `${f.detector} flagged a risky pattern on this line (${f.sink}). ` +
    'It has not been shown that user input reaches it.'
}

export function severityRows(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]))
  findings.forEach((f) => counts[severityLabel(f.severity)]++)
  return SEVERITY_ORDER.filter((s) => s !== 'info' || counts.info)
    .map((s) => ({ key: s, label: s, value: counts[s], className: `sev-${s}` }))
}
