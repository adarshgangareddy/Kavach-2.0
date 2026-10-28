import { useState } from 'react'
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

/**
 * A delete button that asks for confirmation in the page itself. Browser pop-ups
 * (window.confirm) are blocked in some browsers and embedded views, where they
 * silently answer "Cancel".
 */
export function ConfirmDelete({ label = 'Delete', question = 'Delete for good?', onConfirm, disabled }) {
  const [armed, setArmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    setBusy(true)
    setError('')
    try {
      await onConfirm()
    } catch (err) {
      setError(err.message)
      setBusy(false)
      setArmed(false)
    }
  }

  if (!armed) {
    return (
      <span className="confirm-delete">
        <button type="button" className="danger" disabled={disabled} onClick={() => setArmed(true)}>{label}</button>
        {error && <span className="hint bad small" role="alert">{error}</span>}
      </span>
    )
  }
  return (
    <span className="confirm-delete armed" role="group" aria-label={question}>
      <span className="small">{question}</span>
      <button type="button" className="danger solid" disabled={busy} onClick={confirm} autoFocus>
        {busy ? 'Deleting…' : 'Yes, delete'}
      </button>
      <button type="button" disabled={busy} onClick={() => setArmed(false)}>Cancel</button>
    </span>
  )
}

/** Secrets and crypto problems are in the code itself: no user input has to reach them. */
const CODE_PROBLEMS = {
  'CWE-798': 'Anyone who can read the code or its history can use this secret.',
  'CWE-259': 'Anyone who can read the code or its history can use this password.',
  'CWE-327': 'This algorithm or setting is known to be breakable.',
  'CWE-916': 'Passwords hashed this way can be guessed quickly if the hashes leak.',
  'CWE-326': 'A key this short can be broken with enough computing power.',
  'CWE-295': 'Without certificate checks, anyone on the network can pretend to be the server.',
  'CWE-330': 'Values from the random module can be predicted by an attacker.',
}

/** One plain-English sentence: what the finding means. */
export function plainSummary(f) {
  if (CODE_PROBLEMS[f.cwe]) {
    const what = f.sink.includes(' ') ? f.sink : `${f.detector} flagged this line (${f.sink})`  // tool ids have no spaces
    return `${what}. ${CODE_PROBLEMS[f.cwe]}`
  }
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
