import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { ErrorBox, SeverityPill, Spinner, StatusPill, TierPill, plainSummary } from '../components.jsx'

const CONTEXT_LINES = 8

const FACTOR_LABELS = {
  base: 'Base score for this CWE',
  reachable: 'Reachable from user input',
  public_route: 'Exposed on a public route',
  confidence: 'Detector confidence',
  sanitizer_present: 'Sanitizer on the path',
}

const TIER_HELP = {
  'pattern-match': 'Matched a risky pattern. Not yet shown to be reachable from user input.',
  reachable: 'A path from user input to the sink was traced statically.',
  'proof-confirmed': 'A harmless marker test confirmed the path in a sandbox.',
}

function SourceView({ scanId, file, line }) {
  const [text, setText] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.source(scanId, file).then(setText).catch((e) => setError(e.message))
  }, [scanId, file])

  if (error) return <p className="muted">Source unavailable: {error}</p>
  if (text === null) return <Spinner />
  const lines = text.split('\n')
  const start = Math.max(1, line - CONTEXT_LINES)
  const end = Math.min(lines.length, line + CONTEXT_LINES)
  return (
    <pre className="code" aria-label={`${file} lines ${start} to ${end}`}>
      {lines.slice(start - 1, end).map((content, i) => {
        const n = start + i
        return (
          <div key={n} className={n === line ? 'hl' : ''}>
            <span className="ln">{n}</span>
            <span>{content || ' '}</span>
          </div>
        )
      })}
    </pre>
  )
}

function PathChain({ finding }) {
  const steps = finding.path.length ? finding.path : [finding.sink].filter(Boolean)
  if (!steps.length && !finding.source) return <p className="muted">No path recorded for this finding.</p>
  return (
    <ol className="chain">
      {finding.source && <li className="step source"><small>source</small><code>{finding.source}</code></li>}
      {steps.map((step, i) => (
        <li key={i} className={`step ${i === steps.length - 1 ? 'sink' : ''}`}>
          <small>{i === steps.length - 1 ? 'sink' : `step ${i + 1}`}</small>
          <code>{step}</code>
        </li>
      ))}
    </ol>
  )
}

function SeverityBreakdown({ finding }) {
  const entries = Object.entries(finding.severity_factors)
  const raw = entries.reduce((sum, [, v]) => sum + v, 0)
  return (
    <div className="breakdown">
      {entries.map(([key, value]) => (
        <div key={key} className="factor">
          <span>{FACTOR_LABELS[key] ?? key}</span>
          <span className="factor-bar">
            <span className={value < 0 ? 'neg' : 'pos'} style={{ width: `${Math.min(100, (Math.abs(value) / 6) * 100)}%` }} />
          </span>
          <span className="mono">{value > 0 ? '+' : ''}{value.toFixed(1)}</span>
        </div>
      ))}
      <div className="factor total">
        <span>Severity = min(10, sum)</span><span />
        <span className="mono">{Math.min(10, Math.max(0, raw)).toFixed(1)}</span>
      </div>
    </div>
  )
}

const STATUS_ACTIONS = [
  { status: 'fixed', label: 'Mark fixed' },
  { status: 'accepted', label: 'Accept the risk' },
  { status: 'open', label: 'Reopen' },
]

function useNeighbours(scanId, findingId) {
  const [ids, setIds] = useState([])
  useEffect(() => {
    if (scanId) api.findings(scanId).then((all) => setIds(all.map((f) => f.id))).catch(() => setIds([]))
  }, [scanId])
  const i = ids.indexOf(findingId)
  return { prev: i > 0 ? ids.at(i - 1) : null, next: i >= 0 && i < ids.length - 1 ? ids.at(i + 1) : null,
           position: i >= 0 ? `${i + 1} of ${ids.length}` : '' }
}

export default function FindingView({ findingId }) {
  const catalog = useCatalog()
  const [finding, setFinding] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const { prev, next, position } = useNeighbours(finding?.scan_id, findingId)

  useEffect(() => {
    setFinding(null)
    api.finding(findingId).then(setFinding).catch((e) => setError(e.message))
  }, [findingId])

  async function changeStatus(status) {
    setSaving(true)
    setError('')
    try {
      setFinding(await api.setStatus(findingId, status))
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  if (!finding) return error ? <ErrorBox error={error} /> : <Spinner />
  const cweNumber = finding.cwe.match(/^CWE-(\d+)$/)?.[1]

  return (
    <>
      <nav className="crumbs">
        <a href="#/">Your scans</a> / <a href={`#/scans/${finding.scan_id}`}>All issues in this scan</a> / {finding.file}:{finding.line}
      </nav>

      <section className="card finding-head">
        <div className="finding-title">
          <div className="pills">
            <SeverityPill score={finding.severity} />
            <TierPill tier={finding.confidence_tier} />
            <StatusPill status={finding.status} />
          </div>
          <h1>{cweTitle(catalog, finding.cwe)}</h1>
          <p className="mono location">{finding.file}:{finding.line}</p>
          <p className="plain">{plainSummary(finding)}</p>
        </div>
        <nav className="pager" aria-label="Other issues">
          {prev ? <a className="button" href={`#/findings/${prev}`}>‹ Previous</a> : <span />}
          <span className="muted small">{position}</span>
          {next ? <a className="button" href={`#/findings/${next}`}>Next ›</a> : <span />}
        </nav>
      </section>
      <ErrorBox error={error} />

      <section className="card fix-card">
        <p className="eyebrow">Step 3 · Fix and re-check</p>
        <h2>How to fix it</h2>
        <p className="fix">{finding.fix_suggestion}</p>
        <ol className="next-steps">
          <li>Change the code at <span className="mono">{finding.file}:{finding.line}</span> as described above.</li>
          <li>Check your fix: <a href="#/">scan the changed code again</a> (the <em>Paste code</em> tab is quickest).</li>
          <li>
            Update this issue:{' '}
            <span className="status-actions" role="group" aria-label="Change status">
              {STATUS_ACTIONS.filter((a) => a.status !== finding.status).map((a) => (
                <button key={a.status} type="button" disabled={saving}
                        className={a.status === 'fixed' ? 'primary' : ''} onClick={() => changeStatus(a.status)}>
                  {a.label}
                </button>
              ))}
            </span>
          </li>
        </ol>
        <p className="muted small">Fix advice is a suggestion. Review it before applying.</p>
      </section>

      <div className="grid two">
        <section className="card">
          <h2>Where in the code</h2>
          <SourceView scanId={finding.scan_id} file={finding.file} line={finding.line} />
        </section>
        <section className="card">
          <h2>How the data gets there</h2>
          <PathChain finding={finding} />
          <p className="muted small">{TIER_HELP[finding.confidence_tier]}</p>
        </section>
      </div>

      <details className="card more">
        <summary>Why severity {finding.severity.toFixed(1)}? Score breakdown and details</summary>
        <SeverityBreakdown finding={finding} />
        <p className="muted small details-line">
          {cweNumber
            ? <a href={`https://cwe.mitre.org/data/definitions/${cweNumber}.html`} target="_blank" rel="noreferrer">{finding.cwe}</a>
            : finding.cwe}
          {' · '}{finding.owasp} · found by {finding.detector} · ML rank {finding.ml_rank.toFixed(2)}
          {' '}(how likely it is a real issue, 0 to 1)
        </p>
      </details>
    </>
  )
}
