import { useEffect, useState } from 'react'
import { api, STATUSES } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { ErrorBox, SeverityPill, Spinner, StatusPill, TierPill } from '../components.jsx'

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

export default function FindingView({ findingId }) {
  const catalog = useCatalog()
  const [finding, setFinding] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
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
        <a href="#/">Scans</a> / <a href={`#/scans/${finding.scan_id}`}>{finding.scan_id}</a> / {finding.id}
      </nav>

      <section className="card finding-head">
        <div>
          <div className="pills">
            <SeverityPill score={finding.severity} />
            <TierPill tier={finding.confidence_tier} />
            <StatusPill status={finding.status} />
          </div>
          <h1>{cweTitle(catalog, finding.cwe)}</h1>
          <p className="mono location">{finding.file}:{finding.line}</p>
          <p className="muted small">
            {cweNumber
              ? <a href={`https://cwe.mitre.org/data/definitions/${cweNumber}.html`} target="_blank" rel="noreferrer">{finding.cwe}</a>
              : finding.cwe}
            {' · '}{finding.owasp} · detector: {finding.detector} · ML rank {finding.ml_rank.toFixed(2)}
          </p>
        </div>
        <div className="status-actions" role="group" aria-label="Change status">
          {STATUSES.map((s) => (
            <button key={s} type="button" disabled={saving || finding.status === s}
                    className={finding.status === s ? 'active' : ''} onClick={() => changeStatus(s)}>
              {s === 'open' ? 'Reopen' : s === 'fixed' ? 'Mark fixed' : 'Accept risk'}
            </button>
          ))}
        </div>
      </section>
      <ErrorBox error={error} />

      <div className="grid two">
        <section className="card">
          <h2>Where</h2>
          <SourceView scanId={finding.scan_id} file={finding.file} line={finding.line} />
        </section>
        <section className="card">
          <h2>Source to sink path</h2>
          <PathChain finding={finding} />
          <p className="muted small">{TIER_HELP[finding.confidence_tier]}</p>
        </section>
      </div>

      <div className="grid two">
        <section className="card">
          <h2>Why this severity</h2>
          <SeverityBreakdown finding={finding} />
        </section>
        <section className="card">
          <h2>How to fix</h2>
          <p className="fix">{finding.fix_suggestion}</p>
          <p className="muted small">Suggestion only. Review before applying.</p>
        </section>
      </div>
    </>
  )
}
