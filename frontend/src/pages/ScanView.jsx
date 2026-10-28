import { useEffect, useMemo, useState } from 'react'
import { api, severityLabel, SEVERITY_ORDER, STATUSES } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { BarChart, ErrorBox, SeverityPill, Spinner, StatusPill, TierPill, plainSummary, severityRows } from '../components.jsx'

const POLL_MS = 1000

function useScan(scanId) {
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    let timer
    async function poll() {
      try {
        const s = await api.getScan(scanId)
        if (cancelled) return
        setScan(s)
        if (s.status === 'done') setFindings(await api.findings(scanId))
        else if (s.status !== 'failed') timer = setTimeout(poll, POLL_MS)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }
    poll()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [scanId])

  return { scan, findings, error }
}

const EMPTY_FILTERS = { q: '', status: 'open', severity: '' }

function applyFilters(findings, f) {
  const q = f.q.trim().toLowerCase()
  return findings.filter((x) =>
    (!f.status || x.status === f.status) &&
    (!f.severity || severityLabel(x.severity) === f.severity) &&
    (!q || [x.file, x.sink, x.source, x.detector, x.cwe].some((v) => v?.toLowerCase().includes(q))),
  )
}

function SeverityChips({ findings, selected, onSelect }) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]))
  findings.forEach((f) => counts[severityLabel(f.severity)]++)
  return (
    <div className="chips" role="group" aria-label="Filter by severity">
      {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
        <button key={s} type="button" aria-pressed={selected === s}
                className={`chip sev-${s} ${selected === s ? 'on' : ''}`}
                onClick={() => onSelect(selected === s ? '' : s)}>
          <strong>{counts[s]}</strong> {s}
        </button>
      ))}
    </div>
  )
}

function FindingCard({ f, catalog }) {
  return (
    <li>
      <a href={`#/findings/${f.id}`} className="finding-card">
        <SeverityPill score={f.severity} />
        <span className="finding-main">
          <strong>{cweTitle(catalog, f.cwe)}</strong>
          <span className="mono small">{f.file}:{f.line}</span>
          <span className="muted small">{plainSummary(f)}</span>
        </span>
        <span className="finding-side">
          {f.status !== 'open' && <StatusPill status={f.status} />}
          <span className="chev" aria-hidden="true">›</span>
        </span>
      </a>
    </li>
  )
}

export default function ScanView({ scanId }) {
  const { scan, findings, error } = useScan(scanId)
  const catalog = useCatalog()
  const [filters, setFilters] = useState(EMPTY_FILTERS)

  const visible = useMemo(() => (findings ? applyFilters(findings, filters) : []), [findings, filters])
  const cweRows = useMemo(() => {
    const counts = {}
    findings?.forEach((f) => (counts[f.cwe] = (counts[f.cwe] ?? 0) + 1))
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
      .map(([cwe, value]) => ({ key: cwe, label: `${cwe} ${cweTitle(catalog, cwe)}`, value }))
  }, [findings, catalog])
  const statusRows = useMemo(() => STATUSES.map((s) => ({
    key: s, label: s, value: findings?.filter((f) => f.status === s).length ?? 0, className: `status-${s}`,
  })), [findings])

  if (error) return <ErrorBox error={error} />
  if (!scan) return <Spinner />

  const open = findings?.filter((f) => f.status === 'open') ?? []
  const blocking = open.filter((f) => f.severity >= 7).length

  return (
    <>
      <nav className="crumbs"><a href="#/">Your scans</a> / {scan.source_ref}</nav>

      <section className="card summary">
        <div className="summary-head">
          <div>
            <p className="eyebrow">Step 2 · Review the issues</p>
            <h1 className="truncate">{scan.source_ref}</h1>
            <p className="muted small">
              <span className={`pill scan-${scan.status}`}>{scan.status}</span>{' '}
              {scan.files_scanned} files · checked by {scan.detectors.join(', ') || 'no detectors'}
              {scan.finished_at && ` · ${(scan.finished_at - scan.created_at).toFixed(1)}s`}
            </p>
          </div>
          {scan.status === 'done' && (
            <div className="exports" aria-label="Download report">
              <span className="muted small">Download:</span>
              {['pdf', 'json', 'sarif'].map((k) => (
                <a key={k} className="button" href={api.exportUrl(scan.id, k)} download>{k.toUpperCase()}</a>
              ))}
            </div>
          )}
        </div>

        {scan.error && <ErrorBox error={scan.error} />}
        {!findings && scan.status !== 'failed' && <Spinner label="Scanning" />}
        {findings && (
          findings.length === 0 ? (
            <p className="verdict ok">No security issues found.</p>
          ) : (
            <>
              <p className={`verdict ${blocking ? 'bad' : 'ok'}`}>
                {open.length} open {open.length === 1 ? 'issue' : 'issues'}
                {blocking > 0 ? `, ${blocking} serious enough to block a commit (severity 7+).` : ', none serious enough to block a commit.'}
              </p>
              <SeverityChips findings={open} selected={filters.severity}
                             onSelect={(v) => setFilters({ ...filters, severity: v })} />
            </>
          )
        )}
      </section>

      {findings && findings.length > 0 && (
        <section className="card">
          <div className="section-head">
            <h2>Issues <span className="muted">({visible.length})</span></h2>
            <div className="filters-inline">
              <input type="search" placeholder="Search file or call…" value={filters.q}
                     onChange={(e) => setFilters({ ...filters, q: e.target.value })} aria-label="Search issues" />
              <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                      aria-label="Show">
                <option value="open">Open</option>
                <option value="fixed">Fixed</option>
                <option value="accepted">Accepted risk</option>
                <option value="">All</option>
              </select>
            </div>
          </div>
          <p className="muted small">Most serious first. Click an issue to see where it is and how to fix it.</p>
          {visible.length === 0 ? (
            <p className="muted">No issues match.{' '}
              <button type="button" className="link" onClick={() => setFilters(EMPTY_FILTERS)}>Show open issues</button>
            </p>
          ) : (
            <ul className="finding-list">
              {visible.map((f) => <FindingCard key={f.id} f={f} catalog={catalog} />)}
            </ul>
          )}
        </section>
      )}

      {findings && findings.length > 0 && (
        <details className="card more">
          <summary>Charts and scan details</summary>
          <div className="grid charts">
            <BarChart title="By severity" rows={severityRows(findings)} />
            <BarChart title="By weakness (CWE)" rows={cweRows} />
            <BarChart title="By status" rows={statusRows} />
          </div>
          {scan.notes.length > 0 && (
            <>
              <h3>Scan notes</h3>
              <ul className="notes-list">{scan.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
            </>
          )}
          <h3>Confidence levels</h3>
          <ul className="notes-list">
            <li><TierPill tier="reachable" /> a path from user input to the risky call was traced.</li>
            <li><TierPill tier="pattern-match" /> a risky pattern only; not shown to be reachable.</li>
          </ul>
        </details>
      )}
    </>
  )
}
