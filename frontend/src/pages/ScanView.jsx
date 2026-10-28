import { useEffect, useMemo, useState } from 'react'
import { api, severityLabel, STATUSES } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { BarChart, ErrorBox, SeverityPill, Spinner, StatusPill, TierPill, severityRows } from '../components.jsx'

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

function Filters({ filters, setFilters, cwes }) {
  const set = (key) => (e) => setFilters({ ...filters, [key]: e.target.value })
  return (
    <div className="filters">
      <input type="search" placeholder="Search file, sink, source…" value={filters.q}
             onChange={set('q')} aria-label="Search findings" />
      <select value={filters.status} onChange={set('status')} aria-label="Status">
        <option value="">All statuses</option>
        {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      <select value={filters.cwe} onChange={set('cwe')} aria-label="CWE">
        <option value="">All CWEs</option>
        {cwes.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <label className="range">
        Min severity <strong>{Number(filters.min).toFixed(1)}</strong>
        <input type="range" min="0" max="10" step="0.5" value={filters.min} onChange={set('min')} />
      </label>
    </div>
  )
}

function applyFilters(findings, f) {
  const q = f.q.trim().toLowerCase()
  return findings.filter((x) =>
    (!f.status || x.status === f.status) &&
    (!f.cwe || x.cwe === f.cwe) &&
    (!f.severity || severityLabel(x.severity) === f.severity) &&
    x.severity >= Number(f.min) &&
    (!q || [x.file, x.sink, x.source, x.detector, x.cwe].some((v) => v?.toLowerCase().includes(q))),
  )
}

const EMPTY_FILTERS = { q: '', status: '', cwe: '', severity: '', min: 0 }

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

  return (
    <>
      <nav className="crumbs"><a href="#/">Scans</a> / {scan.id}</nav>
      <section className="card scan-head">
        <div>
          <h2>{scan.source_kind}: <span className="mono">{scan.source_ref}</span></h2>
          <p className="muted">
            <span className={`pill scan-${scan.status}`}>{scan.status}</span>{' '}
            {scan.files_scanned} files · detectors: {scan.detectors.join(', ') || 'none'}
            {scan.finished_at && ` · ${(scan.finished_at - scan.created_at).toFixed(1)}s`}
          </p>
        </div>
        {scan.status === 'done' && (
          <div className="exports">
            {['json', 'pdf', 'sarif'].map((k) => (
              <a key={k} className="button" href={api.exportUrl(scan.id, k)} download>{k.toUpperCase()}</a>
            ))}
          </div>
        )}
      </section>

      {scan.error && <ErrorBox error={scan.error} />}
      {scan.notes.length > 0 && (
        <details className="card notes" open={scan.finding_count === 0}>
          <summary>Scan notes ({scan.notes.length})</summary>
          <ul>{scan.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
        </details>
      )}
      {!findings && scan.status !== 'failed' && <Spinner label="Scanning" />}

      {findings && (
        <>
          <div className="grid charts">
            <BarChart title="By severity" rows={severityRows(findings)} selected={filters.severity}
                      onSelect={(v) => setFilters({ ...filters, severity: v })} />
            <BarChart title="By CWE" rows={cweRows} selected={filters.cwe}
                      onSelect={(v) => setFilters({ ...filters, cwe: v })} />
            <BarChart title="By status" rows={statusRows} selected={filters.status}
                      onSelect={(v) => setFilters({ ...filters, status: v })} />
          </div>

          <section className="card">
            <div className="section-head">
              <h2>Findings <span className="muted">({visible.length} of {findings.length})</span></h2>
              {JSON.stringify(filters) !== JSON.stringify(EMPTY_FILTERS) && (
                <button type="button" className="link" onClick={() => setFilters(EMPTY_FILTERS)}>Clear filters</button>
              )}
            </div>
            <Filters filters={filters} setFilters={setFilters} cwes={cweRows.map((r) => r.key)} />
            {visible.length === 0 ? (
              <p className="muted">No findings match.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Severity</th><th>Issue</th><th>Location</th><th>Confidence</th><th>Detector</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {visible.map((f) => (
                      <tr key={f.id} className="clickable" onClick={() => (window.location.hash = `#/findings/${f.id}`)}>
                        <td><SeverityPill score={f.severity} /></td>
                        <td>
                          <a href={`#/findings/${f.id}`}>{cweTitle(catalog, f.cwe)}</a>
                          <div className="muted small">{f.cwe} · {f.owasp}</div>
                        </td>
                        <td className="mono truncate" title={`${f.file}:${f.line}`}>{f.file}:{f.line}</td>
                        <td><TierPill tier={f.confidence_tier} /></td>
                        <td className="small">{f.detector}</td>
                        <td><StatusPill status={f.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  )
}
