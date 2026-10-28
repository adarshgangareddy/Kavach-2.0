import { useEffect, useMemo, useState } from 'react'
import { api, severityLabel, SEVERITY_ORDER, STATUSES } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { BarChart, ConfirmDelete, ErrorBox, SeverityPill, Spinner, StatusPill, TierPill, plainSummary, severityRows } from '../components.jsx'

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

const EMPTY_FILTERS = { q: '', status: 'open', severity: '', found: '' }
const BASELINES = ['bandit', 'semgrep']

/** Which tools reported a finding. Merged findings list every detector, e.g. "bandit+taint-wrapper". */
function foundBy(f) {
  const parts = f.detector.split('+')
  return {
    kavach: parts.some((d) => d.startsWith('taint')),
    bandit: parts.includes('bandit'),
    semgrep: parts.includes('semgrep'),
  }
}

/** 'kavach-only' | 'both' | 'others-only' */
function foundGroup(f) {
  const by = foundBy(f)
  const others = by.bandit || by.semgrep
  if (by.kavach && !others) return 'kavach-only'
  return by.kavach ? 'both' : 'others-only'
}

function applyFilters(findings, f) {
  const q = f.q.trim().toLowerCase()
  return findings.filter((x) =>
    (!f.status || x.status === f.status) &&
    (!f.severity || severityLabel(x.severity) === f.severity) &&
    (!f.found || foundGroup(x) === f.found) &&
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

const GROUPS = [
  { id: 'kavach-only', title: 'Only Kavach found', note: 'missed by the pattern tools', accent: true },
  { id: 'both', title: 'Kavach and others', note: 'found by more than one tool' },
  { id: 'others-only', title: 'Only Bandit or Semgrep', note: 'risky patterns, no traced path' },
]

/** Head-to-head on this scan: what Kavach found that the baseline tools did not. */
function ToolComparison({ scan, findings, selected, onSelect }) {
  const ran = BASELINES.filter((b) => scan.detectors.includes(b))
  if (!scan.detectors.includes('taint') || ran.length === 0 || findings.length === 0) return null
  const counts = { 'kavach-only': 0, both: 0, 'others-only': 0 }
  const perTool = { kavach: 0, bandit: 0, semgrep: 0 }
  findings.forEach((f) => {
    counts[foundGroup(f)]++
    const by = foundBy(f)
    Object.keys(perTool).forEach((t) => { if (by[t]) perTool[t]++ })
  })
  const others = ran.map((b) => b[0].toUpperCase() + b.slice(1)).join(' and ')
  return (
    <div className="compare" aria-label="Kavach compared with other tools on this scan">
      <p className="compare-lead">
        {counts['kavach-only'] > 0
          ? <><strong>{counts['kavach-only']}</strong> {counts['kavach-only'] === 1 ? 'issue' : 'issues'} found only by Kavach, missed by {others}.</>
          : <>Kavach found nothing extra on this scan; every issue was also found by {others}.</>}
      </p>
      <div className="compare-groups" role="group" aria-label="Filter by which tools found an issue">
        {GROUPS.map((g) => (
          <button key={g.id} type="button" aria-pressed={selected === g.id} disabled={!counts[g.id]}
                  className={`compare-group ${g.accent ? 'accent' : ''} ${selected === g.id ? 'on' : ''}`}
                  onClick={() => onSelect(selected === g.id ? '' : g.id)}>
            <span className="compare-count">{counts[g.id]}</span>
            <span className="compare-title">{g.title}</span>
            <span className="muted small">{g.note}</span>
          </button>
        ))}
      </div>
      <p className="muted small">
        Issues each tool reported here: Kavach {perTool.kavach}
        {ran.map((b) => ` · ${b[0].toUpperCase() + b.slice(1)} ${perTool[b]}`).join('')}.
        Click a group to show just those issues.
      </p>
    </div>
  )
}

function FindingCard({ f, catalog }) {
  return (
    <li>
      <a href={`#/findings/${f.id}`} className="finding-card">
        <SeverityPill score={f.severity} />
        <span className="finding-main">
          <strong>
            {cweTitle(catalog, f.cwe)}
            {foundGroup(f) === 'kavach-only' && <span className="pill only-kavach">Only Kavach</span>}
          </strong>
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

function DeleteScanButton({ scan }) {
  return (
    <ConfirmDelete label="Delete scan" question="Delete this scan, its findings and stored code?"
                   onConfirm={async () => { await api.deleteScan(scan.id); window.location.hash = '#/' }} />
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
              <DeleteScanButton scan={scan} />
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
              <ToolComparison scan={scan} findings={findings} selected={filters.found}
                              onSelect={(v) => setFilters({ ...filters, found: v, status: v ? '' : filters.status })} />
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
