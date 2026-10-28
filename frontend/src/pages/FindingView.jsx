import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api.js'
import { cweTitle, useCatalog } from '../App.jsx'
import { ErrorBox, SeverityPill, Spinner, StatusPill, TierPill, plainSummary } from '../components.jsx'
import PathFlow from '../components/PathFlow.jsx'
import { chainFor } from '../components/pathLines.js'

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

/** The finding's file, fetched once and shared by the code panel and the path view. */
function useSource(scanId, file) {
  const [source, setSource] = useState({ text: null, error: '' })
  useEffect(() => {
    setSource({ text: null, error: '' })
    if (!scanId || !file) return
    api.source(scanId, file).then((text) => setSource({ text, error: '' }))
      .catch((e) => setSource({ text: null, error: e.message }))
  }, [scanId, file])
  return source
}

/** Lines around the problem (amber); `focus` is a line picked in the path view (cyan). */
function SourceView({ text, error, line, focus }) {
  if (error) return <p className="muted">Source unavailable: {error}</p>
  if (text === null) return <Spinner />
  const lines = text.split('\n')
  const centre = focus ?? line
  const start = Math.max(1, Math.min(line, centre) - CONTEXT_LINES)
  const end = Math.min(lines.length, Math.max(line, centre) + CONTEXT_LINES)
  return (
    <pre className="code" aria-label={`Lines ${start} to ${end}`}>
      {lines.slice(start - 1, end).map((content, i) => {
        const n = start + i
        const cls = [n === line ? 'hl' : '', n === focus && n !== line ? 'focus' : ''].join(' ').trim()
        return (
          <div key={n} className={cls} aria-current={n === focus ? 'true' : undefined}>
            <span className="ln">{n}</span>
            <span>{content || ' '}</span>
          </div>
        )
      })}
    </pre>
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

/** A name the snippet endpoint accepts: letters, digits, _ and -, ending in .py. */
function snippetName(file) {
  const base = file.split('/').pop().replace(/\.py$/, '').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 60)
  return `${base || 'snippet'}.py`
}

const EDITOR_LINE_PX = 20  // must match .code-editor line-height in styles.css

/** A textarea with a line-number gutter that scrolls with it; the problem line is marked. */
function NumberedEditor({ value, onChange, problemLine }) {
  const area = useRef(null)
  const gutter = useRef(null)
  const lines = value.split('\n').length

  useEffect(() => {  // open at the problem line, a few lines of context above it
    if (area.current) area.current.scrollTop = Math.max(0, problemLine - 5) * EDITOR_LINE_PX
    if (gutter.current && area.current) gutter.current.scrollTop = area.current.scrollTop
  }, [problemLine])

  return (
    <div className="code-editor">
      <div className="gutter" ref={gutter} aria-hidden="true">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} className={i + 1 === problemLine ? 'problem' : ''}>{i + 1}</div>
        ))}
      </div>
      <textarea id="fix-code" ref={area} rows={16} spellCheck={false} wrap="off" value={value}
                onChange={(e) => onChange(e.target.value)}
                onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.target.scrollTop }} />
    </div>
  )
}

/** Tools number some problems differently: Bandit calls every hard-coded secret CWE-259. */
const sameProblem = (a, b) => [a, b].every((c) => c === 'CWE-259' || c === 'CWE-798') || a === b

const CHECK_LABELS = {
  fixed: { text: 'Checked by Kavach', className: 'ok' },
  'not-traced': { text: 'Pattern removed', className: 'neutral' },
  'still-found': { text: 'Needs review', className: 'warn' },
}

/** The diff without its file header lines, each line marked as added, removed or context. */
function DiffView({ diff }) {
  const rows = diff.split('\n').filter((l) => l && !l.startsWith('---') && !l.startsWith('+++'))
  return (
    <pre className="diff" aria-label="Suggested change">
      {rows.map((l, i) => {
        const kind = l.startsWith('@@') ? 'hunk' : l[0] === '+' ? 'add' : l[0] === '-' ? 'del' : ''
        return <div key={i} className={kind}>{kind === 'hunk' ? '⋯' : l}</div>
      })}
    </pre>
  )
}

function downloadDiff(finding, diff) {
  const url = URL.createObjectURL(new Blob([diff], { type: 'text/x-diff' }))
  const link = Object.assign(document.createElement('a'), { href: url, download: `kavach-fix-${finding.id}.diff` })
  link.click()
  URL.revokeObjectURL(url)
}

/** Why there is no patch, plus links to the other issues in the same file (which may have one). */
function NoPatch({ finding, reason }) {
  const catalog = useCatalog()
  const [others, setOthers] = useState([])
  useEffect(() => {
    api.findings(finding.scan_id)
      .then((all) => setOthers(all.filter((f) => f.file === finding.file && f.id !== finding.id)))
      .catch(() => setOthers([]))
  }, [finding.scan_id, finding.file, finding.id])
  const importOnly = reason.includes('only imports a module')

  return (
    <div className="patch-box">
      <div className="patch-head">
        <strong>{importOnly ? 'Nothing to patch on an import line' : 'No automatic patch for this finding'}</strong>
      </div>
      <p className="small">{reason}{importOnly ? '' : ' Follow the advice above.'}</p>
      {importOnly && (
        <p className="small">
          Safe to leave as it is: mark it <strong>Accept the risk</strong> once the code that uses the module is fixed.
        </p>
      )}
      {others.length > 0 && (
        <>
          <p className="small"><strong>Other issues in {finding.file}</strong> (open one to see its patch):</p>
          <ul className="other-issues">
            {others.slice(0, 8).map((f) => (
              <li key={f.id}>
                <a href={`#/findings/${f.id}`}>Line {f.line}: {cweTitle(catalog, f.cwe)}</a>
                {' '}<SeverityPill score={f.severity} />
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

/** Kavach's suggested code change, checked by re-tracing the project, with a button to load it. */
function SuggestedPatch({ finding, onApply, applied }) {
  const [patch, setPatch] = useState(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    setPatch(null)
    setError('')
    api.patch(finding.id).then(setPatch).catch((e) => setError(e.message))
  }, [finding.id])

  if (error) return <p className="muted small">No suggested patch: {error}</p>
  if (patch === null) return <Spinner label="Writing a patch" />
  if (!patch.available) return <NoPatch finding={finding} reason={patch.reason} />
  const check = CHECK_LABELS[patch.verification?.status]

  async function copy() {
    await navigator.clipboard.writeText(patch.diff).catch(() => {})
    setCopied(true)
  }

  return (
    <div className="patch-box">
      <div className="patch-head">
        <strong>Suggested patch: {patch.title}</strong>
        {check && <span className={`check ${check.className}`}>{check.text}</span>}
      </div>
      <p className="small">{patch.explanation}</p>
      <DiffView diff={patch.diff} />
      {patch.verification && <p className="muted small">{patch.verification.message}</p>}
      {patch.notes.map((note) => <p key={note} className="patch-note small">Note: {note}</p>)}
      <div className="fix-actions">
        <button type="button" className="primary" disabled={applied} onClick={() => onApply(patch)}>
          {applied ? 'Patch applied below' : 'Apply patch to the editor'}
        </button>
        <button type="button" onClick={copy}>{copied ? 'Copied' : 'Copy patch'}</button>
        <button type="button" onClick={() => downloadDiff(finding, patch.diff)}>Download .diff</button>
      </div>
    </div>
  )
}

/** Edit the file in place and re-scan it, then say whether this kind of issue is gone. */
function FixEditor({ finding, onFixed, saving }) {
  const catalog = useCatalog()
  const [code, setCode] = useState(null)
  const [original, setOriginal] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [suggestion, setSuggestion] = useState(null)  // the applied patch, while the editor still holds it

  useEffect(() => {
    setResult(null)
    setSuggestion(null)
    api.source(finding.scan_id, finding.file)
      .then((text) => { setCode(text); setOriginal(text) })
      .catch((e) => setError(`Could not load the file: ${e.message}`))
  }, [finding.scan_id, finding.file])

  async function rescan() {
    setBusy(true)
    setError('')
    try {
      setResult(await api.snippet(code, snippetName(finding.file)))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (code === null) return error ? <ErrorBox error={error} /> : <Spinner label="Loading the file" />
  const applied = suggestion !== null && code === suggestion.patched_source
  // With the patch applied unchanged, judge the lines it changed; after hand edits, the whole file.
  const inFile = result?.findings.filter((f) => sameProblem(f.cwe, finding.cwe)) ?? []
  const same = applied ? inFile.filter((f) => suggestion.changed_lines.includes(f.line)) : inFile
  const elsewhere = inFile.length - same.length
  const serious = same.filter((f) => f.severity >= 7)
  const kind = cweTitle(catalog, finding.cwe)

  return (
    <div className="fix-editor">
      <SuggestedPatch finding={finding} applied={applied}
                      onApply={(patch) => { setSuggestion(patch); setCode(patch.patched_source); setResult(null) }} />
      <label className="muted small" htmlFor="fix-code">
        {finding.file}, editable copy (line {finding.line} is the problem)
      </label>
      <NumberedEditor value={code} problemLine={finding.line}
                      onChange={(text) => { setCode(text); setResult(null) }} />
      <div className="fix-actions">
        <button type="button" className="primary" disabled={busy || !code.trim()} onClick={rescan}>
          {busy ? 'Re-scanning…' : 'Re-scan my changes'}
        </button>
        {code !== original && (
          <button type="button" onClick={() => { setCode(original); setResult(null) }}>Undo my edits</button>
        )}
      </div>
      <ErrorBox error={error} />
      {result && (
        <div className={`rescan ${same.length === 0 ? 'ok' : serious.length ? 'bad' : 'warn'}`} role="status">
          {same.length === 0 && (
            <strong>
              {applied ? `Fixed: this ${kind} issue is gone.` : `Fixed: no ${kind} issues left in this file.`}
              {elsewhere > 0 && ` ${elsewhere} other ${kind} ${elsewhere === 1 ? 'issue' : 'issues'} elsewhere in this file still need fixing.`}
            </strong>
          )}
          {same.length > 0 && serious.length === 0 && (
            <strong>Better: {same.length} {kind} {same.length === 1 ? 'finding remains' : 'findings remain'}, none serious enough to block a commit.</strong>
          )}
          {serious.length > 0 && (
            <strong>Not fixed yet: {serious.length} serious {kind} {serious.length === 1 ? 'issue' : 'issues'} still found.</strong>
          )}
          <span>
            {' '}<a href={`#/scans/${result.scan.id}`}>See all {result.findings.length} results of the re-scan</a>
            {serious.length === 0 && finding.status !== 'fixed' && (
              <> · <button type="button" className="link" disabled={saving} onClick={onFixed}>Mark this issue fixed</button></>
            )}
          </span>
        </div>
      )}
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
  const source = useSource(finding?.scan_id, finding?.file)
  const [step, setStep] = useState(null)  // the path step picked in the path view
  const codePanel = useRef(null)
  const chain = useMemo(() => (finding ? chainFor(finding, source.text) : []), [finding, source.text])

  function pickStep(i) {
    setStep(i)
    codePanel.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }

  useEffect(() => {
    setFinding(null)
    setStep(null)
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
          <li>
            Apply Kavach's suggested patch, or edit the code below yourself. The problem is on{' '}
            <strong>line {finding.line}</strong> of <span className="mono">{finding.file}</span>.
          </li>
          <li>Click <strong>Re-scan my changes</strong> to check the fix.</li>
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
        <FixEditor finding={finding} onFixed={() => changeStatus('fixed')} saving={saving} />
        <p className="muted small">
          Patches and advice are suggestions: review them before use. Edits here are only re-scanned; copy
          the fixed code back into your own file, or run <span className="mono">git apply</span> on the
          downloaded .diff from your project folder.
        </p>
      </section>

      <div className="grid two">
        <section className="card" ref={codePanel}>
          <h2>Where in the code</h2>
          <SourceView text={source.text} error={source.error} line={finding.line} focus={chain[step]?.line ?? null} />
        </section>
        <section className="card">
          <h2>How the data gets there</h2>
          <PathFlow chain={chain} selected={step} onSelect={pickStep} />
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
