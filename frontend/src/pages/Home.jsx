import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ConfirmDelete, ErrorBox, Spinner } from '../components.jsx'
import HeroBackdrop from '../components/HeroBackdrop.jsx'
import Tilt from '../components/Tilt.jsx'

const TABS = [
  { id: 'zip', label: 'Upload a zip' },
  { id: 'github', label: 'GitHub link' },
  { id: 'snippet', label: 'Paste code' },
]

const STEPS = [
  { n: 1, title: 'Add your code', text: 'Upload a zip, paste a GitHub link, or paste one function.' },
  { n: 2, title: 'Review the issues', text: 'Most serious first, each with where it is and why it matters.' },
  { n: 3, title: 'Fix and re-check', text: 'Follow the fix advice, scan again, and mark the issue fixed.' },
]

function Steps() {
  return (
    <ol className="steps" aria-label="How it works">
      {STEPS.map((s) => (
        <Tilt as="li" key={s.n}>
          <span className="step-n">{s.n}</span>
          <div>
            <strong>{s.title}</strong>
            <p className="muted small">{s.text}</p>
          </div>
        </Tilt>
      ))}
    </ol>
  )
}

function ScanForm() {
  const [tab, setTab] = useState('zip')
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      let scan
      if (tab === 'zip') scan = await api.uploadZip(file)
      else if (tab === 'github') scan = await api.scanGithub(url.trim())
      else scan = (await api.snippet(code)).scan
      window.location.hash = `#/scans/${scan.id}`
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const ready = (tab === 'zip' && file) || (tab === 'github' && url.trim()) || (tab === 'snippet' && code.trim())
  const hint = {
    zip: 'A .zip of a Python / Flask project, up to 50 MB. Tests, virtualenvs and vendored code are skipped.',
    github: 'A public repository, e.g. https://github.com/owner/repo.',
    snippet: 'One route or function. Good for checking a fix quickly.',
  }[tab]

  return (
    <section className="card">
      <h2>Step 1 · Add your code</h2>
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id}
                  className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <form onSubmit={submit} className="scan-form">
        <p className="muted small">{hint}</p>
        {tab === 'zip' && (
          <label className="dropzone">
            <input type="file" accept=".zip,application/zip"
                   onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <span>{file ? `${file.name} (${(file.size / 1024).toFixed(0)} KB)` : 'Click to choose a .zip file'}</span>
          </label>
        )}
        {tab === 'github' && (
          <input type="url" placeholder="https://github.com/owner/repo" value={url}
                 onChange={(e) => setUrl(e.target.value)} aria-label="GitHub repository URL" />
        )}
        {tab === 'snippet' && (
          <textarea rows={10} spellCheck={false} placeholder="Paste a Flask route or function…"
                    value={code} onChange={(e) => setCode(e.target.value)} aria-label="Code snippet" />
        )}
        <ErrorBox error={error} />
        <button type="submit" className="primary" disabled={!ready || busy}>
          {busy ? 'Scanning…' : 'Scan for security issues'}
        </button>
      </form>
    </section>
  )
}

function countBadge(s) {
  const serious = (s.severity_counts.critical ?? 0) + (s.severity_counts.high ?? 0)
  if (s.status !== 'done') return <span className={`pill scan-${s.status}`}>{s.status}</span>
  if (s.finding_count === 0) return <span className="pill status-fixed">no issues</span>
  return (
    <span className="pills">
      <span className="pill status-open">{s.finding_count} issues</span>
      {serious > 0 && <span className="pill sev-high">{serious} serious</span>}
    </span>
  )
}

function ScanList() {
  const [scans, setScans] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.listScans().then(setScans).catch((e) => setError(e.message))
  }, [])

  async function remove(scan) {
    await api.deleteScan(scan.id)  // errors are shown by ConfirmDelete
    setScans((all) => all.filter((s) => s.id !== scan.id))
  }

  return (
    <section className="card">
      <h2>Your scans</h2>
      <ErrorBox error={error} />
      {scans === null && !error && <Spinner />}
      {scans?.length === 0 && <p className="muted">No scans yet. Add some code above to start.</p>}
      {scans?.length > 0 && (
        <ul className="scan-list">
          {scans.map((s) => (
            <Tilt as="li" key={s.id} className="scan-item">
              <a href={`#/scans/${s.id}`} className="scan-row">
                <span className="scan-name">
                  <strong className="truncate">{s.source_ref}</strong>
                  <span className="muted small">
                    {s.source_kind} · {s.files_scanned} files · {new Date(s.created_at * 1000).toLocaleString()}
                  </span>
                </span>
                {countBadge(s)}
                <span className="chev" aria-hidden="true">›</span>
              </a>
              <span className="delete-scan">
                <ConfirmDelete question="Delete this scan and its results?"
                               disabled={s.status === 'running' || s.status === 'queued'}
                               onConfirm={() => remove(s)} />
              </span>
            </Tilt>
          ))}
        </ul>
      )}
    </section>
  )
}

export default function Home() {
  return (
    <>
      <section className="hero">
        <HeroBackdrop variant="home" />
        <h1>Find security bugs in your Flask app</h1>
        <p className="muted">
          Kavach follows user input through your code, including your own helper functions,
          and shows where it reaches something dangerous.
        </p>
        <Steps />
      </section>
      <ScanForm />
      <ScanList />
    </>
  )
}
