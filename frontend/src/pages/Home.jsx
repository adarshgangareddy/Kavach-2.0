import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ErrorBox, Spinner } from '../components.jsx'

const TABS = [
  { id: 'zip', label: 'Upload zip' },
  { id: 'github', label: 'GitHub URL' },
  { id: 'snippet', label: 'Paste code' },
]

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

  return (
    <section className="card">
      <h2>New scan</h2>
      <p className="muted">Python / Flask projects. Zip up to 50 MB; tests, virtualenvs and vendored code are skipped.</p>
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id}
                  className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <form onSubmit={submit} className="scan-form">
        {tab === 'zip' && (
          <label className="dropzone">
            <input type="file" accept=".zip,application/zip"
                   onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <span>{file ? `${file.name} (${(file.size / 1024).toFixed(0)} KB)` : 'Choose a .zip file'}</span>
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
          {busy ? 'Starting…' : 'Start scan'}
        </button>
      </form>
    </section>
  )
}

function ScanList() {
  const [scans, setScans] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.listScans().then(setScans).catch((e) => setError(e.message))
  }, [])

  return (
    <section className="card">
      <h2>Recent scans</h2>
      <ErrorBox error={error} />
      {scans === null && !error && <Spinner />}
      {scans?.length === 0 && <p className="muted">No scans yet.</p>}
      {scans?.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Scan</th><th>Source</th><th>Status</th><th>Files</th><th>Findings</th><th>Started</th></tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => (window.location.hash = `#/scans/${s.id}`)}>
                  <td><a href={`#/scans/${s.id}`}>{s.id}</a></td>
                  <td className="truncate" title={s.source_ref}>{s.source_kind}: {s.source_ref}</td>
                  <td><span className={`pill scan-${s.status}`}>{s.status}</span></td>
                  <td>{s.files_scanned}</td>
                  <td>
                    {s.finding_count}
                    {(s.severity_counts.critical || s.severity_counts.high) ? (
                      <span className="pill sev-high small">{(s.severity_counts.critical ?? 0) + (s.severity_counts.high ?? 0)} high+</span>
                    ) : null}
                  </td>
                  <td>{new Date(s.created_at * 1000).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default function Home() {
  return (
    <>
      <ScanForm />
      <ScanList />
    </>
  )
}
