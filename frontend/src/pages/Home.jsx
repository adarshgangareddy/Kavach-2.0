import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ConfirmDelete, ErrorBox, Spinner } from '../components.jsx'
import Tilt from '../components/Tilt.jsx'

const TABS = [
  { id: 'snippet', label: 'Paste code (Local scan)' },
  { id: 'zip', label: 'Upload archive (.zip)' },
  { id: 'github', label: 'GitHub repository link' },
]

const WORKFLOW_STEPS = [
  {
    n: 1,
    title: 'Register or open project',
    text: 'Register a local project for monitoring or select source files to scan directly.',
  },
  {
    n: 2,
    title: 'Run security scan',
    text: 'Deterministic AST taint tracking inspects user inputs through helper functions to dangerous sinks.',
  },
  {
    n: 3,
    title: 'Review findings & patches',
    text: 'Inspect identified candidate sinks, review reachability, and apply syntax-safe code fixes.',
  },
]

function WorkflowSteps() {
  return (
    <ol className="steps workflow-steps-grid" aria-label="Kavach scan workflow">
      {WORKFLOW_STEPS.map((s) => (
        <Tilt as="li" key={s.n} className="workflow-step-card">
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

function RegisteredProjects() {
  const [apps, setApps] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [registering, setRegistering] = useState(false)
  const [projectName, setProjectName] = useState('')
  const [createdKey, setCreatedKey] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    loadProjects()
  }, [])

  async function loadProjects() {
    setLoading(true)
    setError('')
    try {
      const list = await api.listApps()
      setApps(list || [])
    } catch (err) {
      setError(err.message || 'Failed to load registered projects')
    } finally {
      setLoading(false)
    }
  }

  async function handleCreateProject(e) {
    e.preventDefault()
    if (!projectName.trim()) return
    setBusy(true)
    setError('')
    try {
      const res = await api.createApp(projectName.trim())
      setCreatedKey(res.app_key || res.key || 'registered')
      setProjectName('')
      await loadProjects()
    } catch (err) {
      setError(err.message || 'Could not register project')
    } finally {
      setBusy(false)
    }
  }

  async function handleDeleteProject(id) {
    try {
      await api.deleteApp(id)
      setApps((prev) => (prev ? prev.filter((a) => a.id !== id) : []))
    } catch (err) {
      setError(err.message || 'Could not remove project')
    }
  }

  return (
    <section className="card project-registry-card">
      <div className="section-head">
        <div>
          <h2>Registered Projects</h2>
          <p className="muted small">
            Monitored applications configured for telemetry and vulnerability alerts.
          </p>
        </div>
        {!registering && (
          <button
            type="button"
            className="button small-button primary"
            onClick={() => { setRegistering(true); setCreatedKey(null); }}
          >
            + Register project
          </button>
        )}
      </div>

      <ErrorBox error={error} />

      {registering && (
        <form onSubmit={handleCreateProject} className="project-register-form">
          <label>
            <span className="small">Project name</span>
            <input
              type="text"
              placeholder="e.g. customer-api"
              required
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              autoFocus
            />
          </label>
          <div className="form-action-row">
            <button type="submit" className="button primary small-button" disabled={busy || !projectName.trim()}>
              {busy ? 'Registering…' : 'Save project'}
            </button>
            <button
              type="button"
              className="button small-button"
              onClick={() => { setRegistering(false); setCreatedKey(null); }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {createdKey && (
        <div className="app-key-banner">
          <div className="app-key-head">
            <strong>Project Registered! Telemetry Key:</strong>
            <span className="muted small">Copy this key now; it is stored as a hash and not shown again.</span>
          </div>
          <code className="app-key-code mono">{createdKey}</code>
        </div>
      )}

      {loading && <Spinner label="Loading projects…" />}

      {!loading && apps && apps.length === 0 && (
        <div className="empty-state-box">
          <p className="muted small">
            No projects registered yet. Register a local project above or run an immediate scan below.
          </p>
        </div>
      )}

      {!loading && apps && apps.length > 0 && (
        <ul className="project-list" aria-label="Registered projects">
          {apps.map((app) => (
            <li key={app.id} className="project-item">
              <div className="project-item-info">
                <strong>{app.name}</strong>
                <span className="muted small mono">ID: {app.id}</span>
                {app.created_at && (
                  <span className="muted small">
                    Registered {new Date(app.created_at * 1000).toLocaleDateString()}
                  </span>
                )}
              </div>
              <div className="project-item-actions">
                <ConfirmDelete
                  question={`Remove project "${app.name}" and its alert bindings?`}
                  onConfirm={() => handleDeleteProject(app.id)}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ScanForm() {
  const [tab, setTab] = useState('snippet')
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
      if (tab === 'zip') {
        scan = await api.uploadZip(file)
      } else if (tab === 'github') {
        scan = await api.scanGithub(url.trim())
      } else {
        scan = (await api.snippet(code)).scan
      }
      window.location.hash = `#/scans/${scan.id}`
    } catch (err) {
      setError(err.message || 'Scan request failed')
    } finally {
      setBusy(false)
    }
  }

  const ready =
    (tab === 'zip' && file) ||
    (tab === 'github' && url.trim()) ||
    (tab === 'snippet' && code.trim())

  const hint = {
    snippet: 'Paste a route or helper function. The AST tracer will detect untrusted source-to-sink flows.',
    zip: 'A .zip archive of a Python project (up to 50 MB). Tests, venvs, and vendored libraries are filtered.',
    github: 'A public GitHub repository (e.g. https://github.com/owner/repo) for shallow cloning and analysis.',
  }[tab]

  return (
    <section className="card scan-workspace-card">
      <div className="section-head">
        <div>
          <h2>Start a Security Scan</h2>
          <p className="muted small">
            Execute AST taint analysis and custom rule checks across your codebase.
          </p>
        </div>
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? 'active' : ''}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="scan-form">
        <p className="muted small">{hint}</p>

        {tab === 'snippet' && (
          <textarea
            rows={10}
            spellCheck={false}
            placeholder={`@app.route("/export")\ndef export_data():\n    filename = request.args.get("file")\n    return open(filename, "rb").read()`}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            aria-label="Code snippet"
          />
        )}

        {tab === 'zip' && (
          <label className="dropzone">
            <input
              type="file"
              accept=".zip,application/zip"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            <span>
              {file
                ? `${file.name} (${(file.size / 1024).toFixed(0)} KB)`
                : 'Click or drop a .zip project archive'}
            </span>
          </label>
        )}

        {tab === 'github' && (
          <input
            type="url"
            placeholder="https://github.com/owner/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            aria-label="GitHub repository URL"
          />
        )}

        <ErrorBox error={error} />

        <button type="submit" className="button primary" disabled={!ready || busy}>
          {busy ? 'Analyzing code…' : 'Scan for security issues'}
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
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadScans()
  }, [])

  async function loadScans() {
    setLoading(true)
    setError('')
    try {
      const list = await api.listScans()
      setScans(list || [])
    } catch (e) {
      setError(e.message || 'Failed to load scans')
    } finally {
      setLoading(false)
    }
  }

  async function remove(scan) {
    try {
      await api.deleteScan(scan.id)
      setScans((all) => all.filter((s) => s.id !== scan.id))
    } catch (err) {
      setError(err.message || 'Failed to delete scan')
    }
  }

  return (
    <section className="card scan-history-card">
      <div className="section-head">
        <div>
          <h2>Recent Scans</h2>
          <p className="muted small">
            Stored scan results and findings scoped to your account.
          </p>
        </div>
      </div>

      <ErrorBox error={error} />

      {loading && <Spinner label="Loading scan history…" />}

      {!loading && scans && scans.length === 0 && (
        <div className="empty-state-box">
          <p className="muted small">No scans yet. Start a scan above to analyze your code.</p>
        </div>
      )}

      {!loading && scans && scans.length > 0 && (
        <ul className="scan-list" aria-label="Scan history">
          {scans.map((s) => (
            <Tilt as="li" key={s.id} className="scan-item">
              <a href={`#/scans/${s.id}`} className="scan-row">
                <span className="scan-name">
                  <strong className="truncate">{s.source_ref}</strong>
                  <span className="muted small">
                    {s.source_kind} · {s.files_scanned} files ·{' '}
                    {new Date(s.created_at * 1000).toLocaleString()}
                  </span>
                </span>
                {countBadge(s)}
                <span className="chev" aria-hidden="true">
                  ›
                </span>
              </a>
              <span className="delete-scan">
                <ConfirmDelete
                  question="Delete this scan and its results?"
                  disabled={s.status === 'running' || s.status === 'queued'}
                  onConfirm={() => remove(s)}
                />
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
    <div className="signed-in-home">
      <section className="hero signed-in-hero">
        <div className="hero-head-block">
          <div className="hero-pill-tag">
            <span className="hero-pill-dot" />
            <span>Developer Workspace · AST Taint Engine</span>
          </div>
          <h1>Projects & Security Scans</h1>
          <p className="muted">
            Kavach statically follows untrusted user input across helper functions to detect Command Injection,
            SQL Injection, and Path Traversal, providing syntax-verified AST patch diffs.
          </p>
        </div>

        <WorkflowSteps />
      </section>

      {/* Phase 2 Local Project Registration & Tracking */}
      <RegisteredProjects />

      {/* Real Scan Workspace */}
      <ScanForm />

      {/* Scans List */}
      <ScanList />
    </div>
  )
}
