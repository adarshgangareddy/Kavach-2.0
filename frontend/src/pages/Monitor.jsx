import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ConfirmDelete, ErrorBox, Spinner } from '../components.jsx'

const POLL_MS = 5000
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : 'never')
const CATEGORY = { sql_injection: 'SQL injection', path_traversal: 'Path traversal' }

function setupCode(key) {
  return `from kavach_telemetry import init_kavach_telemetry

init_kavach_telemetry(app,
                      kavach_url="${window.location.origin}/api",
                      app_key="${key}")`
}

/** Shown once, right after registering: Kavach keeps only a hash of the key. */
function NewKey({ created, onDone }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(setupCode(created.key)).catch(() => {})
    setCopied(true)
  }
  return (
    <div className="notice">
      <p><strong>{created.name}</strong> is registered. Copy this now: the key is shown only once.</p>
      <pre className="code-block">{setupCode(created.key)}</pre>
      <p className="muted small">
        Put <code>telemetry/kavach_telemetry.py</code> in your Flask project, then add these lines after
        creating <code>app</code>. Keep the key out of git, for example in an environment variable.
      </p>
      <div className="row">
        <button type="button" className="primary" onClick={copy}>{copied ? 'Copied' : 'Copy code'}</button>
        <button type="button" onClick={onDone}>Done</button>
      </div>
    </div>
  )
}

function Apps({ apps, onChange }) {
  const [name, setName] = useState('')
  const [created, setCreated] = useState(null)
  const [error, setError] = useState(null)

  async function register(event) {
    event.preventDefault()
    setError(null)
    try {
      setCreated(await api.createApp(name))
      setName('')
      onChange()
    } catch (e) {
      setError(e)
    }
  }

  async function remove(app) {
    await api.deleteApp(app.id)
    onChange()
  }

  return (
    <section className="card">
      <h2>Monitored apps</h2>
      <p className="muted small">Register a Flask app to get a key. The app then reports suspicious requests here.</p>
      <ErrorBox error={error} />
      {created ? <NewKey created={created} onDone={() => setCreated(null)} /> : (
        <form onSubmit={register} className="row">
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="App name, e.g. shop-api"
                 maxLength={80} aria-label="App name" />
          <button type="submit" className="primary" disabled={!name.trim()}>Register app</button>
        </form>
      )}
      {apps?.length > 0 && (
        <ul className="scan-list">
          {apps.map((a) => (
            <li key={a.id} className="scan-item">
              <span className="scan-row">
                <span className="scan-name">
                  <strong className="truncate">{a.name}</strong>
                  <span className="muted small">last alert: {when(a.last_seen)}</span>
                </span>
                <span className="pill status-open">{a.alert_count} alerts</span>
              </span>
              <span className="delete-scan">
                <ConfirmDelete question="Remove this app and its alerts? Its key stops working."
                               onConfirm={() => remove(a)} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function Alerts({ alerts, onClear }) {
  return (
    <section className="card">
      <div className="row spread">
        <h2>Alerts</h2>
        {alerts?.length > 0 && <ConfirmDelete label="Clear all" question="Clear every alert?" onConfirm={onClear} />}
      </div>
      <p className="muted small">Updates every few seconds.</p>
      {alerts === null && <Spinner />}
      {alerts?.length === 0 && <p className="muted">No alerts yet.</p>}
      {alerts?.length > 0 && (
        <table className="alerts-table">
          <thead>
            <tr><th>When</th><th>App</th><th>Reason</th><th>Request</th><th>Input</th><th>From</th></tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>{when(a.received_at)}</td>
                <td>{a.app}</td>
                <td>
                  <span className={`pill ${a.category ? 'sev-critical' : 'sev-high'}`}>
                    {a.category ? CATEGORY[a.category] : a.reason}
                  </span>
                  {a.category && <div className="muted small">{a.reason.replace(/^.*pattern: /, '')}</div>}
                </td>
                <td><code>{a.method} {a.endpoint}</code>
                  {a.size_bytes != null && <span className="muted small"> · {(a.size_bytes / 1048576).toFixed(1)} MB</span>}
                </td>
                <td>
                  {a.field ? <><span className="muted small">{a.field}</span><br /><code className="sample">{a.sample}</code></> : '—'}
                </td>
                <td>{a.client_ip ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

export default function Monitor() {
  const [apps, setApps] = useState(null)
  const [alerts, setAlerts] = useState(null)
  const [error, setError] = useState(null)

  const refresh = () =>
    Promise.all([api.listApps(), api.listAlerts()])
      .then(([a, b]) => { setApps(a); setAlerts(b); setError(null) })
      .catch(setError)

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [])

  async function clear() {
    await api.clearAlerts()
    refresh()
  }

  return (
    <>
      <section className="hero">
        <h1>Monitoring</h1>
        <p className="muted">
          Live alerts from your running Flask apps: SQL injection and path traversal attempts, and oversized requests.
        </p>
      </section>
      <ErrorBox error={error} />
      <Alerts alerts={alerts} onClear={clear} />
      <Apps apps={apps} onChange={refresh} />
    </>
  )
}
