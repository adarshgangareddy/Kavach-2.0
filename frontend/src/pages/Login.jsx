import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ErrorBox } from '../components.jsx'
import HeroBackdrop from '../components/HeroBackdrop.jsx'

const MIN_PASSWORD = 12  // must match MIN_PASSWORD in backend/app/models.py

function friendly(err) {
  return /rate limit|too many/i.test(err.message)
    ? 'Too many attempts. Wait a minute and try again.'
    : err.message
}

/** Sign in, or create an account. On success the parent stores the user. */
export default function Login({ onSignedIn }) {
  const [mode, setMode] = useState('signin')
  const [signupAllowed, setSignupAllowed] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.health().then((h) => setSignupAllowed(Boolean(h.signup))).catch(() => setSignupAllowed(false))
  }, [])

  const signup = mode === 'signup'
  const mismatch = signup && confirm.length > 0 && confirm !== password
  const tooShort = signup && password.length > 0 && password.length < MIN_PASSWORD
  const ready = email.trim() && password && (!signup || (password === confirm && !tooShort))

  function switchTo(next) {
    setMode(next)
    setError('')
    setPassword('')
    setConfirm('')
  }

  async function submit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const who = signup ? await api.register(email.trim(), password) : await api.login(email.trim(), password)
      onSignedIn(who)
    } catch (err) {
      setPassword('')
      setConfirm('')
      setError(friendly(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-stage">
      <HeroBackdrop variant="login" />
      <section className="card login-card">
        <h1>{signup ? 'Create an account' : 'Sign in'}</h1>
        <p className="muted small">
          {signup
            ? 'Your scans are private to your account. Nobody else can see them.'
            : 'Sign in to scan code and see your results. Scans are private to your account.'}
        </p>
        <form onSubmit={submit} className="login-form">
          <label>
            <span>Email</span>
            <input type="email" autoComplete={signup ? 'email' : 'username'} required value={email}
                   onChange={(e) => setEmail(e.target.value)} autoFocus />
          </label>
          <label>
            <span>Password</span>
            <input type="password" autoComplete={signup ? 'new-password' : 'current-password'} required
                   minLength={signup ? MIN_PASSWORD : undefined} value={password}
                   onChange={(e) => setPassword(e.target.value)} aria-describedby="pw-hint" />
            {signup && (
              <span id="pw-hint" className={`hint ${tooShort ? 'bad' : ''}`}>
                At least {MIN_PASSWORD} characters. A short sentence works well.
              </span>
            )}
          </label>
          {signup && (
            <label>
              <span>Confirm password</span>
              <input type="password" autoComplete="new-password" required value={confirm}
                     onChange={(e) => setConfirm(e.target.value)} />
              {mismatch && <span className="hint bad">The passwords do not match.</span>}
            </label>
          )}
          <ErrorBox error={error} />
          <button type="submit" className="primary" disabled={busy || !ready}>
            {busy ? (signup ? 'Creating account…' : 'Signing in…') : (signup ? 'Create account' : 'Sign in')}
          </button>
        </form>
        {signupAllowed && (
          <p className="muted small switch-mode">
            {signup ? 'Already have an account? ' : 'New here? '}
            <button type="button" className="link" onClick={() => switchTo(signup ? 'signin' : 'signup')}>
              {signup ? 'Sign in' : 'Create an account'}
            </button>
          </p>
        )}
      </section>
    </div>
  )
}
