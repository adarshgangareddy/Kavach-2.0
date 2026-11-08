import { createContext, useContext, useEffect, useState } from 'react'
import { api, UNAUTHORIZED_EVENT } from './api.js'
import { Spinner } from './components.jsx'
import PageTransition from './components/PageTransition.jsx'
import ReduceEffectsToggle from './components/ReduceEffectsToggle.jsx'
import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import Welcome from './pages/Welcome.jsx'
import ScanView from './pages/ScanView.jsx'
import FindingView from './pages/FindingView.jsx'
import Monitor from './pages/Monitor.jsx'

const CatalogContext = createContext({})
export const useCatalog = () => useContext(CatalogContext)

export function cweTitle(catalog, cwe) {
  return catalog[cwe]?.title ?? cwe
}

function useHashRoute() {
  const read = () => window.location.hash.replace(/^#/, '') || '/'
  const [route, setRoute] = useState(read)
  useEffect(() => {
    const onChange = () => {
      setRoute(read())
      window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}

/** undefined while checking the session, null when signed out, else {email, role}. */
function useSession() {
  const [user, setUser] = useState(undefined)
  useEffect(() => {
    api.me().then(setUser).catch(() => setUser(null))
    const signedOut = () => setUser(null)
    window.addEventListener(UNAUTHORIZED_EVENT, signedOut)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, signedOut)
  }, [])
  return [user, setUser]
}

function EngineStatusBadge() {
  const [status, setStatus] = useState(null)
  const [detectors, setDetectors] = useState([])

  useEffect(() => {
    let active = true
    Promise.all([
      api.health().catch(() => ({ status: 'offline' })),
      api.detectors().catch(() => []),
    ]).then(([h, d]) => {
      if (active) {
        setStatus(h?.status === 'ok' ? 'online' : 'offline')
        setDetectors(Array.isArray(d) ? d : [])
      }
    })
    return () => { active = false }
  }, [])

  if (!status) return null

  const isOnline = status === 'online'
  const ready = detectors.filter((d) => d.available)

  return (
    <span
      className={`badge ${isOnline ? (ready.length ? 'ok' : 'warn') : 'critical'}`}
      title={
        isOnline
          ? `Engine connected.\nReady detectors: ${ready.map((d) => d.name).join(', ') || 'None'}`
          : 'Backend engine is currently unreachable'
      }
    >
      <span className={`status-dot ${isOnline ? 'ok' : 'critical'}`} />
      {isOnline ? (ready.length ? `Engine: Connected (${ready.length})` : 'Engine: No Detectors') : 'Engine: Offline'}
    </span>
  )
}

export default function App() {
  const route = useHashRoute()
  const [user, setUser] = useSession()
  const [catalog, setCatalog] = useState({})
  useEffect(() => {
    if (user) api.cweCatalog().then(setCatalog).catch(() => {})
  }, [user])

  async function signOut() {
    await api.logout().catch(() => {})
    setUser(null)
    window.location.hash = '#/'
  }

  function signedIn(who) {
    setUser(who)
    if (route === '/login') window.location.hash = '#/'  // otherwise stay on the page they asked for
  }

  let page
  const scan = route.match(/^\/scans\/(S-[0-9a-f]{8})$/)
  const finding = route.match(/^\/findings\/(F-[0-9a-f]{8}-\d+)$/)

  if (user === undefined) {
    page = <Spinner label="Checking your session" />
  } else if (!user) {
    // Unauthenticated public experience
    page = <Welcome onSignedIn={signedIn} initialAuth={route === '/login'} />
  } else if (scan) {
    page = <ScanView scanId={scan[1]} />
  } else if (finding) {
    page = <FindingView findingId={finding[1]} />
  } else if (route === '/monitor') {
    page = <Monitor />
  } else if (route === '/welcome') {
    page = <Welcome onSignedIn={signedIn} user={user} />
  } else {
    page = <Home />
  }

  return (
    <CatalogContext.Provider value={catalog}>
      <header className="topbar">
        <a href="#/" className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none"
                  stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
            <path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" strokeWidth="2"
                  strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Kavach
        </a>
        {!user && (
          <>
            <nav className="topnav-center" aria-label="Main Navigation">
              <a href="#product" className="navlink">Product</a>
              <a href="#how-it-works" className="navlink">How it works</a>
              <a href="#privacy" className="navlink">Privacy</a>
            </nav>
            <div className="topnav-actions">
              <ReduceEffectsToggle />
              <a href="#/login" className="button small-button nav-signin-btn">Sign in</a>
            </div>
          </>
        )}
        {user && (
          <nav className="topnav">
            <a href="#/" className={route === '/' ? 'navlink active' : 'navlink'}>Scans</a>
            <a href="#/monitor" className={route === '/monitor' ? 'navlink active' : 'navlink'}>Monitoring</a>
            <EngineStatusBadge />
            <ReduceEffectsToggle />
            <span className="muted small user-email" title={`Signed in as ${user.email} (${user.role})`}>
              {user.email}
            </span>
            <button type="button" className="small-button" onClick={signOut}>Log out</button>
          </nav>
        )}
      </header>
      <main className={!user ? 'container full-welcome' : 'container'}>
        <PageTransition routeKey={route}>{page}</PageTransition>
      </main>
    </CatalogContext.Provider>
  )
}
