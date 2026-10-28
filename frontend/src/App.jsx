import { createContext, useContext, useEffect, useState } from 'react'
import { api } from './api.js'
import Home from './pages/Home.jsx'
import ScanView from './pages/ScanView.jsx'
import FindingView from './pages/FindingView.jsx'

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

function DetectorBadge() {
  const [detectors, setDetectors] = useState(null)
  useEffect(() => {
    api.detectors().then(setDetectors).catch(() => setDetectors([]))
  }, [])
  if (detectors === null) return null
  const ready = detectors.filter((d) => d.available)
  return (
    <span className={`badge ${ready.length ? 'ok' : 'warn'}`}
          title={detectors.map((d) => `${d.name}: ${d.available ? 'ready' : 'not installed'}`).join('\n')}>
      {ready.length ? `Detectors: ${ready.map((d) => d.name).join(', ')}` : 'No detectors installed'}
    </span>
  )
}

export default function App() {
  const route = useHashRoute()
  const [catalog, setCatalog] = useState({})
  useEffect(() => {
    api.cweCatalog().then(setCatalog).catch(() => {})
  }, [])

  let page
  const scan = route.match(/^\/scans\/(S-[0-9a-f]{8})$/)
  const finding = route.match(/^\/findings\/(F-[0-9a-f]{8}-\d+)$/)
  if (scan) page = <ScanView scanId={scan[1]} />
  else if (finding) page = <FindingView findingId={finding[1]} />
  else page = <Home />

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
          ZeroDay Sentinel
        </a>
        <nav className="topnav">
          <a href="#/" className="button primary small-button">+ New scan</a>
          <DetectorBadge />
        </nav>
      </header>
      <main className="container">{page}</main>
    </CatalogContext.Provider>
  )
}
