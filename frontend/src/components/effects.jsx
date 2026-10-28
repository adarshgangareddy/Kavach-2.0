import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

/** localStorage key for the header's "Reduce effects" toggle. */
export const EFFECTS_KEY = 'kavach.reduceEffects'
const SMALL_SCREEN = '(max-width: 767px)'
const REDUCED_MOTION = '(prefers-reduced-motion: reduce)'

function readSaved() {
  try {
    return window.localStorage.getItem(EFFECTS_KEY) === '1'
  } catch {
    return false  // private mode or blocked storage: effects stay on, nothing breaks
  }
}

function save(value) {
  try {
    window.localStorage.setItem(EFFECTS_KEY, value ? '1' : '0')
  } catch {
    /* storage unavailable: the choice lasts for this visit only */
  }
}

/** True when the browser can create a WebGL context. */
export function hasWebGL() {
  try {
    const canvas = document.createElement('canvas')
    return Boolean(canvas.getContext('webgl2') || canvas.getContext('webgl'))
  } catch {
    return false
  }
}

function useMedia(query) {
  const read = () => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(query).matches : false)
  const [matches, setMatches] = useState(read)
  useEffect(() => {
    if (!window.matchMedia) return undefined
    const list = window.matchMedia(query)
    const onChange = () => setMatches(list.matches)
    onChange()
    list.addEventListener?.('change', onChange)
    return () => list.removeEventListener?.('change', onChange)
  }, [query])
  return matches
}

/** Why 3D is off, in words for the header button's tooltip; null when nothing global stops it. */
const REASONS = {
  toggle: 'You turned effects off.',
  system: 'Your system asks for reduced motion, so 3D and motion stay off.',
  webgl: 'This browser cannot draw 3D (WebGL is off or missing), so 2D views are shown.',
  slow: 'A 3D view ran under 40 frames a second, so Kavach switched to 2D to stay smooth.',
  error: 'A 3D view hit an error, so Kavach switched to 2D.',
  'webgl-lost': 'The graphics card reset, so Kavach switched to 2D.',
}

const EffectsContext = createContext(null)

/**
 * Decides, for the whole app, whether 3D and motion may run. 3D is off when the user turned
 * effects down, the system asks for reduced motion, WebGL is missing, the frame rate collapsed
 * or a 3D view crashed. Phones get 2D too, except views that opt in with allowSmall.
 */
export function EffectsProvider({ children, detectWebGL = hasWebGL }) {
  const [reduceEffects, setReduce] = useState(readSaved)
  const [webgl] = useState(() => detectWebGL())
  const [disabled, setDisabled] = useState(null)  // why 3D was switched off this visit, if it was
  const prefersReduced = useMedia(REDUCED_MOTION)
  const small = useMedia(SMALL_SCREEN)

  const setReduceEffects = useCallback((value) => {
    setReduce(value)
    save(value)
  }, [])
  const disable3D = useCallback((reason) => {
    setDisabled((current) => {
      if (!current) console.info(`Kavach: 3D switched to 2D (${reason}).`)
      return current ?? reason
    })
  }, [])
  const retry3D = useCallback(() => setDisabled(null), [])

  const motion = !reduceEffects && !prefersReduced
  useEffect(() => {
    document.documentElement.dataset.effects = motion ? 'on' : 'off'
  }, [motion])

  const offReason = reduceEffects ? 'toggle' : prefersReduced ? 'system' : !webgl ? 'webgl' : disabled
  const value = useMemo(() => ({
    reduceEffects, setReduceEffects, prefersReduced, small, webgl, disabled, disable3D, retry3D, motion,
    offReason, offMessage: offReason ? REASONS[offReason] ?? REASONS.error : null,
    allow3D: ({ allowSmall = false } = {}) => motion && webgl && !disabled && (allowSmall || !small),
  }), [reduceEffects, setReduceEffects, prefersReduced, small, webgl, disabled, disable3D, retry3D, motion, offReason])
  return <EffectsContext.Provider value={value}>{children}</EffectsContext.Provider>
}

export function useEffects() {
  const value = useContext(EffectsContext)
  if (!value) throw new Error('useEffects needs an <EffectsProvider> above it')
  return value
}
