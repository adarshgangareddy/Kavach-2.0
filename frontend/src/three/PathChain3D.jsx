import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import { useEffects } from '../components/effects.jsx'
import { useFpsGuard } from './useFpsGuard.js'
import WakeOnChange from './WakeOnChange.jsx'

const COLOR = { source: '#22D3EE', function: '#CBD5E1', sink: '#F43F5E' }
const GAP = 1.7         // distance between steps
const HOP = 0.75        // seconds for the data to move one step
const PULSE = 1.0       // seconds the sink pulses at the end
const LABEL_CHARS = 22

const short = (label) => (label.length > LABEL_CHARS ? `${label.slice(0, LABEL_CHARS - 1)}…` : label)

/** Steps left to right on a gentle wave, so the chain reads in order but still has depth. */
function positionsFor(count) {
  return Array.from({ length: count }, (_, i) => new THREE.Vector3(
    (i - (count - 1) / 2) * GAP, Math.sin(i * 1.3) * 0.35, Math.cos(i * 1.1) * 0.45))
}

/** Keeps each HTML label on top of its node, wherever the camera puts it. */
function useLabels(points, labels) {
  const v = useMemo(() => new THREE.Vector3(), [])
  useFrame(({ camera, size }) => {
    points.forEach((p, i) => {
      const el = labels.current[i]
      if (!el) return
      v.copy(p).project(camera)
      const below = i % 2 === 0  // alternate below / above the node so neighbours never overlap
      el.style.transform = `translate(-50%, ${below ? '0' : '-100%'}) translate(${(v.x * 0.5 + 0.5) * size.width}px, ${(-v.y * 0.5 + 0.5) * size.height + (below ? 18 : -18)}px)`
    })
  })
}

/** Moves the camera so the whole chain, plus room for labels, fills the box at any size. */
function FitCamera({ count }) {
  const { camera, size, invalidate } = useThree()
  useEffect(() => {
    const half = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2))
    const byWidth = ((count - 1) * GAP + 2.6) / (2 * half * (size.width / size.height))
    const byHeight = 2.6 / (2 * half)
    camera.position.set(0, 0.5, Math.max(byWidth, byHeight))
    camera.lookAt(0, 0, 0)
    camera.updateProjectionMatrix()
    invalidate()
  }, [camera, size.width, size.height, count, invalidate])
  return null
}

function Chain({ chain, points, selected, onSelect, playing, onPlayed, labels, onSlow }) {
  useFpsGuard(onSlow, { enabled: playing })
  useLabels(points, labels)
  const group = useRef()
  const particle = useRef()
  const sinkHalo = useRef()
  const nodes = useRef([])
  const time = useRef(0)
  const lines = useMemo(() => {
    const geometry = new THREE.BufferGeometry().setFromPoints(points.flatMap((p, i) => (i ? [points[i - 1], p] : [])))
    return geometry
  }, [points])
  useEffect(() => () => lines.dispose(), [lines])
  useEffect(() => { time.current = 0 }, [playing])

  const total = (points.length - 1) * HOP + PULSE
  useFrame((state, delta) => {
    group.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.3) * (playing ? 0.12 : 0)
    if (!playing) {
      particle.current.visible = false
      sinkHalo.current.scale.setScalar(1.6)
      nodes.current.forEach((m, i) => m && m.scale.setScalar(i === selected ? 1.45 : 1))
      return
    }
    time.current = Math.min(total, time.current + Math.min(delta, 0.1))
    const travel = Math.min(1, time.current / ((points.length - 1) * HOP)) * (points.length - 1)
    const i = Math.min(points.length - 2, Math.floor(travel))
    particle.current.visible = travel < points.length - 1
    particle.current.position.lerpVectors(points[i], points[i + 1], travel - i)
    nodes.current.forEach((m, k) => m && m.scale.setScalar(k <= travel ? 1.3 : 0.85))  // steps light up as data passes
    const since = time.current - (points.length - 1) * HOP
    sinkHalo.current.scale.setScalar(since > 0 ? 1.6 + 3 * (1 - since / PULSE) : 1.6)
    if (time.current >= total) onPlayed()
  })

  return (
    <group ref={group}>
      {chain.map((step, i) => (
        <mesh key={i} ref={(m) => { nodes.current[i] = m }} position={points[i]}
              onClick={(e) => { e.stopPropagation(); onSelect(i) }}
              onPointerOver={() => { document.body.style.cursor = 'pointer' }}
              onPointerOut={() => { document.body.style.cursor = '' }}>
          <sphereGeometry args={[step.kind === 'function' ? 0.16 : 0.2, 24, 24]} />
          <meshBasicMaterial color={COLOR[step.kind]} toneMapped={false} />
        </mesh>
      ))}
      {selected != null && (
        <mesh position={points[selected]}>
          <ringGeometry args={[0.3, 0.36, 40]} />
          <meshBasicMaterial color="#22D3EE" side={THREE.DoubleSide} toneMapped={false} />
        </mesh>
      )}
      <mesh ref={sinkHalo} position={points.at(-1)}>
        <sphereGeometry args={[0.2, 24, 24]} />
        <meshBasicMaterial color={COLOR.sink} transparent opacity={0.18} depthWrite={false}
                           blending={THREE.AdditiveBlending} toneMapped={false} />
      </mesh>
      <mesh ref={particle} visible={false}>
        <sphereGeometry args={[0.09, 16, 16]} />
        <meshBasicMaterial color="#E0FBFF" toneMapped={false} />
      </mesh>
      <lineSegments geometry={lines}>
        <lineBasicMaterial color="#22D3EE" transparent opacity={0.45} />
      </lineSegments>
    </group>
  )
}

/**
 * The finding's path as a 3D chain: source (cyan), functions (light grey), sink (red).
 * Click a node to pick its step; `playKey` changing plays the data flowing along the chain.
 */
export default function PathChain3D({ chain, selected, onSelect, playKey, onPlayed }) {
  const { disable3D } = useEffects()
  const points = useMemo(() => positionsFor(chain.length), [chain.length])
  const labels = useRef([])
  const [playing, setPlaying] = useState(false)
  useEffect(() => { if (playKey) setPlaying(true) }, [playKey])
  useEffect(() => () => { document.body.style.cursor = '' }, [])
  const loop = playing ? 'always' : 'demand'

  return (
    <div className="pathchain-3d" data-testid="path-chain-3d" aria-hidden="true">
      <Canvas dpr={[1, 1.5]} frameloop={loop} camera={{ position: [0, 0.5, 8], fov: 45 }}
              gl={{ antialias: true, alpha: true }}>
        <WakeOnChange value={`${loop}-${selected}`} />
        <FitCamera count={chain.length} />
        <Chain chain={chain} points={points} selected={selected} onSelect={onSelect} playing={playing}
               labels={labels} onSlow={() => disable3D('slow')}
               onPlayed={() => { setPlaying(false); onPlayed?.() }} />
      </Canvas>
      <div className="pathchain-labels" aria-hidden="true">
        {chain.map((step, i) => (
          <span key={i} ref={(el) => { labels.current[i] = el }} title={step.label}
                className={`pathchain-label ${step.kind} ${i === selected ? 'selected' : ''}`}>
            {short(step.label)}
          </span>
        ))}
      </div>
    </div>
  )
}
