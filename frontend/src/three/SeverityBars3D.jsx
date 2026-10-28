import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import { useEffects } from '../components/effects.jsx'
import { useFpsGuard } from './useFpsGuard.js'
import WakeOnChange from './WakeOnChange.jsx'

const COLOR = { critical: '#F43F5E', high: '#FB923C', medium: '#F59E0B', low: '#7DD3FC', info: '#94A3B8' }
const GAP = 1.25
const WIDTH = 0.75
const TALLEST = 2.2
const GROW = 0.8   // seconds for the bars to rise from zero

const ease = (t) => 1 - (1 - t) ** 3

function Bars({ rows, selected, hovered, onHover, onSelect, onGrown, tips, onSlow, growing }) {
  useFpsGuard(onSlow, { enabled: growing })
  const max = Math.max(1, ...rows.map((r) => r.value))
  const bars = useRef([])
  const time = useRef(0)
  const done = useRef(false)
  const top = useMemo(() => new THREE.Vector3(), [])
  const x = (i) => (i - (rows.length - 1) / 2) * GAP

  useFrame(({ camera, size }, delta) => {
    time.current = Math.min(GROW, time.current + Math.min(delta, 0.1))
    const k = ease(time.current / GROW)
    rows.forEach((r, i) => {
      const bar = bars.current[i]
      if (!bar) return
      const h = Math.max(0.02, (r.value / max) * TALLEST * k)
      bar.scale.y = h
      bar.position.y = h / 2 - TALLEST / 2
      const tip = tips.current[i]
      if (tip) {  // the count and name sit above each bar, as text
        top.set(x(i), h - TALLEST / 2 + 0.25, 0).project(camera)
        tip.style.transform = `translate(-50%, -100%) translate(${(top.x * 0.5 + 0.5) * size.width}px, ${(-top.y * 0.5 + 0.5) * size.height}px)`
      }
    })
    if (time.current >= GROW && !done.current) {
      done.current = true
      onGrown()
    }
  })

  return (
    <group>
      {rows.map((r, i) => {
        const dim = (selected && selected !== r.key) || (hovered != null && hovered !== i)
        return (
          <mesh key={r.key} ref={(m) => { bars.current[i] = m }} position={[x(i), -TALLEST / 2, 0]} scale={[1, 0.02, 1]}
                onPointerOver={(e) => { e.stopPropagation(); onHover(i); document.body.style.cursor = 'pointer' }}
                onPointerOut={() => { onHover(null); document.body.style.cursor = '' }}
                onClick={(e) => { e.stopPropagation(); onSelect(selected === r.key ? '' : r.key) }}>
            <boxGeometry args={[WIDTH, 1, WIDTH]} />
            <meshStandardMaterial color={COLOR[r.key] ?? COLOR.info} roughness={0.35} metalness={0.1}
                                  emissive={COLOR[r.key] ?? COLOR.info} emissiveIntensity={dim ? 0.05 : 0.35}
                                  transparent opacity={dim ? 0.45 : 1} />
          </mesh>
        )
      })}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -TALLEST / 2 - 0.01, 0]}>
        <planeGeometry args={[rows.length * GAP + 0.6, 1.6]} />
        <meshBasicMaterial color="#22D3EE" transparent opacity={0.05} />
      </mesh>
    </group>
  )
}

/** Looks down on the bars at a slight angle, fitted to the box. */
function FitCamera({ count }) {
  const { camera, size, invalidate } = useThree()
  useEffect(() => {
    const half = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2))
    const byWidth = (count * GAP + 1) / (2 * half * (size.width / size.height))
    const z = Math.max(byWidth, (TALLEST + 1.4) / (2 * half))
    camera.position.set(0, 1.4, z)
    camera.lookAt(0, -0.2, 0)
    camera.updateProjectionMatrix()
    invalidate()
  }, [camera, size.width, size.height, count, invalidate])
  return null
}

/**
 * Severity of the open issues as 3D bars. Hover a bar for its count; click it to filter the list.
 * The bars rise once, then the canvas only redraws when something changes.
 */
export default function SeverityBars3D({ rows, selected, onSelect }) {
  const { disable3D } = useEffects()
  const [hovered, setHovered] = useState(null)
  const [growing, setGrowing] = useState(true)
  const tips = useRef([])
  useEffect(() => () => { document.body.style.cursor = '' }, [])
  const loop = growing ? 'always' : 'demand'
  const tip = hovered != null ? rows[hovered] : null

  return (
    <div className="sevbars-3d" data-testid="severity-3d" aria-hidden="true">
      <Canvas dpr={[1, 1.5]} frameloop={loop} camera={{ position: [0, 1.4, 7], fov: 40 }} gl={{ antialias: true, alpha: true }}>
        <WakeOnChange value={`${loop}-${hovered}-${selected}`} />
        <FitCamera count={rows.length} />
        <ambientLight intensity={0.55} />
        <directionalLight position={[3, 5, 4]} intensity={1.1} />
        <Bars rows={rows} selected={selected} hovered={hovered} onHover={setHovered} onSelect={onSelect}
              onGrown={() => setGrowing(false)} tips={tips} onSlow={() => disable3D('slow')} growing={growing} />
      </Canvas>
      <div className="sevbars-tips">
        {rows.map((r, i) => (
          <span key={r.key} ref={(el) => { tips.current[i] = el }} className={`sevbars-tip sev-${r.key}`}>
            <strong>{r.value}</strong> {r.label}
          </span>
        ))}
      </div>
      {tip && (
        <div className="sevbars-tooltip" role="status">
          {tip.label[0].toUpperCase() + tip.label.slice(1)}: {tip.value} open {tip.value === 1 ? 'issue' : 'issues'}. Click to {selected === tip.key ? 'show all' : 'show only these'}.
        </div>
      )}
    </div>
  )
}
