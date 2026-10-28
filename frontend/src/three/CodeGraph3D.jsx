import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { useEffects } from '../components/effects.jsx'
import { makeGraph } from './graphData.js'
import { useFpsGuard } from './useFpsGuard.js'

const CYAN = '#22D3EE'
const RED = '#F43F5E'
const DRIFT = 0.09      // how far a node wanders from its home, in scene units
const SPIN = 0.035      // radians per second around the vertical axis
const PARALLAX = 0.22   // how much the graph leans toward the mouse

/** Mouse position in -1..1, read from the window so the canvas never blocks clicks. */
function usePointer() {
  const pointer = useRef({ x: 0, y: 0 })
  useEffect(() => {
    const onMove = (e) => {
      pointer.current.x = (e.clientX / window.innerWidth) * 2 - 1
      pointer.current.y = (e.clientY / window.innerHeight) * 2 - 1
    }
    window.addEventListener('pointermove', onMove, { passive: true })
    return () => window.removeEventListener('pointermove', onMove)
  }, [])
  return pointer
}

function Graph({ graph, onSlow }) {
  useFpsGuard(onSlow)
  const pointer = usePointer()
  const spin = useRef()
  const tilt = useRef()
  const calm = useRef()
  const risky = useRef()
  const halos = useRef()
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const ids = useMemo(() => {
    const all = graph.nodes.map((_, i) => i)
    return { calm: all.filter((i) => !graph.risky.has(i)), risky: all.filter((i) => graph.risky.has(i)) }
  }, [graph])
  const current = useMemo(() => new Float32Array(graph.nodes.length * 3), [graph])
  const lines = useMemo(() => {
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(new Float32Array(graph.edges.length * 6), 3))
    return geometry
  }, [graph])
  useEffect(() => () => lines.dispose(), [lines])  // made by hand, so freed by hand

  useFrame((state, delta) => {
    const t = state.clock.elapsedTime
    graph.nodes.forEach((n, i) => {
      current[i * 3] = n.x + Math.sin(t * n.speed + n.phase) * DRIFT
      current[i * 3 + 1] = n.y + Math.cos(t * n.speed * 0.8 + n.phase) * DRIFT
      current[i * 3 + 2] = n.z + Math.sin(t * n.speed * 0.6 + n.phase * 1.3) * DRIFT
    })
    const place = (mesh, list, scaleFor) => {
      list.forEach((id, k) => {
        dummy.position.set(current[id * 3], current[id * 3 + 1], current[id * 3 + 2])
        dummy.scale.setScalar(scaleFor(id))
        dummy.updateMatrix()
        mesh.setMatrixAt(k, dummy.matrix)
      })
      mesh.instanceMatrix.needsUpdate = true
    }
    const pulse = (id) => 1 + 0.45 * Math.max(0, Math.sin(t * 2.2 + graph.nodes[id].phase))
    place(calm.current, ids.calm, () => 1)
    place(risky.current, ids.risky, pulse)
    place(halos.current, ids.risky, (id) => 1.5 + 2.2 * Math.max(0, Math.sin(t * 2.2 + graph.nodes[id].phase)))

    const positions = lines.attributes.position.array
    graph.edges.forEach(([a, b], k) => {
      positions.set(current.subarray(a * 3, a * 3 + 3), k * 6)
      positions.set(current.subarray(b * 3, b * 3 + 3), k * 6 + 3)
    })
    lines.attributes.position.needsUpdate = true

    spin.current.rotation.y += delta * SPIN
    tilt.current.rotation.x += (pointer.current.y * PARALLAX - tilt.current.rotation.x) * 0.04
    tilt.current.rotation.z += (-pointer.current.x * PARALLAX * 0.5 - tilt.current.rotation.z) * 0.04
  })

  return (
    <group ref={tilt}>
      <group ref={spin}>
        <instancedMesh ref={calm} args={[undefined, undefined, ids.calm.length]}>
          <sphereGeometry args={[0.035, 10, 10]} />
          <meshBasicMaterial color={CYAN} toneMapped={false} />
        </instancedMesh>
        <instancedMesh ref={risky} args={[undefined, undefined, ids.risky.length]}>
          <sphereGeometry args={[0.055, 12, 12]} />
          <meshBasicMaterial color={RED} toneMapped={false} />
        </instancedMesh>
        <instancedMesh ref={halos} args={[undefined, undefined, ids.risky.length]}>
          <sphereGeometry args={[0.05, 12, 12]} />
          <meshBasicMaterial color={RED} transparent opacity={0.14} depthWrite={false}
                             blending={THREE.AdditiveBlending} toneMapped={false} />
        </instancedMesh>
        <lineSegments geometry={lines}>
          <lineBasicMaterial color={CYAN} transparent opacity={0.16} depthWrite={false}
                             blending={THREE.AdditiveBlending} />
        </lineSegments>
      </group>
    </group>
  )
}

/** Only animate while the hero is on screen; otherwise render on demand (that is, not at all). */
function useOnScreen(ref) {
  const [visible, setVisible] = useState(true)
  useEffect(() => {
    if (!ref.current || !window.IntersectionObserver) return undefined
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting))
    observer.observe(ref.current)
    return () => observer.disconnect()
  }, [ref])
  return visible
}

/**
 * The hero's slowly turning network of functions (cyan) with a few risky ones (red).
 * `distance` is how far the camera sits: closer fills a wide, short hero.
 */
export default function CodeGraph3D({ distance = 7.5 }) {
  const { disable3D } = useEffects()
  const graph = useMemo(() => makeGraph(), [])
  const box = useRef()
  const visible = useOnScreen(box)
  const lost = useRef(null)
  useEffect(() => () => lost.current?.(), [])

  return (
    <div ref={box} className="graph-3d" data-testid="code-graph-3d" aria-hidden="true">
      <Canvas dpr={[1, 1.5]} frameloop={visible ? 'always' : 'demand'} camera={{ position: [0, 0, distance], fov: 50 }}
              gl={{ antialias: true, alpha: true, powerPreference: 'default' }}
              onCreated={({ gl }) => {
                const onLost = () => disable3D('webgl-lost')
                gl.domElement.addEventListener('webglcontextlost', onLost)
                lost.current = () => gl.domElement.removeEventListener('webglcontextlost', onLost)
              }}>
        <Graph graph={graph} onSlow={() => disable3D('slow')} />
      </Canvas>
    </div>
  )
}
