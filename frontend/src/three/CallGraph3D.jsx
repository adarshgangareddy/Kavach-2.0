import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { useEffects } from '../components/effects.jsx'
import { makeGraph } from './graphData.js'
import { layoutCallGraph, MAX_PATHS } from './callGraph.js'
import { useFpsGuard } from './useFpsGuard.js'
import WakeOnChange from './WakeOnChange.jsx'

const COLOR = { source: '#22D3EE', function: '#94A3B8', sink: '#F43F5E' }
const RADIUS = { source: 0.13, function: 0.1, sink: 0.14 }
const BUILD_STEP = 0.12   // seconds between nodes appearing
const TRAVEL = 1.1        // seconds for a particle to go from source to sink
const STAGGER = 0.55      // seconds between particles starting
const PULSE = 0.9         // seconds a sink keeps pulsing after a hit
const hidden = new THREE.Matrix4().makeScale(0, 0, 0)

function useLines(edgeCount) {
  const geometry = useMemo(() => {
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(Math.max(1, edgeCount) * 6), 3))
    return g
  }, [edgeCount])
  useEffect(() => () => geometry.dispose(), [geometry])
  return geometry
}

/** While the scan runs: a graph grows node by node. It shows work in progress, not real results. */
function Building({ onSlow }) {
  useFpsGuard(onSlow)
  const graph = useMemo(() => makeGraph({ count: 40, risky: 0, seed: 11 }), [])
  const edges = useMemo(() => [...graph.edges].sort((a, b) => Math.max(...a) - Math.max(...b)), [graph])
  const lines = useLines(edges.length)
  const nodes = useRef()
  const spin = useRef()
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const scale = 0.7

  useEffect(() => {
    const positions = lines.attributes.position.array
    edges.forEach(([a, b], k) => {
      positions.set([graph.nodes[a].x * scale, graph.nodes[a].y * scale, graph.nodes[a].z * scale], k * 6)
      positions.set([graph.nodes[b].x * scale, graph.nodes[b].y * scale, graph.nodes[b].z * scale], k * 6 + 3)
    })
    lines.attributes.position.needsUpdate = true
  }, [edges, graph, lines])

  useFrame((state, delta) => {
    const shown = Math.floor(state.clock.elapsedTime / BUILD_STEP) % (graph.nodes.length + 12)  // pause, then rebuild
    graph.nodes.forEach((n, i) => {
      if (i >= shown) return nodes.current.setMatrixAt(i, hidden)
      const age = Math.min(1, (state.clock.elapsedTime - i * BUILD_STEP) / 0.3)
      dummy.position.set(n.x * scale, n.y * scale, n.z * scale)
      dummy.scale.setScalar(Math.max(0.01, age))
      dummy.updateMatrix()
      nodes.current.setMatrixAt(i, dummy.matrix)
    })
    nodes.current.instanceMatrix.needsUpdate = true
    lines.setDrawRange(0, edges.filter(([a, b]) => Math.max(a, b) < shown).length * 2)
    spin.current.rotation.y += delta * 0.25
  })

  return (
    <group ref={spin}>
      <instancedMesh ref={nodes} args={[undefined, undefined, graph.nodes.length]}>
        <sphereGeometry args={[0.07, 12, 12]} />
        <meshBasicMaterial color={COLOR.source} toneMapped={false} />
      </instancedMesh>
      <lineSegments geometry={lines}>
        <lineBasicMaterial color={COLOR.source} transparent opacity={0.25} />
      </lineSegments>
    </group>
  )
}

/** Where a particle is after `t` seconds of travel along a chain of points. */
function along(points, t) {
  const progress = Math.min(1, Math.max(0, t / TRAVEL)) * (points.length - 1)
  const i = Math.min(points.length - 2, Math.floor(progress))
  return new THREE.Vector3().lerpVectors(points[i], points[i + 1], progress - i)
}

/** The real call graph: nodes appear by depth, then tainted data runs from each source to its sink. */
function Result({ graph, onSlow, onDone }) {
  useFpsGuard(onSlow)
  const layout = useMemo(() => layoutCallGraph(graph), [graph])
  const byKind = useMemo(() => ({
    source: graph.nodes.filter((n) => n.kind === 'source'),
    function: graph.nodes.filter((n) => n.kind === 'function'),
    sink: graph.nodes.filter((n) => n.kind === 'sink'),
  }), [graph])
  const played = useMemo(() => graph.paths.slice(0, MAX_PATHS).map((p) => ({
    ...p, points: p.ids.map((id) => new THREE.Vector3(...layout.get(id))),
  })), [graph, layout])
  const maxDepth = Math.max(0, ...graph.nodes.map((n) => n.depth))
  const buildTime = (maxDepth + 1) * 0.25
  const endTime = buildTime + (played.length - 1) * STAGGER + TRAVEL + PULSE
  const lines = useLines(graph.edges.length)
  const meshes = { source: useRef(), function: useRef(), sink: useRef() }
  const halos = useRef()
  const particles = useRef()
  const lineMaterial = useRef()
  const finished = useRef(false)
  const clock = useRef(0)  // own time: the canvas clock restarts when it switches to render-on-demand
  const dummy = useMemo(() => new THREE.Object3D(), [])

  useEffect(() => {
    const positions = lines.attributes.position.array
    graph.edges.forEach(([a, b], k) => {
      positions.set(layout.get(a), k * 6)
      positions.set(layout.get(b), k * 6 + 3)
    })
    lines.attributes.position.needsUpdate = true
  }, [graph, layout, lines])

  useFrame((_, delta) => {
    clock.current = finished.current ? endTime : Math.min(endTime, clock.current + Math.min(delta, 0.1))
    const t = clock.current
    const put = (mesh, k, position, scale) => {
      dummy.position.set(...position)
      dummy.scale.setScalar(scale)
      dummy.updateMatrix()
      mesh.setMatrixAt(k, dummy.matrix)
    }
    Object.entries(byKind).forEach(([kind, list]) => {
      list.forEach((n, k) => put(meshes[kind].current, k, layout.get(n.id),
        Math.min(1, Math.max(0.001, (t - n.depth * 0.25) / 0.3))))
      meshes[kind].current.instanceMatrix.needsUpdate = true
    })
    lineMaterial.current.opacity = 0.3 * Math.min(1, t / buildTime)

    const hitAt = new Map()  // sink id -> when its particle arrived
    played.forEach((p, k) => {
      const start = buildTime + k * STAGGER
      const active = t >= start && t <= start + TRAVEL
      const where = active ? along(p.points, t - start) : null
      if (where) put(particles.current, k, where.toArray(), 1)
      else particles.current.setMatrixAt(k, hidden)
      if (t >= start + TRAVEL) hitAt.set(p.ids.at(-1), Math.max(hitAt.get(p.ids.at(-1)) ?? 0, start + TRAVEL))
    })
    particles.current.instanceMatrix.needsUpdate = true
    byKind.sink.forEach((n, k) => {
      const since = hitAt.has(n.id) ? t - hitAt.get(n.id) : Infinity
      const pulse = since < PULSE ? 1 - since / PULSE : 0
      put(halos.current, k, layout.get(n.id), since === Infinity ? 0.001 : 1.6 + pulse * 2.4)
    })
    halos.current.instanceMatrix.needsUpdate = true

    if (t >= endTime && !finished.current) {
      finished.current = true
      onDone()  // nothing moves any more: the canvas switches to render-on-demand
    }
  })

  return (
    <group>
      {Object.keys(byKind).map((kind) => (
        <instancedMesh key={kind} ref={meshes[kind]} args={[undefined, undefined, Math.max(1, byKind[kind].length)]}
                       count={byKind[kind].length}>
          <sphereGeometry args={[RADIUS[kind], 18, 18]} />
          <meshBasicMaterial color={COLOR[kind]} toneMapped={false} />
        </instancedMesh>
      ))}
      <instancedMesh ref={halos} args={[undefined, undefined, Math.max(1, byKind.sink.length)]} count={byKind.sink.length}>
        <sphereGeometry args={[0.14, 18, 18]} />
        <meshBasicMaterial color={COLOR.sink} transparent opacity={0.22} depthWrite={false}
                           blending={THREE.AdditiveBlending} toneMapped={false} />
      </instancedMesh>
      <instancedMesh ref={particles} args={[undefined, undefined, Math.max(1, played.length)]} count={played.length}>
        <sphereGeometry args={[0.07, 12, 12]} />
        <meshBasicMaterial color="#E0FBFF" toneMapped={false} />
      </instancedMesh>
      <lineSegments geometry={lines}>
        <lineBasicMaterial ref={lineMaterial} color={COLOR.source} transparent opacity={0} />
      </lineSegments>
    </group>
  )
}

/** Fit the camera to the graph's width so long chains stay on screen. */
function cameraFor(graph) {
  if (!graph) return [0, 0, 6]
  const depth = Math.max(0, ...graph.nodes.map((n) => n.depth))
  return [0, 0, Math.max(5.5, depth * 2.2 + 2.5)]
}

/**
 * The scan page's call graph. mode "building" while the scan runs; "result" once findings are in,
 * when `graph` (from buildCallGraph) holds the real traced paths.
 */
export default function CallGraph3D({ mode, graph }) {
  const { disable3D } = useEffects()
  const [animating, setAnimating] = useState(true)
  const box = useRef()
  const [visible, setVisible] = useState(true)
  useEffect(() => {
    if (!box.current || !window.IntersectionObserver) return undefined
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting))
    observer.observe(box.current)
    return () => observer.disconnect()
  }, [])
  const onSlow = () => disable3D('slow')
  const loop = animating && visible ? 'always' : 'demand'

  return (
    <div ref={box} className="callgraph-3d" data-testid="call-graph-3d" aria-hidden="true">
      <Canvas dpr={[1, 1.5]} frameloop={loop}
              camera={{ position: cameraFor(mode === 'result' ? graph : null), fov: 45 }}
              gl={{ antialias: true, alpha: true }}>
        <WakeOnChange value={loop} />
        {mode === 'building'
          ? <Building onSlow={onSlow} />
          : <Result graph={graph} onSlow={onSlow} onDone={() => setAnimating(false)} />}
      </Canvas>
    </div>
  )
}
