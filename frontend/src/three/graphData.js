/** A made-up "code graph" for the hero: the same seeded layout for the 3D view and its 2D fallback. */

export const NODE_COUNT = 120  // the brief caps the hero at 150 nodes
export const RISKY_COUNT = 6   // nodes that pulse red, like vulnerable functions
const LINKS_PER_NODE = 2

function seeded(seed) {  // mulberry32: small, fast, repeatable
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** Nodes in a loose, flattened sphere; each joined to its nearest neighbours. */
export function makeGraph({ count = NODE_COUNT, risky = RISKY_COUNT, seed = 7 } = {}) {
  const rand = seeded(seed)
  const nodes = Array.from({ length: count }, () => {
    const theta = rand() * Math.PI * 2
    const phi = Math.acos(2 * rand() - 1)
    const r = 2.2 + rand() * 1.6
    return {
      x: r * Math.sin(phi) * Math.cos(theta) * 1.35,
      y: r * Math.cos(phi) * 0.75,
      z: r * Math.sin(phi) * Math.sin(theta),
      phase: rand() * Math.PI * 2,
      speed: 0.25 + rand() * 0.35,
    }
  })
  const seen = new Set()
  const edges = []
  nodes.forEach((a, i) => {
    nodes.map((b, j) => [j, (a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2])
      .filter(([j]) => j !== i)
      .sort((p, q) => p[1] - q[1])
      .slice(0, LINKS_PER_NODE)
      .forEach(([j]) => {
        const key = i < j ? `${i}-${j}` : `${j}-${i}`
        if (!seen.has(key)) {
          seen.add(key)
          edges.push([i, j])
        }
      })
  })
  const riskyIds = new Set()
  while (riskyIds.size < Math.min(risky, count)) riskyIds.add(Math.floor(rand() * count))
  return { nodes, edges, risky: riskyIds }
}
