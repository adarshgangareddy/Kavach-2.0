/**
 * Call graph for the scan page, built from real findings: each traced finding gives a chain
 * source -> functions -> sink, using its `source` and `path` fields. No made-up data.
 */

export const MAX_PATHS = 12  // particles to play; the table below the graph lists every path

const sinkKey = (f) => `sink:${f.sink || f.path.at(-1)}@${f.file}:${f.line}`

/** A finding with a traced path: a user-input source and at least one step. */
export function isTraced(f) {
  return f.detected_at !== 'watch'  // fix-watcher leads trace a dependency, not user input
    && Boolean(f.source) && Array.isArray(f.path) && f.path.length > 0
}

/** The chain of labels for one finding: source, the functions it passes through, then the sink. */
export function chainOf(f) {
  return [f.source, ...f.path]
}

/**
 * Nodes are merged by name (a helper used by two routes is one node); each sink stays its own
 * node because it is one specific line. Paths are ordered most severe first.
 */
export function buildCallGraph(findings) {
  const traced = findings.filter(isTraced).sort((a, b) => b.severity - a.severity)
  const nodes = new Map()
  const edges = new Map()
  const paths = traced.map((f) => {
    const labels = chainOf(f)
    const ids = labels.map((label, i) => {
      const kind = i === 0 ? 'source' : i === labels.length - 1 ? 'sink' : 'function'
      const id = kind === 'sink' ? sinkKey(f) : `${kind}:${label}`
      const node = nodes.get(id) ?? { id, label, kind, depth: i }
      node.depth = Math.max(node.depth, i)
      if (kind === 'sink') node.severity = Math.max(node.severity ?? 0, f.severity)
      nodes.set(id, node)
      return id
    })
    ids.slice(1).forEach((id, i) => edges.set(`${ids[i]}>${id}`, [ids[i], id]))
    return { findingId: f.id, cwe: f.cwe, severity: f.severity, file: f.file, line: f.line, labels, ids }
  })
  const last = Math.max(0, ...[...nodes.values()].map((n) => n.depth))
  nodes.forEach((n) => { if (n.kind === 'sink') n.depth = last })  // every sink in the right-hand column
  return { nodes: [...nodes.values()], edges: [...edges.values()], paths }
}

/** Left-to-right layers by depth, spread vertically, centred on the origin. */
export function layoutCallGraph(graph, { columnGap = 2.2, rowGap = 0.9 } = {}) {
  const columns = new Map()
  graph.nodes.forEach((n) => columns.set(n.depth, [...(columns.get(n.depth) ?? []), n]))
  const depths = [...columns.keys()].sort((a, b) => a - b)
  const width = (depths.length - 1) * columnGap
  const positions = new Map()
  depths.forEach((depth, col) => {
    const column = columns.get(depth)
    column.forEach((n, row) => {
      const y = ((column.length - 1) / 2 - row) * rowGap
      const z = ((row % 3) - 1) * 0.35  // a little depth so the 3D view is not flat
      positions.set(n.id, [col * columnGap - width / 2, y, z])
    })
  })
  return positions
}
