import { describe, expect, it } from 'vitest'
import { buildCallGraph, isTraced, layoutCallGraph } from './callGraph.js'

const finding = (over) => ({ id: 'F-1', cwe: 'CWE-89', severity: 9.3, file: 'helpers.py', line: 16,
  source: 'request.args', path: ['lookup()', 'query_text()', 'db.execute'], sink: 'db.execute', ...over })

describe('buildCallGraph', () => {
  it('turns each traced finding into a source -> functions -> sink chain', () => {
    const graph = buildCallGraph([finding()])
    expect(graph.paths[0].labels).toEqual(['request.args', 'lookup()', 'query_text()', 'db.execute'])
    expect(graph.nodes.map((n) => n.kind)).toEqual(['source', 'function', 'function', 'sink'])
    expect(graph.edges).toHaveLength(3)
  })

  it('shares function nodes between paths but keeps every sink line separate', () => {
    const graph = buildCallGraph([
      finding(),
      finding({ id: 'F-2', line: 30, severity: 7, path: ['lookup()', 'db.execute'] }),
    ])
    expect(graph.nodes.filter((n) => n.label === 'lookup()')).toHaveLength(1)
    expect(graph.nodes.filter((n) => n.kind === 'sink')).toHaveLength(2)
  })

  it('ignores pattern-only findings and orders paths most severe first', () => {
    const graph = buildCallGraph([
      finding({ id: 'low', severity: 4 }),
      finding({ id: 'pattern', source: '', path: [] }),
      finding({ id: 'high', severity: 9.8, line: 40 }),
    ])
    expect(graph.paths.map((p) => p.findingId)).toEqual(['high', 'low'])
    expect(isTraced(finding({ source: '' }))).toBe(false)
  })

  it('puts every sink in the last column, whatever its path length', () => {
    const graph = buildCallGraph([finding(), finding({ id: 'F-2', line: 30, path: ['save()', 'open'] })])
    const depths = graph.nodes.filter((n) => n.kind === 'sink').map((n) => n.depth)
    expect(new Set(depths)).toEqual(new Set([3]))
  })

  it('lays nodes out left to right by depth', () => {
    const graph = buildCallGraph([finding()])
    const xs = graph.paths[0].ids.map((id) => layoutCallGraph(graph).get(id)[0])
    expect([...xs].sort((a, b) => a - b)).toEqual(xs)
  })
})
