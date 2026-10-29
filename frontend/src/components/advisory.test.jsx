import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { LinkedText, isAdvisory, plainSummary } from '../components.jsx'
import { buildCallGraph, isTraced } from '../three/callGraph.js'
import { chainFor } from './pathLines.js'

const ADVISORY = { id: 'F-1', detected_at: 'watch', cwe: 'CWE-1395', file: 'app.py', line: 1, severity: 5.7,
  source: 'requirements.txt:1 Flask==0.12.2', path: ['import flask'], sink: 'flask 0.12.2 has 8 published security fixes you do not have',
  detector: 'fixwatch', severity_factors: {} }

afterEach(cleanup)

describe('fix-watcher findings in the dashboard', () => {
  it('are recognised and summed up in plain words', () => {
    expect(isAdvisory(ADVISORY)).toBe(true)
    expect(isAdvisory({ ...ADVISORY, detected_at: 'review' })).toBe(false)
    expect(plainSummary(ADVISORY)).toBe('flask 0.12.2 has 8 published security fixes you do not have. '
      + 'This file imports it, so those fixes may matter here.')
  })

  it('show the dependency, then where it is used, in the path view', () => {
    expect(chainFor(ADVISORY, 'from flask import Flask\n')).toEqual([
      { label: 'requirements.txt:1 Flask==0.12.2', kind: 'source', tag: 'dependency', line: null },
      { label: 'import flask', kind: 'sink', tag: 'used here', line: 1 },
    ])
  })

  it('stay out of the call graph: they trace a dependency, not user input', () => {
    expect(isTraced(ADVISORY)).toBe(false)
    expect(buildCallGraph([ADVISORY]).paths).toEqual([])
  })

  it('make advisory links in the fix advice clickable', () => {
    render(<p><LinkedText text="Fixes: GHSA-x (https://osv.dev/vulnerability/GHSA-x)." /></p>)
    const link = screen.getByRole('link', { name: 'osv.dev/vulnerability/GHSA-x' })
    expect(link.getAttribute('href')).toBe('https://osv.dev/vulnerability/GHSA-x')
    expect(link.getAttribute('rel')).toContain('noopener')
  })
})
