import { describe, expect, it } from 'vitest'
import { chainFor, functionName } from './pathLines.js'

const FILE = [
  'from flask import request',          // 1
  '',                                    // 2
  '@app.route("/lookup")',               // 3
  'def lookup():',                       // 4
  '    name = request.args.get("n")',    // 5
  '    return query_text(name)',         // 6
  '',                                    // 7
  'def query_text(value):',              // 8
  '    return db.execute("SELECT " + value)',  // 9
].join('\n')

const finding = { source: "request.args['n']", path: ['lookup()', 'query_text()', 'db.execute'],
  sink: 'db.execute', line: 9 }

describe('chainFor', () => {
  it('links source, functions and sink to their lines', () => {
    expect(chainFor(finding, FILE)).toEqual([
      { label: "request.args['n']", kind: 'source', line: 5 },
      { label: 'lookup()', kind: 'function', line: 4 },
      { label: 'query_text()', kind: 'function', line: 8 },
      { label: 'db.execute', kind: 'sink', line: 9 },
    ])
  })

  it('says a function is elsewhere instead of guessing', () => {
    const chain = chainFor({ ...finding, path: ['lookup()', 'helpers.other()', 'db.execute'] }, FILE)
    expect(chain[2]).toEqual({ label: 'helpers.other()', kind: 'function', line: null })
  })

  it('handles a pattern-only finding (no source, no path)', () => {
    expect(chainFor({ source: '', path: [], sink: 'open', line: 3 }, FILE)).toEqual([{ label: 'open', kind: 'sink', line: 3 }])
  })

  it('strips module and arguments from function labels', () => {
    expect(functionName('helpers.lookup_user()')).toBe('lookup_user')
  })
})
