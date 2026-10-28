/**
 * Links each step of a finding's path to a line in its file, using only the finding and the file's
 * text. The path holds function names, not line numbers, so functions are found by their `def`.
 */

const DEF = (name) => new RegExp(`^\\s*(async\\s+)?def\\s+${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`)

/** "helpers.lookup_user()" -> "lookup_user". */
export function functionName(label) {
  return label.replace(/\(.*$/, '').split('.').pop().trim()
}

/** Line numbers (1-based) where a function starts and ends, by indentation. */
function functionSpan(lines, name) {
  const start = lines.findIndex((l) => DEF(name).test(l))
  if (start < 0) return null
  const indent = lines[start].match(/^\s*/)[0].length
  let end = start + 1
  while (end < lines.length && (lines[end].trim() === '' || lines[end].match(/^\s*/)[0].length > indent)) end += 1
  return [start + 1, end]
}

/**
 * The chain shown for a finding: source (user input), each function, then the sink.
 * `kind` is source | function | sink; `line` is null when the step is in another file.
 */
export function chainFor(finding, text) {
  const steps = finding.path?.length ? finding.path : [finding.sink].filter(Boolean)
  const labels = [finding.source, ...steps].filter(Boolean)
  const lines = (text ?? '').split('\n')
  const entry = steps.length > 1 ? functionSpan(lines, functionName(steps[0])) : null
  return labels.map((label, i) => {
    const kind = finding.source && i === 0 ? 'source' : i === labels.length - 1 ? 'sink' : 'function'
    if (kind === 'sink') return { label, kind, line: finding.line }
    if (kind === 'function') {
      const span = functionSpan(lines, functionName(label))
      return { label, kind, line: span ? span[0] : null }
    }
    const needle = label.replace(/[[(].*$/, '')  // request.args['q'] -> request.args
    const [from, to] = entry ?? [1, lines.length]
    const hit = lines.slice(from - 1, to).findIndex((l) => l.includes(needle))
    return { label, kind, line: hit >= 0 ? from + hit : null }
  })
}
