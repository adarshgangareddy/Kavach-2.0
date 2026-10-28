const BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(BASE + path, options)
  if (!res.ok) {
    let message = res.statusText
    try {
      const body = await res.json()
      message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message || `Request failed (${res.status})`)
  }
  return res
}

const json = (path, options) => request(path, options).then((r) => r.json())

export const api = {
  detectors: () => json('/detectors'),
  cweCatalog: () => json('/cwe'),
  listScans: () => json('/scans'),
  getScan: (id) => json(`/scans/${id}`),
  findings: (id) => json(`/scans/${id}/findings`),
  finding: (id) => json(`/findings/${id}`),
  setStatus: (id, status) =>
    json(`/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }),
  uploadZip: (file) => {
    const form = new FormData()
    form.append('file', file)
    return json('/scans', { method: 'POST', body: form })
  },
  scanGithub: (url) => {
    const form = new FormData()
    form.append('github_url', url)
    return json('/scans', { method: 'POST', body: form })
  },
  snippet: (code) =>
    json('/snippet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    }),
  source: (scanId, path) =>
    request(`/scans/${scanId}/source?path=${encodeURIComponent(path)}`).then((r) => r.text()),
  exportUrl: (scanId, kind) =>
    kind === 'sarif' ? `${BASE}/scans/${scanId}/sarif` : `${BASE}/scans/${scanId}/report?format=${kind}`,
}

export function severityLabel(score) {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES = ['open', 'fixed', 'accepted']
