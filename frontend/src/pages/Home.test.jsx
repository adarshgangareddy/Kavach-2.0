import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EffectsProvider } from '../components/effects.jsx'
import Home from './Home.jsx'

vi.mock('../api.js', () => ({
  api: {
    listApps: vi.fn(),
    createApp: vi.fn(),
    deleteApp: vi.fn(),
    listScans: vi.fn(),
    uploadZip: vi.fn(),
    scanGithub: vi.fn(),
    snippet: vi.fn(),
  },
}))

import { api } from '../api.js'

function renderHome() {
  return render(
    <EffectsProvider detectWebGL={() => true}>
      <Home />
    </EffectsProvider>,
  )
}

describe('Home Component (Signed-in App Shell & Initial Scan Workflow)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listApps.mockResolvedValue([
      { id: 'app-1', name: 'flask-demo', created_at: 1731000000 },
    ])
    api.listScans.mockResolvedValue([
      {
        id: 'S-abc12345',
        source_kind: 'snippet',
        source_ref: 'snippet.py',
        files_scanned: 1,
        created_at: 1731000000,
        status: 'done',
        severity_counts: { critical: 1, high: 0 },
        finding_count: 1,
      },
    ])
  })
  afterEach(cleanup)

  it('renders project heading, workflow steps, registered projects and scans', async () => {
    renderHome()

    expect(screen.getByRole('heading', { level: 1, name: /projects & security scans/i })).toBeTruthy()
    expect(screen.getByText(/register or open project/i)).toBeTruthy()
    expect(screen.getByRole('heading', { level: 2, name: /registered projects/i })).toBeTruthy()

    await waitFor(() => {
      expect(screen.getByText('flask-demo')).toBeTruthy()
      expect(screen.getByText('snippet.py')).toBeTruthy()
    })
  })

  it('allows registering a new project via createApp API', async () => {
    api.createApp.mockResolvedValue({ id: 'app-2', name: 'payment-service', app_key: 'test_sec_key_123' })
    renderHome()

    const registerBtn = screen.getByRole('button', { name: /\+ register project/i })
    fireEvent.click(registerBtn)

    const input = screen.getByPlaceholderText(/e\.g\. customer-api/i)
    fireEvent.change(input, { target: { value: 'payment-service' } })

    const saveBtn = screen.getByRole('button', { name: /save project/i })
    fireEvent.click(saveBtn)

    await waitFor(() => {
      expect(api.createApp).toHaveBeenCalledWith('payment-service')
      expect(screen.getByText(/test_sec_key_123/i)).toBeTruthy()
    })
  })

  it('submits a snippet scan with local code', async () => {
    api.snippet.mockResolvedValue({ scan: { id: 'S-new12345' } })
    renderHome()

    const textarea = screen.getByLabelText(/code snippet/i)
    fireEvent.change(textarea, { target: { value: 'def test(): return open("/tmp/file").read()' } })

    const scanBtn = screen.getByRole('button', { name: /scan for security issues/i })
    fireEvent.click(scanBtn)

    await waitFor(() => {
      expect(api.snippet).toHaveBeenCalledWith('def test(): return open("/tmp/file").read()')
    })
  })
})
