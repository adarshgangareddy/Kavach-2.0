import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api.js'
import { EffectsProvider } from '../components/effects.jsx'
import Welcome from './Welcome.jsx'

// Mock api methods
vi.mock('../api.js', () => ({
  api: {
    health: vi.fn().mockResolvedValue({ status: 'ok', signup: true }),
    login: vi.fn().mockResolvedValue({ id: 'u1', email: 'test@example.com', role: 'developer' }),
    register: vi.fn().mockResolvedValue({ id: 'u1', email: 'test@example.com', role: 'developer' }),
  },
}))

function renderWelcome(ui = <Welcome />) {
  return render(
    <EffectsProvider detectWebGL={() => true}>
      {ui}
    </EffectsProvider>,
  )
}

describe('Welcome Component (Public Homepage & Welcome Experience)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.health.mockResolvedValue({ status: 'ok', signup: true })
    api.login.mockResolvedValue({ id: 'u1', email: 'test@example.com', role: 'developer' })
    api.register.mockResolvedValue({ id: 'u1', email: 'test@example.com', role: 'developer' })
  })
  afterEach(() => {
    cleanup()
  })

  it('renders the public hero headline, description, and primary/secondary CTAs', () => {
    renderWelcome()
    expect(screen.getByRole('heading', { level: 1, name: /find security flaws before they reach production/i })).toBeTruthy()
    expect(screen.getByRole('link', { name: /continue locally/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /continue with github/i })).toBeTruthy()
  })

  it('renders the 3-step "How Kavach works" and transparent privacy sections', () => {
    renderWelcome()
    expect(screen.getByRole('heading', { name: /from raw input to verified fix in three steps/i })).toBeTruthy()
    expect(screen.getByText(/local cli requires no account/i)).toBeTruthy()
    expect(screen.getByRole('heading', { name: /transparent data boundaries by design/i })).toBeTruthy()
    expect(screen.getByText(/local processing/i)).toBeTruthy()
  })

  it('renders the illustrative glass preview panels with high contrast code and verified patch', () => {
    const { container } = renderWelcome()
    expect(screen.getByText(/illustrative preview/i)).toBeTruthy()
    expect(container.querySelector('.code-filename').textContent).toContain('documents.py')
    expect(screen.getByText(/suggested fix/i)).toBeTruthy()
  })

  it('switches vulnerability class in the local interactive explorer', () => {
    renderWelcome()
    const cmdInjBtn = screen.getByRole('tab', { name: /command injection/i })
    fireEvent.click(cmdInjBtn)
    expect(screen.getAllByText(/app\/utils\/compress\.py/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/CWE-78/i).length).toBeGreaterThan(0)
  })

  it('opens GitHub auth dialog and displays clean unconfigured notice', () => {
    renderWelcome()
    const ghBtn = screen.getByRole('button', { name: /continue with github/i })
    fireEvent.click(ghBtn)

    expect(screen.getByRole('dialog')).toBeTruthy()
    expect(screen.getByRole('heading', { level: 2, name: /sign in with github/i })).toBeTruthy()
    expect(screen.getByText(/first-time sign-in/i)).toBeTruthy()
    expect(screen.getAllByText(/github sign-in is not configured yet/i).length).toBeGreaterThan(0)
    expect(screen.getByRole('link', { name: /continue locally \(no account\)/i })).toBeTruthy()
  })

  it('supports switching to email/password authentication tab', () => {
    const onSignedIn = vi.fn()
    const { container } = renderWelcome(<Welcome onSignedIn={onSignedIn} initialAuth={true} />)

    const emailTabBtn = screen.getByRole('tab', { name: /email & password/i })
    fireEvent.click(emailTabBtn)

    expect(screen.getByLabelText(/^email$/i)).toBeTruthy()
    expect(screen.getByLabelText(/^password$/i)).toBeTruthy()
    expect(container.querySelector('button[type="submit"]')).toBeTruthy()
  })
})
