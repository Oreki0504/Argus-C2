import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { LogOut, UserRound } from 'lucide-react'
import { api } from '../api/client'
import { clearSession } from '../api/query'
import { useViewer } from '../features/auth/context'
import { Brand, ErrorState } from './ui'
import { AppearanceControls } from './AppearanceControls'
import { usePreferences } from '../preferences/context'
import { hasManagement } from '../features/management/access'

const links = [
  { to: '/', label: 'Overview' },
  { to: '/traffic', label: 'Traffic' },
  { to: '/manage', label: 'Management' },
]
export function AppShell() {
  const { t } = usePreferences()
  const identity = useViewer()
  const admin = identity?.role === 'Admin'
  const client = useQueryClient()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  async function logout() {
    if (!identity) return
    setBusy(true)
    setError(null)
    await client.cancelQueries({ queryKey: ['console'] })
    client.removeQueries({ queryKey: ['console'] })
    try {
      await api.logout(identity.csrf_token)
      await clearSession(client)
      navigate('/', { replace: true })
    } catch (error) {
      setError(error)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className={`viewer-shell ${admin ? 'admin-viewer' : ''}`}>
      <a href="#main-content" className="skip-link">
        {t('Skip to content')}
      </a>
      <header className="viewer-header">
        <div className="viewer-header-inner">
          <Link to="/" aria-label="ARGUS">
            <Brand compact />
          </Link>
          {admin ? (
            <nav className="header-navigation" aria-label={t('Main navigation')}>
              {links
                .filter((link) => link.to !== '/manage' || hasManagement(identity))
                .map(({ to, label }) => (
                  <NavLink key={to} to={to} end={to === '/'}>
                    {t(label)}
                  </NavLink>
                ))}
            </nav>
          ) : (
            <span className="viewer-product">{t('Fleet monitor')}</span>
          )}
          <div className="viewer-account">
            <AppearanceControls />
            {identity ? (
              <>
                <Link
                  to="/account"
                  className="account-link"
                  aria-label={`${t('Account & sign-in')}: ${identity.name}`}
                >
                  <UserRound size={16} aria-hidden="true" />
                  <span className="viewer-name">{identity.name}</span>
                </Link>
                {admin && <span className="role-badge">{t('Administrator')}</span>}
                <button className="login-link" disabled={busy} onClick={() => void logout()}>
                  <LogOut size={15} />
                  {t('Sign out')}
                </button>
              </>
            ) : (
              <Link to="/login" className="login-link">
                {t('Log in')}
              </Link>
            )}
          </div>
        </div>
      </header>
      <main id="main-content" tabIndex={-1}>
        {error !== null ? (
          <ErrorState error={error} retry={() => void logout()} />
        ) : busy ? (
          <p role="status">{t('Signing out…')}</p>
        ) : (
          <Outlet />
        )}
      </main>
      <footer className="viewer-footer">
        <span>
          ARGUS <span aria-hidden="true">/</span> {t('Fleet observability')}
        </span>
        <span>{t('Public summaries · Local time')}</span>
      </footer>
    </div>
  )
}
