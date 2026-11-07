import { usePreferences } from '../../preferences/context'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowRight } from 'lucide-react'
import { ErrorState } from '../../components/ui'
import { clearSession } from '../../api/query'
import { api } from '../../api/client'

// The server starts a login transaction and returns a fixed same-origin
// navigation path. It owns provider redirects, state, nonce and PKCE.
export function OIDCForm({ csrf, setup = false }: { csrf: string; setup?: boolean }) {
  const { t } = usePreferences()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const action = setup ? '/v1/console/setup/bind' : '/v1/console/auth/login'
  return (
    <>
      <form
        onSubmit={async (event) => {
          event.preventDefault()
          setBusy(true)
          setError(null)
          try {
            if (import.meta.env.DEV && import.meta.env.MODE === 'mock') {
              const { simulateOIDC } = await import('../../mocks/browser')
              await simulateOIDC(action, csrf)
              await clearSession(client)
              navigate('/', { replace: true })
            } else {
              const start = await api.beginOIDC(csrf, setup)
              window.location.assign(start.redirect_path)
            }
          } catch (error) {
            setError(error)
          } finally {
            setBusy(false)
          }
        }}
      >
        <button className="button primary wide" disabled={busy} type="submit">
          {t(busy ? 'Connecting…' : setup ? 'Verify identity & activate' : 'Continue with SSO')}
          <ArrowRight size={17} />
        </button>
      </form>
      {error !== null && <ErrorState error={error} />}
    </>
  )
}
