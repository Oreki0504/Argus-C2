import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { clearSession } from '../../api/query'
import { ErrorState } from '../../components/ui'
import { usePreferences } from '../../preferences/context'

export function TokenSignIn({ csrf }: { csrf: string }) {
  const { t } = usePreferences()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  return (
    <form
      className="token-sign-in"
      onSubmit={async (event) => {
        event.preventDefault()
        const form = event.currentTarget
        const token = String(new FormData(form).get('token') ?? '').trim()
        form.reset()
        setBusy(true)
        setError(null)
        try {
          const identity = await api.tokenLogin(token, csrf)
          await clearSession(client)
          client.setQueryData(['me'], identity)
          await navigate('/manage', { replace: true })
        } catch (caught) {
          setError(caught)
        } finally {
          setBusy(false)
        }
      }}
    >
      <label htmlFor="login-token">{t('Administrator token')}</label>
      <input
        id="login-token"
        name="token"
        type="password"
        autoComplete="current-password"
        required
        maxLength={128}
        disabled={busy}
        placeholder={t('Paste your installation token')}
      />
      {error !== null && <ErrorState error={error} />}
      <button className="button primary wide" disabled={busy} type="submit">
        {t(busy ? 'Signing in…' : 'Enter console')}
      </button>
    </form>
  )
}
