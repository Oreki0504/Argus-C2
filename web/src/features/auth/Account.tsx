import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Navigate, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../../api/client'
import { consoleKey } from '../../api/query'
import { ErrorState, Loading, Notice } from '../../components/ui'
import { usePreferences } from '../../preferences/context'
import { useViewer } from './context'
import { ProviderIcon } from './ProviderIcon'
import { ProviderSettings } from './ProviderSettings'

export function AccountPage() {
  const viewer = useViewer()
  return viewer ? <AccountSettings /> : <Navigate to="/login" replace />
}
function AccountSettings() {
  const viewer = useViewer()!
  const { t } = usePreferences()
  const [params] = useSearchParams()
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [configure, setConfigure] = useState(false)
  const client = useQueryClient()
  const key = [...consoleKey(viewer), 'account']
  const account = useQuery({ queryKey: key, queryFn: ({ signal }) => api.account(signal) })
  const providersKey = [...consoleKey(viewer), 'account-providers']
  const providers = useQuery({
    queryKey: providersKey,
    queryFn: ({ signal }) => api.accountProviders(signal),
    enabled: viewer.role === 'Admin' && configure,
  })
  if (account.isPending) return <Loading label="Loading account" />
  if (account.isError)
    return <ErrorState error={account.error} retry={() => void account.refetch()} />
  const reason = params.get('reason')
  const allowed = [
    'session_expired',
    'identity_conflict',
    'oidc_callback_invalid',
    'oidc_unavailable',
  ]
  return (
    <section className="account-page">
      <h1>{t('Account & sign-in')}</h1>
      <p className="muted">
        {t(
          'Link Google or GitHub to this account. Your permissions and administrator token stay unchanged.',
        )}
      </p>
      {reason && allowed.includes(reason) && (
        <Notice kind="warning">{t(new ApiError(400, reason).message)}</Notice>
      )}
      {params.get('bound') === '1' && <Notice>{t('Account linked successfully.')}</Notice>}
      <div className="account-providers">
        {account.data.providers.map((p) => {
          const linked = account.data.identities.filter((i) => i.issuer === p.issuer)
          return (
            <div className="account-provider" key={p.kind}>
              <ProviderIcon kind={p.kind} />
              <strong>{p.name}</strong>
              <span className="muted">{linked.length ? t('Linked') : t('Not linked')}</span>
              <button
                className="button"
                disabled={busy || linked.length > 0}
                onClick={async () => {
                  setBusy(true)
                  setError(null)
                  try {
                    if (import.meta.env.DEV && import.meta.env.MODE === 'mock') {
                      const { simulateAccountBinding } = await import('../../mocks/browser')
                      await simulateAccountBinding(p.kind, account.data.csrf_token)
                      await account.refetch()
                    } else {
                      const start = await api.bindAccount(p.kind, account.data.csrf_token)
                      window.location.assign(start.redirect_path)
                    }
                  } catch (caught) {
                    setError(caught)
                  } finally {
                    setBusy(false)
                  }
                }}
              >
                {t(linked.length ? 'Linked' : 'Bind with {provider}', { provider: p.name })}
              </button>
            </div>
          )
        })}
        {!account.data.providers.length && (
          <Notice>
            {t('No OAuth providers configured. You can keep using your administrator token.')}
          </Notice>
        )}
      </div>
      {error !== null && <ErrorState error={error} />}
      {viewer.role === 'Admin' && (
        <details
          className="account-configuration"
          onToggle={(event) => setConfigure(event.currentTarget.open)}
        >
          <summary>{t('Configure sign-in providers (optional)')}</summary>
          {configure &&
            (providers.isPending ? (
              <Loading label="Loading providers" />
            ) : providers.isError ? (
              <ErrorState error={providers.error} retry={() => void providers.refetch()} />
            ) : (
              <ProviderSettings
                setup={providers.data}
                save={(data) => {
                  client.setQueryData(providersKey, data)
                  void client.invalidateQueries({ queryKey: key })
                  void client.invalidateQueries({ queryKey: ['auth-status'] })
                }}
              />
            ))}
        </details>
      )}
    </section>
  )
}
