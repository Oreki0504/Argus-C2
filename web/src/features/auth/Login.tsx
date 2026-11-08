import { usePreferences } from '../../preferences/context'
import { AppearanceControls } from '../../components/AppearanceControls'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../../api/client'
import { Brand, ErrorState, Loading, Notice } from '../../components/ui'
import { OIDCForm } from './OIDCForm'
import { TokenSignIn } from './TokenSignIn'

const reasons = new Set([
  'session_expired',
  'forbidden',
  'oidc_callback_invalid',
  'oidc_unavailable',
  'account_pending',
  'service_unavailable',
])
export function Login() {
  const { t } = usePreferences()
  const [params] = useSearchParams()
  const status = useQuery({
    queryKey: ['auth-status'],
    queryFn: ({ signal }) => api.authStatus(signal),
  })
  const reason = params.get('reason')
  return (
    <main className="auth-layout">
      <section className="auth-story">
        <Brand />
        <div className="auth-story-copy">
          <span className="eyebrow">{t('VISIBILITY, WITH BOUNDARIES')}</span>
          <h1>
            {t('Your fleet.')}
            <br />
            {t('A clearer picture.')}
          </h1>
          <p>
            {t(
              'A focused workspace for authorized Linux fleet diagnostics. From the first heartbeat to the latest observation.',
            )}
          </p>
          <div className="auth-illustration" aria-hidden="true">
            <span />
            <span />
            <span />
            <ShieldCheck size={56} strokeWidth={1} />
          </div>
        </div>
        <p className="auth-footnote">
          ARGUS C2 <span>FLEET CONSOLE / 01</span>
        </p>
      </section>
      <section className="auth-content">
        <div className="auth-appearance">
          <AppearanceControls />
        </div>
        <Link className="login-back" to="/">
          <ArrowLeft size={15} />
          {t('Back to overview')}
        </Link>
        <div className="auth-card">
          <span className="eyebrow">{t('WELCOME TO ARGUS')}</span>
          <h2>{t('Sign in to your console')}</h2>
          <p className="muted">{t('Choose how you want to sign in.')}</p>
          {reason && reasons.has(reason) && (
            <Notice kind="warning">{t(new ApiError(401, reason).message)}</Notice>
          )}
          {status.isPending ? (
            <Loading label="Checking console" />
          ) : status.isError ? (
            <ErrorState error={status.error} retry={() => void status.refetch()} />
          ) : (
            <>
              {status.data.state === 'ACTIVE' &&
                (status.data.providers.length > 0 || status.data.provider_name) && (
                  <OIDCForm
                    csrf={status.data.csrf_token}
                    providers={status.data.providers.length ? status.data.providers : undefined}
                  />
                )}
              {(status.data.token_enabled || status.data.state !== 'ACTIVE') && (
                <TokenSignIn csrf={status.data.csrf_token} />
              )}
              {status.data.state !== 'ACTIVE' && (
                <>
                  <p className="auth-help">
                    {t(
                      'Use the random token from your installation terminal to enter the console. OAuth can be linked later.',
                    )}
                  </p>
                  <Link className="text-link" to="/setup">
                    {t('Token setup help')}
                  </Link>
                </>
              )}
            </>
          )}
          <div className="auth-security">
            <ShieldCheck size={16} />
            {t('Your login stays on this Console. Link OAuth later in account settings.')}
          </div>
        </div>
        <p className="auth-bottom">{t('Secure access. Purposeful diagnostics.')}</p>
      </section>
    </main>
  )
}
