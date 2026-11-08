import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { Brand, ErrorState, Loading } from '../../components/ui'
import { AppearanceControls } from '../../components/AppearanceControls'
import { usePreferences } from '../../preferences/context'
import { TokenSignIn } from '../auth/TokenSignIn'

export function SetupPage() {
  const { t } = usePreferences()
  const status = useQuery({
    queryKey: ['auth-status'],
    queryFn: ({ signal }) => api.authStatus(signal),
  })
  return (
    <main className="setup-layout setup-simple">
      <header className="setup-header">
        <Brand />
        <div className="setup-header-actions">
          <AppearanceControls />
          <Link to="/">{t('Back to overview')}</Link>
        </div>
      </header>
      <section className="setup-panel">
        <h1>{t('Enter your administrator token')}</h1>
        <p className="muted">
          {t(
            'Use the random token from your installation terminal to enter the console. OAuth can be linked later.',
          )}
        </p>
        {status.isPending ? (
          <Loading label="Checking console" />
        ) : status.isError ? (
          <ErrorState error={status.error} retry={() => void status.refetch()} />
        ) : (
          <>
            <TokenSignIn csrf={status.data.csrf_token} />
            {!status.data.token_enabled && status.data.state !== 'ACTIVE' && (
              <div className="token-help">
                <p>
                  {t(
                    'No current login token? Run this command on your server, then read the new token file and refresh this page.',
                  )}
                </p>
                <code>
                  sudo /usr/local/libexec/argus-c2/server console-token issue -config
                  /etc/argus-c2/server-local.json -out /etc/argus-c2/setup/console-new.token
                </code>
                <p>
                  {t(
                    'Use a new output filename each time. Previously issued tokens and setup sessions will be invalidated.',
                  )}
                </p>
              </div>
            )}
          </>
        )}
        <Link className="text-link" to="/login">
          {t('Return to sign in')}
        </Link>
      </section>
    </main>
  )
}
