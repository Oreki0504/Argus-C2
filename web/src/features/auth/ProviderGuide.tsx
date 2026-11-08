import { ExternalLink } from 'lucide-react'
import { usePreferences } from '../../preferences/context'

export function ProviderGuide({ kind, callback }: { kind: 'google' | 'github'; callback: string }) {
  const { t } = usePreferences()
  const github = kind === 'github'
  return (
    <details className="provider-guide">
      <summary>
        {t('How to create a {provider} OAuth app', { provider: github ? 'GitHub' : 'Google' })}
      </summary>
      <ol>
        {github ? (
          <>
            <li>{t('Open GitHub Settings → Developer settings → OAuth Apps → New OAuth App.')}</li>
            <li>
              {t('Set Application name to ARGUS and Homepage URL to:')}
              <code>{new URL(callback).origin}</code>
            </li>
            <li>
              {t(
                'Paste this exact address into Authorization callback URL, then click Register application:',
              )}
              <code>{callback}</code>
            </li>
            <li>
              {t(
                'Copy Client ID. Click Generate a new client secret, then paste both values into the fields below. Device Flow is not required.',
              )}
            </li>
          </>
        ) : (
          <>
            <li>
              {t(
                'In Google Cloud, select or create a project. Open Google Auth Platform and complete Branding with an app name, support email and developer contact.',
              )}
            </li>
            <li>
              {t(
                'Under Audience, choose External for personal Google accounts. If the app is in Testing, add the Google account you will use under Test users.',
              )}
            </li>
            <li>
              {t(
                'Open Clients → Create client. Choose Web application, name it ARGUS, and add this address under Authorized redirect URIs:',
              )}
              <code>{callback}</code>
            </li>
            <li>
              {t(
                'Create the client and copy its Client ID and Client Secret into the fields below. Authorized JavaScript origins are not required for this server login flow.',
              )}
            </li>
          </>
        )}
        <li>
          {t(
            'Click Save sign-in methods here, then Bind with Google or GitHub in the account card in step 2. Complete authorization until the card shows Linked.',
          )}
        </li>
      </ol>
      <p className="field-hint">
        {t(
          'Keep the HTTPS scheme, hostname, port and callback path exactly as shown. If you see redirect_uri_mismatch, compare the full address in both places.',
        )}
      </p>
      {!github && (
        <p className="field-hint">
          {t(
            'Google requires an accepted HTTPS domain for a deployed app; a public IP address is not a valid redirect host. Use a domain for your Console before configuring Google.',
          )}
        </p>
      )}
      <a
        className="provider-app-link"
        href={
          github
            ? 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app'
            : 'https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred'
        }
        target="_blank"
        rel="noreferrer"
      >
        {t('Official setup guide')} <ExternalLink size={13} />
      </a>
    </details>
  )
}
