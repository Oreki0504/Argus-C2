import { usePreferences } from '../../preferences/context'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowRight } from 'lucide-react'
import { ErrorState } from '../../components/ui'
import type { LoginProvider } from '../../api/contracts'
import { ProviderIcon } from './ProviderIcon'
import { beginSignIn } from './sign-in'

// The server starts a login transaction and returns a fixed same-origin
// navigation path. It owns provider redirects, state, nonce and PKCE.
export function OIDCForm({
  csrf,
  setup = false,
  providers = [{ kind: 'oidc', name: 'SSO' }],
}: {
  csrf: string
  setup?: boolean
  providers?: LoginProvider[]
}) {
  const { t } = usePreferences()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  return (
    <>
      <form
        className="social-sign-in"
        onSubmit={async (event) => {
          event.preventDefault()
          setBusy(true)
          setError(null)
          try {
            const button = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null
            const provider = providers.find((item) => item.kind === button?.value) ?? providers[0]
            if (provider) await beginSignIn(csrf, setup, provider.kind, client, navigate)
          } catch (error) {
            setError(error)
          } finally {
            setBusy(false)
          }
        }}
      >
        {providers.map((provider) => (
          <button
            key={provider.kind}
            className="button social-button wide"
            disabled={busy}
            type="submit"
            value={provider.kind}
          >
            <ProviderIcon kind={provider.kind} />
            {busy
              ? t('Connecting…')
              : provider.kind === 'oidc'
                ? t(setup ? 'Verify identity & activate' : 'Continue with SSO')
                : t('Continue with {provider}', { provider: provider.name })}
            <ArrowRight size={17} />
          </button>
        ))}
      </form>
      {error !== null && <ErrorState error={error} />}
    </>
  )
}
