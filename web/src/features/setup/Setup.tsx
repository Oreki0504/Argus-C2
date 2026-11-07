import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Check, Copy, ExternalLink } from 'lucide-react'
import { api, ApiError } from '../../api/client'
import type { ProviderKind, Setup as SetupContract } from '../../api/contracts'
import { Brand, ErrorState, Loading } from '../../components/ui'
import { AppearanceControls } from '../../components/AppearanceControls'
import { usePreferences } from '../../preferences/context'
import { beginSignIn } from '../auth/sign-in'
import { ProviderIcon } from '../auth/ProviderIcon'

const names = { google: 'Google', github: 'GitHub', oidc: 'SSO' }
const applications = {
  google: 'https://console.cloud.google.com/auth/clients',
  github: 'https://github.com/settings/applications/new',
}

function ProviderSetup({
  setup,
  save,
}: {
  setup: SetupContract
  save: (value: SetupContract) => void
}) {
  const { t } = usePreferences()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [enabled, setEnabled] = useState<ProviderKind[]>(() =>
    setup.providers.length ? setup.providers.map((p) => p.kind) : ['github'],
  )
  const [clientIDs, setClientIDs] = useState<Partial<Record<ProviderKind, string>>>(() =>
    Object.fromEntries(setup.providers.map((p) => [p.kind, p.client_id])),
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [copied, setCopied] = useState<ProviderKind | null>(null)
  const toggle = (kind: ProviderKind) =>
    setEnabled((current) =>
      current.includes(kind) ? current.filter((p) => p !== kind) : [...current, kind],
    )
  return (
    <form
      className="provider-setup"
      onSubmit={async (event) => {
        event.preventDefault()
        const form = event.currentTarget
        const fields = new FormData(form)
        const button = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null
        const selected = enabled.find((kind) => kind === button?.value) ?? enabled[0]
        if (!selected) return
        const providers = enabled.map((kind) => ({
          kind,
          issuer: kind === 'oidc' ? String(fields.get('oidc-issuer') ?? '').trim() : '',
          client_id: String(fields.get(`${kind}-client_id`) ?? '').trim(),
          client_secret: String(fields.get(`${kind}-client_secret`) ?? '').trim(),
        }))
        for (const kind of enabled)
          (form.elements.namedItem(`${kind}-client_secret`) as HTMLInputElement).value = ''
        setBusy(true)
        setError(null)
        try {
          const saved = await api.provider({ providers }, setup.csrf_token)
          save(saved)
          await beginSignIn(saved.csrf_token, true, selected, client, navigate)
        } catch (caught) {
          setError(caught)
        } finally {
          setBusy(false)
        }
      }}
    >
      <p className="muted">
        {t('Enable one or both. Sign in below to bind your first administrator.')}
      </p>
      <div className="provider-choices">
        {(['github', 'google'] as const).map((kind) => (
          <label
            key={kind}
            className={`provider-choice ${enabled.includes(kind) ? 'selected' : ''}`}
          >
            <ProviderIcon kind={kind} />
            <strong>{names[kind]}</strong>
            <input
              type="checkbox"
              checked={enabled.includes(kind)}
              onChange={() => toggle(kind)}
              disabled={busy}
              aria-label={t('Enable {provider}', { provider: names[kind] })}
            />
          </label>
        ))}
      </div>
      <details className="other-provider" open={enabled.includes('oidc') || undefined}>
        <summary>{t('Other identity provider (Auth0 / OIDC)')}</summary>
        <label className="oidc-choice">
          <input
            type="checkbox"
            checked={enabled.includes('oidc')}
            onChange={() => toggle('oidc')}
            disabled={busy}
          />
          {t('Enable custom SSO')}
        </label>
      </details>
      <div className="provider-fields">
        {enabled.map((kind) => {
          const saved = setup.providers.find((p) => p.kind === kind)
          const sameClient = saved && saved.client_id === clientIDs[kind]
          return (
            <fieldset key={kind} className="provider-fieldset" disabled={busy}>
              <legend>{names[kind]}</legend>
              {kind !== 'oidc' && (
                <a
                  className="provider-app-link"
                  href={applications[kind]}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t('Create OAuth app')}
                  <ExternalLink size={13} />
                </a>
              )}
              {kind === 'oidc' && (
                <>
                  <label htmlFor="oidc-issuer">{t('Issuer URL')}</label>
                  <input
                    id="oidc-issuer"
                    name="oidc-issuer"
                    type="url"
                    required
                    pattern="https://.+"
                    defaultValue={saved?.issuer}
                    placeholder="https://your-tenant.auth0.com/"
                  />
                </>
              )}
              <label htmlFor={`${kind}-callback`}>{t('Callback URL')}</label>
              <div className="callback-control">
                <input id={`${kind}-callback`} value={setup.callback_uris[kind]} readOnly />
                <button
                  type="button"
                  className="button"
                  aria-label={t('Copy {provider} callback URL', { provider: names[kind] })}
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(setup.callback_uris[kind])
                      setCopied(kind)
                    } catch (caught) {
                      setError(caught)
                    }
                  }}
                >
                  {copied === kind ? <Check size={15} /> : <Copy size={15} />}
                </button>
              </div>
              <label htmlFor={`${kind}-client-id`}>{names[kind]} Client ID</label>
              <input
                id={`${kind}-client-id`}
                name={`${kind}-client_id`}
                required
                maxLength={512}
                autoComplete="off"
                value={clientIDs[kind] ?? ''}
                onChange={(event) =>
                  setClientIDs((current) => ({ ...current, [kind]: event.target.value }))
                }
              />
              <label htmlFor={`${kind}-client-secret`}>{names[kind]} Client Secret</label>
              <input
                id={`${kind}-client-secret`}
                name={`${kind}-client_secret`}
                type="password"
                maxLength={4096}
                autoComplete="off"
                required={kind !== 'oidc' && !sameClient}
                placeholder={sameClient ? t('Saved — leave blank to keep') : ''}
              />
            </fieldset>
          )
        })}
      </div>
      {error !== null && <ErrorState error={error} />}
      <div className="setup-bind-actions">
        {enabled.map((kind) => (
          <button
            key={kind}
            className="button social-button"
            type="submit"
            value={kind}
            disabled={busy}
          >
            <ProviderIcon kind={kind} />
            {busy ? t('Connecting…') : t('Bind with {provider}', { provider: names[kind] })}
            <ArrowRight size={16} />
          </button>
        ))}
      </div>
      <p className="field-hint">
        {t(
          'Application credentials are configured once. Future visits only need a sign-in button.',
        )}
      </p>
    </form>
  )
}

export function SetupPage() {
  const { t } = usePreferences()
  const client = useQueryClient()
  const status = useQuery({
    queryKey: ['auth-status'],
    queryFn: ({ signal }) => api.authStatus(signal),
  })
  const resume = useQuery({
    queryKey: ['setup'],
    queryFn: ({ signal }) => api.setup(signal),
    enabled: status.data?.state === 'SETUP_PENDING',
    retry: false,
  })
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const setup = resume.data
  const save = (data: SetupContract) => client.setQueryData(['setup'], data)
  if (status.isPending || (status.data?.state === 'SETUP_PENDING' && resume.isPending))
    return <Loading label="Checking setup state" />
  if (status.isError)
    return (
      <main className="standalone">
        <ErrorState error={status.error} retry={() => void status.refetch()} />
      </main>
    )
  if (!status.data) return null
  if (status.data.state !== 'SETUP_PENDING')
    return (
      <main className="setup-closed">
        <Brand />
        <h1>
          {t(
            status.data.state === 'ACTIVE'
              ? 'Your console is already set up'
              : 'Waiting for the server owner',
          )}
        </h1>
        <p>
          {t(
            status.data.state === 'ACTIVE'
              ? 'Sign in with your linked account.'
              : 'Generate a one-time setup code on the server to get started.',
          )}
        </p>
        <Link className="button primary" to="/login">
          {t('Return to sign in')}
        </Link>
      </main>
    )
  if (resume.isError && !(resume.error instanceof ApiError && resume.error.status === 401))
    return (
      <main className="standalone">
        <ErrorState error={resume.error} retry={() => void resume.refetch()} />
      </main>
    )
  return (
    <main className="setup-layout setup-simple">
      <header className="setup-header">
        <Brand />
        <div className="setup-header-actions">
          <AppearanceControls />
          <Link to="/login">
            <ArrowLeft size={16} />
            {t('Back to sign in')}
          </Link>
        </div>
      </header>
      <div className="setup-intro">
        <h1>{t('Set up your console')}</h1>
        <p>{t('Verify ownership, then bind your Google or GitHub account.')}</p>
      </div>
      <ol className="setup-progress" aria-label={t('Setup progress')}>
        {['Verify ownership', 'Bind administrator'].map((label, index) => (
          <li key={label} aria-current={index === (setup ? 1 : 0) ? 'step' : undefined}>
            <span>{setup && index === 0 ? <Check size={14} /> : index + 1}</span>
            {t(label)}
          </li>
        ))}
      </ol>
      <section className="setup-panel">
        <h2>{t(setup ? 'Choose your sign-in methods' : 'Verify console ownership')}</h2>
        {setup ? (
          <ProviderSetup setup={setup} save={save} />
        ) : (
          <form
            onSubmit={async (event) => {
              event.preventDefault()
              const input = event.currentTarget.elements.namedItem('secret') as HTMLInputElement
              const secret = input.value.trim()
              input.value = ''
              setBusy(true)
              setError(null)
              try {
                save(await api.prove(secret, status.data.csrf_token))
              } catch (caught) {
                setError(caught)
              } finally {
                setBusy(false)
              }
            }}
          >
            <p className="muted">
              {t('Enter the setup code shown in your server’s installation terminal.')}
            </p>
            <label htmlFor="secret">{t('Bootstrap secret')}</label>
            <input
              id="secret"
              name="secret"
              type="password"
              autoComplete="off"
              spellCheck={false}
              required
              pattern="[a-fA-F0-9]{64}"
              minLength={64}
              maxLength={64}
              placeholder={t('64-character setup code')}
            />
            {error !== null && <ErrorState error={error} />}
            <button className="button primary" disabled={busy}>
              {t(busy ? 'Verifying…' : 'Verify & continue')}
              <ArrowRight size={16} />
            </button>
          </form>
        )}
      </section>
    </main>
  )
}
