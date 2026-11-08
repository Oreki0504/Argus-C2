import { useState } from 'react'
import { Check, Copy, ExternalLink } from 'lucide-react'
import { api } from '../../api/client'
import type { ProviderKind, Setup as SetupContract } from '../../api/contracts'
import { ErrorState } from '../../components/ui'
import { usePreferences } from '../../preferences/context'
import { ProviderIcon } from '../auth/ProviderIcon'

const names = { google: 'Google', github: 'GitHub', oidc: 'SSO' }
const applications = {
  google: 'https://console.cloud.google.com/auth/clients',
  github: 'https://github.com/settings/applications/new',
}

export function ProviderSettings({
  setup,
  save,
}: {
  setup: SetupContract
  save: (value: SetupContract) => void
}) {
  const { t } = usePreferences()
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
        if (!enabled.length) return
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
          const saved = await api.accountProvider({ providers }, setup.csrf_token)
          save(saved)
        } catch (caught) {
          setError(caught)
        } finally {
          setBusy(false)
        }
      }}
    >
      <p className="muted">
        {t('OAuth is optional. Configure providers here, then bind your account above.')}
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
        <button className="button primary" type="submit" disabled={busy || !enabled.length}>
          {busy ? t('Saving…') : t('Save sign-in methods')}
        </button>
      </div>
      <p className="field-hint">
        {t(
          'Application credentials are configured once. Future visits only need a sign-in button.',
        )}
      </p>
    </form>
  )
}
