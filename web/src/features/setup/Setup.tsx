import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Check, KeyRound, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../../api/client'
import type { Setup as SetupContract } from '../../api/contracts'
import { Brand, ErrorState, Loading, Notice } from '../../components/ui'
import { OIDCForm } from '../auth/OIDCForm'

export function SetupPage() {
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
  const [editingProvider, setEditingProvider] = useState(false)
  const setup = resume.data
  const step = setup?.step === 'bind' && !editingProvider ? 2 : setup ? 1 : 0
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
          {status.data.state === 'ACTIVE'
            ? 'Your console is already set up'
            : 'Waiting for the server owner'}
        </h1>
        <p>
          {status.data.state === 'ACTIVE'
            ? 'First-run setup is closed. Sign in with your identity provider.'
            : 'Generate a one-time bootstrap secret using the local server setup command before continuing.'}
        </p>
        <Link className="button primary" to="/login">
          Return to sign in
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
    <main className="setup-layout">
      <header className="setup-header">
        <Brand />
        <Link to="/login">
          <ArrowLeft size={16} />
          Back to sign in
        </Link>
      </header>
      <div className="setup-intro">
        <p className="eyebrow">FIRST-RUN SETUP</p>
        <h1>A secure start for your fleet.</h1>
        <p>Connect your identity provider and establish your first administrator.</p>
      </div>
      <div className="setup-workspace">
        <nav aria-label="Setup progress">
          <ol className="steps">
            {['Verify ownership', 'Connect identity provider', 'Bind administrator'].map(
              (label, index) => (
                <li
                  key={label}
                  aria-current={index === step ? 'step' : undefined}
                  className={index < step ? 'complete' : index === step ? 'current' : ''}
                >
                  <span>{index < step ? <Check size={16} /> : `0${index + 1}`}</span>
                  <div>
                    {label}
                    <small>
                      {
                        [
                          'One-time local setup secret',
                          'OIDC provider configuration',
                          'Verify your organization identity',
                        ][index]
                      }
                    </small>
                  </div>
                </li>
              ),
            )}
          </ol>
          <div className="setup-sidebar-note">
            <ShieldCheck size={20} />
            <p>Setup closes automatically after your first administrator is bound.</p>
          </div>
        </nav>
        <section className="setup-panel">
          <span className="step-icon">{step === 0 ? <KeyRound /> : <ShieldCheck />}</span>
          <p className="eyebrow">STEP 0{step + 1} OF 03</p>
          <h2>
            {['Verify console ownership', 'Connect your identity provider', 'Make it yours'][step]}
          </h2>
          {error !== null && <ErrorState error={error} />}
          {step === 0 && (
            <form
              onSubmit={async (event) => {
                event.preventDefault()
                const form = event.currentTarget
                const secret = String(new FormData(form).get('secret') ?? '')
                form.reset()
                setBusy(true)
                setError(null)
                try {
                  save(await api.prove(secret, status.data.csrf_token))
                } catch (error) {
                  setError(error)
                } finally {
                  setBusy(false)
                }
              }}
            >
              <p className="muted">
                Enter the one-time setup secret generated locally by the server owner.
              </p>
              <label htmlFor="secret">Bootstrap secret</label>
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
                placeholder="64-character setup secret"
                aria-describedby="secret-help"
              />
              <p className="field-hint" id="secret-help">
                Short-lived and single-use. This is not your CLI admin token.
              </p>
              <Notice>
                The secret establishes setup access. Your administrator identity is verified in the
                final step.
              </Notice>
              <button className="button primary" disabled={busy}>
                {busy ? 'Verifying…' : 'Verify & continue'}
                <ArrowRight size={16} />
              </button>
            </form>
          )}
          {step === 1 && setup && (
            <form
              onSubmit={async (event) => {
                event.preventDefault()
                const form = event.currentTarget
                const fields = new FormData(form)
                const body = {
                  issuer: String(fields.get('issuer')),
                  client_id: String(fields.get('client_id')),
                  client_secret: String(fields.get('client_secret') ?? ''),
                }
                const secretInput = form.elements.namedItem('client_secret') as HTMLInputElement
                secretInput.value = ''
                setBusy(true)
                setError(null)
                try {
                  save(await api.provider(body, setup.csrf_token))
                  setEditingProvider(false)
                } catch (error) {
                  setError(error)
                } finally {
                  setBusy(false)
                }
              }}
            >
              <p className="muted">
                Use an OIDC application registered with your organization’s provider.
              </p>
              <label htmlFor="issuer">Issuer URL</label>
              <input
                id="issuer"
                name="issuer"
                type="url"
                required
                pattern="https://.+"
                placeholder="https://identity.example.com"
                defaultValue={setup.issuer}
              />
              <label htmlFor="client-id">Client ID</label>
              <input
                id="client-id"
                name="client_id"
                required
                maxLength={512}
                defaultValue={setup.client_id}
                autoComplete="off"
              />
              <label htmlFor="client-secret">
                Client secret <span className="muted">(if required)</span>
              </label>
              <input
                id="client-secret"
                name="client_secret"
                type="password"
                maxLength={4096}
                autoComplete="off"
              />
              <label htmlFor="callback">Redirect URI</label>
              <input id="callback" value={setup.callback_uri} readOnly />
              <p className="field-hint">
                Register this exact URI with your provider. It is supplied by the Console server.
              </p>
              <button className="button primary" disabled={busy}>
                {busy ? 'Validating provider…' : 'Validate & continue'}
                <ArrowRight size={16} />
              </button>
            </form>
          )}
          {step === 2 && setup && (
            <>
              <p className="muted">
                Sign in to verify the identity that will become the first administrator of this
                console.
              </p>
              <dl className="detail-list">
                <div>
                  <dt>Identity provider</dt>
                  <dd>{setup.issuer}</dd>
                </div>
                <div>
                  <dt>Assigned role</dt>
                  <dd>
                    <span className="role-badge">Admin</span>
                  </dd>
                </div>
              </dl>
              <Notice>
                Activation completes only after the server verifies your identity. Your setup secret
                and setup session are then revoked.
              </Notice>
              <OIDCForm setup csrf={setup.csrf_token} />
              <button className="text-action" onClick={() => setEditingProvider(true)}>
                Change identity provider settings
              </button>
            </>
          )}
        </section>
      </div>
    </main>
  )
}
