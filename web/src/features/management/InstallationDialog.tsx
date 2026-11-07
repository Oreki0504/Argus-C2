import { useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Copy, Terminal } from 'lucide-react'
import { management } from '../../api/management'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { ErrorState, Loading, Notice } from '../../components/ui'
import { useNow } from '../fleet/useSummary'
import { uncertainWrite, useManagement } from './hooks'
import { Dialog, MutationError } from './shared'
import { installCommand } from './install-command'

export function EnrollmentModes({
  manual,
  onChange,
  disabled = false,
}: {
  manual: boolean
  onChange: () => void
  disabled?: boolean
}) {
  const { t } = usePreferences()
  return (
    <div className="enrollment-modes" role="group" aria-label={t('Enrollment method')}>
      <button
        type="button"
        aria-pressed={!manual}
        disabled={disabled}
        onClick={() => manual && onChange()}
      >
        {t('Install command')}
      </button>
      <button
        type="button"
        aria-pressed={manual}
        disabled={disabled}
        onClick={() => !manual && onChange()}
      >
        {t('Manual enrollment')}
      </button>
    </div>
  )
}

export function InstallationDialog({
  onClose,
  onManual,
}: {
  onClose: () => void
  onManual: () => void
}) {
  const { t } = usePreferences()
  const { identity, key, refresh } = useManagement()
  const { timestampLabel } = useFormat()
  const now = useNow()
  const input = useRef<HTMLTextAreaElement>(null)
  const [tool, setTool] = useState<'curl' | 'wget'>('curl')
  const [copyState, setCopyState] = useState('')
  const status = useQuery({
    queryKey: [...key, 'installer'],
    queryFn: ({ signal }) => management.installer(signal),
  })
  const mutation = useMutation({
    mutationFn: (ttl: number) => management.install(ttl, identity.csrf_token),
    onSuccess: () => {
      void refresh()
    },
    gcTime: 0,
    retry: false,
  })
  const result = mutation.data
  const expired = !!result && now >= result.expires_at
  const command = result && !expired ? installCommand(result.url, tool) : ''
  async function copy() {
    if (!command) return
    try {
      await navigator.clipboard.writeText(command)
      setCopyState('Copied')
    } catch {
      input.current?.focus()
      input.current?.select()
      setCopyState('Copy the selected command manually.')
    }
  }
  return (
    <Dialog title={t('Add agent')} onClose={onClose} busy={mutation.isPending}>
      {import.meta.env.DEV && import.meta.env.MODE === 'mock' && (
        <Notice>{t('Preview only: this sample command cannot install an Agent.')}</Notice>
      )}
      {!result ? (
        <>
          <EnrollmentModes manual={false} onChange={onManual} disabled={mutation.isPending} />
          {status.isPending ? (
            <Loading label="Loading installer" />
          ) : status.isError ? (
            <ErrorState error={status.error} retry={() => void status.refetch()} />
          ) : !status.data.enabled ? (
            <Notice>
              {t(
                'Automatic installation is not configured. Ask the server operator to publish Agent binaries and configure the Fleet address, or use manual enrollment.',
              )}
            </Notice>
          ) : (
            <form
              className="management-form"
              onSubmit={(event) => {
                event.preventDefault()
                mutation.mutate(Number(new FormData(event.currentTarget).get('ttl')) * 60)
              }}
            >
              <p className="form-intro">
                {t(
                  'Paste one command on a new server to download, configure, enroll and start its Agent.',
                )}
              </p>
              <div className="installer-target">
                <Terminal size={18} aria-hidden="true" />
                <div>
                  <strong>Linux · systemd</strong>
                  <span>
                    {status.data.platforms
                      .map((p) => (p === 'linux/amd64' ? 'x86_64' : 'ARM64'))
                      .join(' / ')}{' '}
                    · {status.data.fleet_origin}
                  </span>
                </div>
              </div>
              <p className="field-hint">
                {t(
                  'Requires root or sudo. The service runs as argus-agent. Existing installations are preserved; only system information and metrics are allowed by default.',
                )}
              </p>
              <label htmlFor="install-ttl">{t('Command lifetime (minutes)')}</label>
              <input
                id="install-ttl"
                name="ttl"
                type="number"
                min={1}
                max={60}
                step={1}
                defaultValue={15}
                required
              />
              <MutationError error={mutation.error} />
              <div className="dialog-actions">
                <button
                  type="button"
                  className="button secondary"
                  disabled={mutation.isPending}
                  onClick={onClose}
                >
                  {t('Cancel')}
                </button>
                <button
                  className="button primary"
                  disabled={mutation.isPending || uncertainWrite(mutation.error)}
                >
                  {t(mutation.isPending ? 'Submitting…' : 'Generate install command')}
                </button>
              </div>
            </form>
          )}
        </>
      ) : (
        <div className="enrollment-result">
          <Notice kind={expired ? 'warning' : 'info'}>
            {t(
              expired
                ? 'This command has expired. Close this dialog to create another.'
                : 'For one new server. Keep this command private; its link can be downloaded only once.',
            )}
          </Notice>
          <div className="install-command-toolbar">
            <label htmlFor="install-command">{t('Run on the agent machine')}</label>
            <select
              aria-label={t('Download tool')}
              value={tool}
              onChange={(event) => {
                setTool(event.target.value as 'curl' | 'wget')
                setCopyState('')
              }}
            >
              <option value="curl">curl</option>
              <option value="wget">wget</option>
            </select>
          </div>
          <textarea
            id="install-command"
            className="install-command"
            ref={input}
            readOnly
            value={command}
            rows={6}
            spellCheck={false}
            autoComplete="off"
          />
          <div className="token-actions">
            <button className="button secondary" disabled={expired} onClick={() => void copy()}>
              <Copy size={15} />
              {t('Copy command')}
            </button>
            <span role="status">{t(copyState)}</span>
          </div>
          <p className="field-hint">
            {t('Expires')} {timestampLabel(result.expires_at)}
          </p>
          <p className="field-hint">
            {t(
              'The script downloads completely before it runs. After installation, refresh Agents to check the first heartbeat. Closing this dialog removes the command.',
            )}
          </p>
          <div className="dialog-actions">
            <button className="button primary" onClick={onClose}>
              {t('Done')}
            </button>
          </div>
        </div>
      )}
    </Dialog>
  )
}
