import { uncertainWrite, useListNavigation, useManagement } from './hooks'
import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Copy, MoreHorizontal, Plus, ShieldOff } from 'lucide-react'
import { management } from '../../api/management'
import type { ManagedAgent } from '../../api/management-contracts'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { heartbeat } from '../../lib/format'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { useNow } from '../fleet/useSummary'
import { canManage } from './access'
import { AuditLink, Dialog, MutationError, Pager, SectionHeading } from './shared'
import { InstallationDialog, EnrollmentModes } from './InstallationDialog'

export function AgentsPage() {
  const { t } = usePreferences()
  const { relativeTime, timestampLabel } = useFormat()
  const { identity, key } = useManagement()
  const now = useNow()
  const nav = useListNavigation(['q', 'status'])
  const [adding, setAdding] = useState(false)
  const [selected, setSelected] = useState<ManagedAgent | null>(null)
  const filters = { ...nav.filters, cursor: nav.cursor, limit: 8 }
  const query = useQuery({
    queryKey: [...key, 'agents', filters],
    queryFn: ({ signal }) => management.agents(filters, signal),
  })
  return (
    <>
      <SectionHeading
        title="Agents"
        description="Enroll agents and manage their access to the fleet."
        busy={query.isFetching}
        refresh={() => void query.refetch()}
      >
        {canManage(identity, 'agents:write') && (
          <button className="button primary" onClick={() => setAdding(true)}>
            <Plus size={16} />
            {t('Add agent')}
          </button>
        )}
      </SectionHeading>
      <div className="management-filters">
        <input
          aria-label={t('Search managed agents')}
          placeholder={t('Name, hostname or agent ID')}
          value={nav.filters.q}
          onChange={(event) => nav.change('q', event.target.value)}
        />
        <select
          aria-label={t('Agent access')}
          value={nav.filters.status}
          onChange={(event) => nav.change('status', event.target.value)}
        >
          <option value="">{t('All access states')}</option>
          <option value="active">{t('Active')}</option>
          <option value="disabled">{t('Disabled')}</option>
        </select>
      </div>
      {query.isPending ? (
        <Loading label="Loading agents" />
      ) : query.isError ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : (
        <section className="panel management-table-panel">
          {query.data.items.length ? (
            <div
              className="table-scroll"
              role="region"
              aria-label={t('Managed agents')}
              tabIndex={0}
            >
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t('Agent')}</th>
                    <th scope="col">{t('Access / heartbeat')}</th>
                    <th scope="col">{t('Agent version')}</th>
                    <th scope="col">{t('Certificate expires')}</th>
                    <th scope="col">{t('Actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((agent) => (
                    <tr key={agent.node_id}>
                      <th scope="row">
                        <Link className="text-link" to={`/fleet/${agent.public_id}`}>
                          {agent.display_name}
                        </Link>
                        <small>
                          {agent.hostname} · {agent.node_id}
                        </small>
                      </th>
                      <td>
                        <div className="stacked-status">
                          <Status>{agent.status === 'active' ? 'Active' : 'Disabled'}</Status>
                          <span title={timestampLabel(agent.last_seen_at)}>
                            {t(heartbeat(agent.last_seen_at, now))} ·{' '}
                            {relativeTime(agent.last_seen_at, now)}
                          </span>
                        </div>
                      </td>
                      <td>
                        {agent.agent_version}
                        <small>
                          {t('Protocol {version}', { version: agent.protocol_version })}
                        </small>
                      </td>
                      <td>
                        <span
                          className={
                            agent.certificate_expires_at - now < 6 * 86400
                              ? 'certificate-warning'
                              : ''
                          }
                        >
                          {timestampLabel(agent.certificate_expires_at)}
                        </span>
                      </td>
                      <td>
                        <button
                          className="round-button"
                          aria-label={t('Manage {name}', { name: agent.display_name })}
                          aria-haspopup="dialog"
                          onClick={() => setSelected(agent)}
                        >
                          <MoreHorizontal size={18} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No matching agents">Try another name or access filter.</EmptyState>
          )}
          <Pager
            total={query.data.total}
            visible={query.data.items.length}
            cursor={nav.cursor}
            next={query.data.next_cursor}
            onNext={nav.advance}
            onBack={nav.back}
          />
        </section>
      )}
      {adding && <AddAgentDialog onClose={() => setAdding(false)} />}
      {selected && <AgentActionsDialog agent={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

function AgentActionsDialog({ agent, onClose }: { agent: ManagedAgent; onClose: () => void }) {
  const { t } = usePreferences()
  const { identity, refresh } = useManagement()
  const [disabling, setDisabling] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const mutation = useMutation({
    mutationFn: () => management.disable(agent.node_id, confirmation, identity.csrf_token),
    onSuccess: () => {
      void refresh()
      onClose()
    },
  })
  return (
    <Dialog
      title={disabling ? t('Disable agent') : agent.display_name}
      onClose={onClose}
      busy={mutation.isPending}
    >
      <p className="form-intro">
        {agent.display_name} · <code>{agent.node_id}</code>
      </p>
      {disabling ? (
        <form
          className="management-form"
          onSubmit={(event) => {
            event.preventDefault()
            if (confirmation === agent.node_id) mutation.mutate()
          }}
        >
          <Notice kind="warning">
            {t(
              'Disabling rejects this agent’s future requests and affects unfinished tasks. There is no re-enable action; reconnecting requires new enrollment.',
            )}
          </Notice>
          <label htmlFor="disable-confirm">{t('Type the agent ID to confirm')}</label>
          <input
            id="disable-confirm"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            required
          />
          <MutationError error={mutation.error} />
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              disabled={mutation.isPending}
              onClick={() => setDisabling(false)}
            >
              {t('Back')}
            </button>
            <button
              className="button danger"
              disabled={
                mutation.isPending ||
                confirmation !== agent.node_id ||
                uncertainWrite(mutation.error)
              }
            >
              {t(mutation.isPending ? 'Submitting…' : 'Disable agent')}
            </button>
          </div>
        </form>
      ) : (
        <div className="agent-action-list">
          <Link className="button secondary" to={`/fleet/${agent.public_id}`}>
            {t('View monitoring')}
          </Link>
          {canManage(identity, 'tasks:read') && (
            <Link className="button secondary" to={`/manage/tasks?node_id=${agent.node_id}`}>
              {t('View tasks')}
            </Link>
          )}
          {canManage(identity, 'tasks:read') &&
            canManage(identity, 'tasks:write') &&
            agent.status === 'active' && (
              <Link className="button primary" to={`/manage/tasks?new=1&agent=${agent.public_id}`}>
                {t('Dispatch task')}
              </Link>
            )}
          <AuditLink nodeId={agent.node_id} />
          {canManage(identity, 'agents:write') && agent.status === 'active' && (
            <button className="button danger" onClick={() => setDisabling(true)}>
              <ShieldOff size={16} />
              {t('Disable agent')}
            </button>
          )}
          {agent.status === 'disabled' && (
            <Notice>{t('This agent is disabled. New enrollment is required to reconnect.')}</Notice>
          )}
        </div>
      )}
    </Dialog>
  )
}

function AddAgentDialog({ onClose }: { onClose: () => void }) {
  const [manual, setManual] = useState(false)
  return manual ? (
    <EnrollmentDialog onClose={onClose} onInstall={() => setManual(false)} />
  ) : (
    <InstallationDialog onClose={onClose} onManual={() => setManual(true)} />
  )
}

function EnrollmentDialog({ onClose, onInstall }: { onClose: () => void; onInstall: () => void }) {
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const { identity, refresh } = useManagement()
  const now = useNow()
  const tokenInput = useRef<HTMLTextAreaElement>(null)
  const [copyState, setCopyState] = useState('')
  const mutation = useMutation({
    mutationFn: (ttl: number) => management.enroll(ttl, identity.csrf_token),
    onSuccess: () => {
      void refresh()
    },
  })
  const enrollment = mutation.data
  const expired = enrollment ? now >= enrollment.expires_at : false
  async function copy() {
    if (!enrollment || expired) return
    try {
      await navigator.clipboard.writeText(enrollment.token)
      setCopyState('Copied')
    } catch {
      tokenInput.current?.focus()
      tokenInput.current?.select()
      setCopyState('Copy the selected token manually.')
    }
  }
  return (
    <Dialog title={t('Add agent')} onClose={onClose} busy={mutation.isPending}>
      {!enrollment && <EnrollmentModes manual onChange={onInstall} disabled={mutation.isPending} />}
      {!enrollment ? (
        <form
          className="management-form"
          onSubmit={(event) => {
            event.preventDefault()
            mutation.mutate(Number(new FormData(event.currentTarget).get('ttl')) * 60)
          }}
        >
          <p className="form-intro">
            {t('Create a short-lived enrollment token, then enroll the agent on its own machine.')}
          </p>
          <label htmlFor="enrollment-ttl">{t('Token lifetime (minutes)')}</label>
          <input
            id="enrollment-ttl"
            name="ttl"
            type="number"
            min={1}
            max={60}
            defaultValue={5}
            step={1}
            required
          />
          <p className="field-hint">
            {t('The token is shown once and is not saved in browser storage.')}
          </p>
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
              {t(mutation.isPending ? 'Submitting…' : 'Create enrollment token')}
            </button>
          </div>
        </form>
      ) : (
        <div className="enrollment-result">
          <Notice kind={expired ? 'warning' : 'info'}>
            {t(
              expired
                ? 'This token has expired. Close this dialog to create another.'
                : 'Copy this token now. Closing this dialog removes it from the page.',
            )}
          </Notice>
          <label htmlFor="enrollment-token">{t('Enrollment token')}</label>
          <textarea
            ref={tokenInput}
            id="enrollment-token"
            readOnly
            value={expired ? '' : enrollment.token}
            rows={3}
            spellCheck={false}
          />
          <div className="token-actions">
            <button className="button secondary" disabled={expired} onClick={() => void copy()}>
              <Copy size={15} />
              {t('Copy token')}
            </button>
            <span role="status">{t(copyState)}</span>
          </div>
          <p className="field-hint">
            {t('Expires')} {timestampLabel(enrollment.expires_at)}
          </p>
          <h3>{t('On the agent machine')}</h3>
          <ol className="enrollment-steps">
            <li>
              {t('Install the agent and configure its Fleet server address, CA and local policy.')}
            </li>
            <li>{t('Save the token to a private file readable only by the agent owner.')}</li>
            <li>
              {t('Run enrollment with your configuration and token file:')}
              <pre tabIndex={0}>
                agent enroll -config /etc/argus-c2/agent.json -token-file /private/agent.token
              </pre>
            </li>
            <li>
              {t(
                'Start the agent, then refresh the Agent list to check registration and the first heartbeat.',
              )}
            </li>
          </ol>
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
