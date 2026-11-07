import { uncertainWrite, useListNavigation, useManagement } from './hooks'
import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ArrowLeft, Plus } from 'lucide-react'
import { management } from '../../api/management'
import {
  createTaskSchema,
  taskTypes,
  taskStates,
  type CreateTask,
} from '../../api/management-contracts'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { canManage } from './access'
import { AuditLink, Dialog, MutationError, Pager, SectionHeading } from './shared'

export function TasksPage() {
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const { identity, key } = useManagement()
  const nav = useListNavigation(['node_id', 'status', 'task_type'])
  const [params, setParams] = useSearchParams()
  const filters = { ...nav.filters, cursor: nav.cursor, limit: 8 }
  const query = useQuery({
    queryKey: [...key, 'tasks', filters],
    queryFn: ({ signal }) => management.tasks(filters, signal),
  })
  const writable = canManage(identity, 'tasks:write') && canManage(identity, 'agents:read')
  const close = () =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current)
        next.delete('new')
        next.delete('agent')
        return next
      },
      { replace: true },
    )
  return (
    <>
      <SectionHeading
        title="Tasks"
        description="Dispatch diagnostics and inspect their outcomes."
        busy={query.isFetching}
        refresh={() => void query.refetch()}
      >
        {writable && (
          <button
            className="button primary"
            onClick={() =>
              setParams(
                (current) => {
                  const next = new URLSearchParams(current)
                  next.set('new', '1')
                  return next
                },
                { replace: true },
              )
            }
          >
            <Plus size={16} />
            {t('New task')}
          </button>
        )}
      </SectionHeading>
      <div className="management-filters">
        <input
          aria-label={t('Filter by agent ID')}
          placeholder={t('Agent ID')}
          value={nav.filters.node_id}
          onChange={(event) => nav.change('node_id', event.target.value)}
        />
        <select
          aria-label={t('Task status')}
          value={nav.filters.status}
          onChange={(event) => nav.change('status', event.target.value)}
        >
          <option value="">{t('All task states')}</option>
          {taskStates.map((state) => (
            <option key={state} value={state}>
              {t(state)}
            </option>
          ))}
        </select>
        <select
          aria-label={t('Task type')}
          value={nav.filters.task_type}
          onChange={(event) => nav.change('task_type', event.target.value)}
        >
          <option value="">{t('All collectors')}</option>
          {taskTypes.map((type) => (
            <option key={type} value={type}>
              {t(type)}
            </option>
          ))}
        </select>
      </div>
      {query.isPending ? (
        <Loading label="Loading tasks" />
      ) : query.isError ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : (
        <section className="panel management-table-panel">
          {query.data.items.length ? (
            <div className="table-scroll" role="region" aria-label={t('Tasks')} tabIndex={0}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t('Task')}</th>
                    <th scope="col">{t('Agent')}</th>
                    <th scope="col">{t('Status')}</th>
                    <th scope="col">{t('Created')}</th>
                    <th scope="col">{t('Actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((task) => (
                    <tr key={task.id}>
                      <th scope="row">
                        <Link className="text-link" to={`/manage/tasks/${task.id}`}>
                          {t(task.task_type)}
                        </Link>
                        <small className="record-id">{task.id}</small>
                      </th>
                      <td>
                        {task.agent_name}
                        <small>{task.node_id}</small>
                      </td>
                      <td>
                        <Status>{task.status}</Status>
                      </td>
                      <td className="management-time">{timestampLabel(task.created_at)}</td>
                      <td>
                        <Link className="text-link" to={`/manage/tasks/${task.id}`}>
                          {t('View task')}
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No matching tasks">Try another agent or task filter.</EmptyState>
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
      {params.get('new') === '1' && writable && (
        <NewTaskDialog initialPublicId={params.get('agent') ?? undefined} onClose={close} />
      )}
    </>
  )
}

function NewTaskDialog({
  initialPublicId,
  onClose,
}: {
  initialPublicId?: string
  onClose: () => void
}) {
  const { t } = usePreferences()
  const { identity, key, refresh } = useManagement()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [type, setType] = useState<CreateTask['task_type']>('system.info')
  const [validation, setValidation] = useState(false)
  const lookup = {
    q: search,
    public_id: !search && selected === null ? initialPublicId : undefined,
    status: 'active',
    limit: 100,
  }
  const agents = useQuery({
    queryKey: [...key, 'agent-options', lookup],
    queryFn: ({ signal }) => management.agents(lookup, signal),
  })
  const nodeId =
    selected ?? (initialPublicId && !search ? agents.data?.items[0]?.node_id : '') ?? ''
  const mutation = useMutation({
    mutationFn: (body: CreateTask) => management.createTask(body, identity.csrf_token),
    onSuccess: (task) => {
      void refresh()
      navigate(`/manage/tasks/${task.id}`)
    },
  })
  return (
    <Dialog title={t('New task')} onClose={onClose} busy={mutation.isPending}>
      <form
        className="management-form"
        onSubmit={(event) => {
          event.preventDefault()
          const form = new FormData(event.currentTarget)
          const parameters =
            type === 'service.status'
              ? { service_id: String(form.get('resource')) }
              : type === 'ssh.audit'
                ? { profile_id: String(form.get('resource')) }
                : {}
          const body = createTaskSchema.safeParse({
            node_id: nodeId,
            task_type: type,
            parameters,
            ttl_seconds: Number(form.get('ttl')),
            execution_timeout_ms: Number(form.get('timeout')),
          })
          setValidation(!body.success)
          if (body.success) mutation.mutate(body.data)
        }}
      >
        <p className="form-intro">{t('Choose an agent and an allowed diagnostic collector.')}</p>
        <label htmlFor="task-agent-search">{t('Find agent')}</label>
        <input
          id="task-agent-search"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value)
            setSelected('')
          }}
          placeholder={t('Search agents…')}
        />
        <label htmlFor="task-agent">{t('Agent')}</label>
        <select
          id="task-agent"
          required
          value={nodeId}
          disabled={agents.isPending || mutation.isPending}
          onChange={(event) => setSelected(event.target.value)}
        >
          <option value="">{t('Choose an agent')}</option>
          {agents.data?.items.map((agent) => (
            <option key={agent.node_id} value={agent.node_id}>
              {agent.display_name} · {agent.node_id}
            </option>
          ))}
        </select>
        {agents.isError && <ErrorState error={agents.error} retry={() => void agents.refetch()} />}
        {agents.data?.next_cursor && (
          <p className="field-hint">{t('Refine your search to find more agents.')}</p>
        )}
        <label htmlFor="task-type">{t('Task type')}</label>
        <select
          id="task-type"
          value={type}
          onChange={(event) => setType(event.target.value as CreateTask['task_type'])}
        >
          {taskTypes.map((value) => (
            <option key={value} value={value}>
              {t(value)}
            </option>
          ))}
        </select>
        {(type === 'service.status' || type === 'ssh.audit') && (
          <>
            <label htmlFor="task-resource">
              {t(type === 'service.status' ? 'Service ID' : 'SSH profile ID')}
            </label>
            <input
              key={type}
              id="task-resource"
              name="resource"
              required
              maxLength={32}
              pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,31}"
              placeholder={type === 'service.status' ? 'journal' : 'host'}
            />
            <p className="field-hint">
              {t('Use an identifier configured in the agent’s local policy.')}
            </p>
          </>
        )}
        <div className="form-two-columns">
          <div>
            <label htmlFor="task-ttl">{t('Dispatch TTL (seconds)')}</label>
            <input
              id="task-ttl"
              name="ttl"
              type="number"
              min={10}
              max={3600}
              step={1}
              defaultValue={300}
              required
            />
          </div>
          <div>
            <label htmlFor="task-timeout">{t('Execution timeout (ms)')}</label>
            <input
              id="task-timeout"
              name="timeout"
              type="number"
              min={1}
              max={30000}
              step={1}
              defaultValue={10000}
              required
            />
          </div>
        </div>
        <p className="field-hint">
          {t('The agent’s local policy and timeout limits still apply.')}
        </p>
        {validation && (
          <p className="form-error" role="alert">
            {t('Check the form values and try again.')}
          </p>
        )}
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
            disabled={
              mutation.isPending ||
              agents.isPending ||
              agents.isError ||
              !nodeId ||
              uncertainWrite(mutation.error)
            }
          >
            {t(mutation.isPending ? 'Submitting…' : 'Dispatch task')}
          </button>
        </div>
      </form>
    </Dialog>
  )
}

export function TaskDetailPage() {
  const { taskId = '' } = useParams()
  const { identity, key } = useManagement()
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const [raw, setRaw] = useState(false)
  const query = useQuery({
    queryKey: [...key, 'task', taskId],
    queryFn: ({ signal }) => management.task(taskId, signal),
  })
  if (query.isPending) return <Loading label="Loading task" />
  if (query.isError) return <ErrorState error={query.error} retry={() => void query.refetch()} />
  const { task, result } = query.data
  return (
    <div className="managed-task-detail">
      <Link className="back-link" to={`/manage/tasks?node_id=${task.node_id}`}>
        <ArrowLeft size={14} />
        {t('Back to tasks')}
      </Link>
      <SectionHeading
        title={t(task.task_type)}
        description={task.id}
        busy={query.isFetching}
        refresh={() => void query.refetch()}
      >
        <Status>{task.status}</Status>
      </SectionHeading>
      <div className="task-detail-columns">
        <section className="panel management-facts">
          <h3>{t('Dispatch details')}</h3>
          <dl>
            {[
              ['Agent', `${task.agent_name} · ${task.node_id}`],
              ['Created', timestampLabel(task.created_at)],
              ['Dispatch deadline', timestampLabel(task.dispatch_expires_at)],
              ['Execution authorized', timestampLabel(task.execution_authorized_at)],
              ['Result due', timestampLabel(task.result_due_at)],
              ['Result received', timestampLabel(task.result_received_at)],
              ['Execution timeout (ms)', String(task.execution_timeout_ms)],
              [
                'Parameters',
                Object.entries(task.parameters)
                  .map(([key, value]) => `${key}: ${value}`)
                  .join(', ') || t('None'),
              ],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{t(label)}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
          <AuditLink nodeId={task.node_id} taskId={task.id} />
        </section>
        <section className="panel management-result">
          <div className="result-heading">
            <h3>{t('Result')}</h3>
            {result && (
              <button className="text-action" aria-pressed={raw} onClick={() => setRaw(!raw)}>
                {t(raw ? 'Hide JSON' : 'View JSON')}
              </button>
            )}
          </div>
          {task.status === 'UNKNOWN' && (
            <Notice kind="warning">
              {t(
                'The outcome is unknown. A later result may still arrive; this does not prove the task stopped.',
              )}
            </Notice>
          )}
          {result ? (
            <>
              <p className="muted">
                {t('Completed')} {timestampLabel(result.completed_at)}
              </p>
              {result.error && <Notice kind="warning">{t(result.error)}</Notice>}
              {raw ? (
                <pre className="json-result" tabIndex={0}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              ) : Object.keys(result.payload).length ? (
                <dl className="result-fields">
                  {Object.entries(result.payload).map(([name, value]) => (
                    <div key={name}>
                      <dt>{name}</dt>
                      <dd>
                        {typeof value === 'object' ? (
                          <pre>{JSON.stringify(value, null, 2)}</pre>
                        ) : (
                          String(value)
                        )}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="empty-result">{t('No observation payload was returned.')}</p>
              )}
            </>
          ) : (
            <p className="empty-result">
              {t('No result has arrived. Refresh to check the current state.')}
            </p>
          )}
        </section>
      </div>
      {canManage(identity, 'tasks:write') && (
        <p className="management-note">
          {t('To run another diagnostic, start a new task from the task list.')}
        </p>
      )}
    </div>
  )
}
