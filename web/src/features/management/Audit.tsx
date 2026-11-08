import { useListNavigation, useManagement } from './hooks'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { management } from '../../api/management'
import { EmptyState, ErrorState, Loading, Status } from '../../components/ui'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { Pager, SectionHeading } from './shared'
import { canManage } from './access'

export function AuditPage() {
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const { identity, key } = useManagement()
  const nav = useListNavigation(['action', 'node_id', 'task_id', 'subject_id'])
  const filters = { ...nav.filters, cursor: nav.cursor, limit: 8 }
  const query = useQuery({
    queryKey: [...key, 'audit', filters],
    queryFn: ({ signal }) => management.audit(filters, signal),
  })
  return (
    <>
      <SectionHeading
        title="Audit"
        description="Review recorded management and agent operations."
        busy={query.isFetching}
        refresh={() => void query.refetch()}
      />
      <div className="management-filters audit-filters">
        {[
          ['action', 'Action'],
          ['node_id', 'Agent ID'],
          ['task_id', 'Task ID'],
          ['subject_id', 'User ID'],
        ].map(([key, label]) => (
          <input
            key={key}
            aria-label={t(label)}
            placeholder={t(label)}
            value={nav.filters[key]}
            onChange={(event) => nav.change(key, event.target.value)}
          />
        ))}
      </div>
      {query.isPending ? (
        <Loading label="Loading audit events" />
      ) : query.isError ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : (
        <section className="panel management-table-panel">
          {query.data.items.length ? (
            <div className="table-scroll" role="region" aria-label={t('Audit events')} tabIndex={0}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t('Time')}</th>
                    <th scope="col">{t('Actor')}</th>
                    <th scope="col">{t('Action')}</th>
                    <th scope="col">{t('Target')}</th>
                    <th scope="col">{t('Outcome')}</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((event) => {
                    const localizedAction = t(event.action)
                    return (
                      <tr key={event.id}>
                        <th scope="row" className="management-time">
                          {timestampLabel(event.timestamp)}
                          <small>#{event.id}</small>
                        </th>
                        <td>
                          <strong>{event.actor}</strong>
                        </td>
                        <td>
                          <span className="audit-action-pill">{localizedAction}</span>
                          {localizedAction !== event.action && <small>{event.action}</small>}
                        </td>
                        <td>
                          {event.node_id && <span className="mono-chip">{event.node_id}</span>}
                          {event.task_id &&
                            (canManage(identity, 'tasks:read') ? (
                              <Link
                                className="text-link audit-task-link"
                                to={`/manage/tasks/${event.task_id}`}
                              >
                                {event.task_id}
                              </Link>
                            ) : (
                              <small>{event.task_id}</small>
                            ))}
                          {event.subject_id && (
                            <span className="mono-chip">{event.subject_id}</span>
                          )}
                          {!event.node_id && !event.task_id && !event.subject_id && '—'}
                        </td>
                        <td>
                          <Status>{event.status}</Status>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No matching audit events">
              Try another action or target filter.
            </EmptyState>
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
      <p className="management-note">
        {t(
          'This log contains recorded state changes; it is not a log of every read or sign-in attempt.',
        )}
      </p>
    </>
  )
}
