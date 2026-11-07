import { useFormat } from '../../lib/useFormat'
import { Link, useSearchParams } from 'react-router-dom'
import { RefreshCw, Search, Server } from 'lucide-react'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { UtilizationStrip } from '../../components/UtilizationStrip'
import { heartbeat } from '../../lib/format'
import { useViewer } from '../auth/context'
import { useNow, useSummary } from './useSummary'
import { useCardPageSize } from './useCardPageSize'
import { usePreferences } from '../../preferences/context'

const heartbeatFilters = [
  { value: 'all', label: 'All Server', tone: 'all' },
  { value: 'Online', label: 'Online', tone: 'online' },
  { value: 'Stale', label: 'Stale', tone: 'stale' },
  { value: 'Offline', label: 'Offline', tone: 'offline' },
] as const

export function AgentOverview() {
  const { relativeTime, timestampLabel } = useFormat()
  const { t, language } = usePreferences()
  const identity = useViewer()
  const pageSize = useCardPageSize()
  const summary = useSummary()
  const now = useNow(1_000)
  const localTime = new Intl.DateTimeFormat(language, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  })
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const status =
    heartbeatFilters.find((filter) => filter.value === params.get('status'))?.value ?? 'all'
  const change = (key: string, value: string) =>
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous)
        if (value && value !== 'all') next.set(key, value)
        else next.delete(key)
        if (key !== 'page') next.delete('page')
        return next
      },
      { replace: true },
    )
  if (identity && !identity.capabilities.includes('summary:read'))
    return (
      <EmptyState title="Your console is ready">
        Fleet summaries will appear after your administrator enables the Console data service.
      </EmptyState>
    )
  if (summary.isPending) return <Loading label="Loading agents" />
  if (summary.isError)
    return (
      <>
        <h1>{t('Fleet overview')}</h1>
        <ErrorState error={summary.error} retry={() => void summary.refetch()} />
      </>
    )
  const data = summary.data
  const matching = data.nodes.filter((node) =>
    node.display_name.toLowerCase().includes(search.toLowerCase()),
  )
  const filtered = matching.filter(
    (node) => status === 'all' || heartbeat(node.last_seen_at, now) === status,
  )
  const counts = matching.reduce<Record<string, number>>((result, node) => {
    const state = heartbeat(node.last_seen_at, now)
    result[state] = (result[state] ?? 0) + 1
    return result
  }, {})
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const requestedPage = Number(params.get('page') ?? 1)
  const page =
    Number.isInteger(requestedPage) && requestedPage > 0 ? Math.min(requestedPage, pages) : 1
  const nodes = filtered.slice((page - 1) * pageSize, page * pageSize)
  return (
    <section className="agent-overview">
      <div className="compact-heading">
        <div>
          <h1>{t('Fleet overview')}</h1>
          <p className="overview-updated" title={timestampLabel(data.generated_at)}>
            <time dateTime={new Date(now * 1000).toISOString()}>
              {localTime.format(now * 1000)}
            </time>
            {' · '}
            {t('Updated {time} · every 30s', { time: relativeTime(data.generated_at, now) })}
          </p>
        </div>
        <button
          className="button secondary"
          onClick={() => void summary.refetch()}
          disabled={summary.isFetching}
        >
          <RefreshCw size={15} className={summary.isFetching ? 'spin' : ''} />
          {t('Refresh')}
        </button>
      </div>
      {now - data.generated_at > 90 && (
        <Notice kind="warning">
          {t('This summary is stale. Each observation keeps its original collection time.')}
        </Notice>
      )}
      <div className="agent-toolbar">
        <div className="search-input">
          <Search size={16} aria-hidden="true" />
          <input
            aria-label={t('Search agents')}
            placeholder={t('Search…')}
            value={search}
            onChange={(event) => change('q', event.target.value)}
          />
        </div>
        <div className="heartbeat-filters" role="group" aria-label={t('Filter heartbeat status')}>
          {heartbeatFilters.map((filter) => (
            <button
              key={filter.value}
              type="button"
              className={`heartbeat-filter filter-${filter.tone}`}
              aria-pressed={status === filter.value}
              onClick={() => change('status', filter.value)}
            >
              <span className="heartbeat-filter-label">
                <span className="status-dot" aria-hidden="true" />
                {t(filter.label)}
              </span>
              <strong>
                {filter.value === 'all' ? matching.length : (counts[filter.value] ?? 0)}
              </strong>
            </button>
          ))}
        </div>
      </div>
      {nodes.length ? (
        <div className="agent-grid">
          {nodes.map((node) => {
            const stale =
              (node.resources.as_of !== null && now - node.resources.as_of > 90) ||
              (node.traffic.as_of !== null && now - node.traffic.as_of > 90)
            return (
              <article
                className={`agent-card ${stale ? 'agent-stale' : ''}`}
                data-status={heartbeat(node.last_seen_at, now)}
                key={node.public_id}
                aria-label={node.display_name}
                title={`${t('Resources')}: ${timestampLabel(node.resources.as_of)} · ${t('Traffic')}: ${timestampLabel(node.traffic.as_of)}`}
              >
                <div className="agent-card-header">
                  <span className="agent-icon">
                    <Server size={19} strokeWidth={1.5} />
                  </span>
                  <div className="agent-heading">
                    <h2>
                      <Link
                        className="agent-card-link"
                        to={`/fleet/${node.public_id}`}
                        aria-label={t('View {name}', { name: node.display_name })}
                      >
                        {node.display_name}
                      </Link>
                    </h2>
                    <p>
                      {node.system.os ?? t('System unavailable')} ·{' '}
                      {node.system.architecture ?? '—'}
                    </p>
                  </div>
                  <div className="agent-badges">
                    <Status>{heartbeat(node.last_seen_at, now)}</Status>
                    {stale && <span className="stale-flag">{t('Stale observations')}</span>}
                  </div>
                </div>
                <UtilizationStrip node={node} />
              </article>
            )
          })}
        </div>
      ) : (
        <section className="panel">
          <EmptyState title={data.nodes.length ? 'No matching agents' : 'Your fleet starts here'}>
            {data.nodes.length
              ? 'Try another name or heartbeat filter.'
              : 'Public agent summaries will appear here when observations become available.'}
          </EmptyState>
        </section>
      )}
      <div className="overview-bottomline">
        <p>{t('Bandwidth % uses configured capacity; — means unavailable.')}</p>
        {pages > 1 && (
          <div className="pagination">
            <button
              className="button secondary"
              disabled={page <= 1}
              onClick={() => change('page', String(page - 1))}
            >
              {t('Previous')}
            </button>
            <span>{t('Page {page} of {pages}', { page, pages })}</span>
            <button
              className="button secondary"
              disabled={page >= pages}
              onClick={() => change('page', String(page + 1))}
            >
              {t('Next')}
            </button>
          </div>
        )}
      </div>
    </section>
  )
}
