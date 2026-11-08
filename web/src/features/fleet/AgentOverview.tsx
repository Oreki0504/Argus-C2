import { useState } from 'react'
import { useFormat } from '../../lib/useFormat'
import { Link, useSearchParams } from 'react-router-dom'
import {
  ArrowDownUp,
  ArrowUpDown,
  ArrowUpRight,
  LayoutGrid,
  Rows3,
  RefreshCw,
  Search,
  Server,
  Terminal,
  Cpu,
} from 'lucide-react'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { UtilizationStrip } from '../../components/UtilizationStrip'
import { heartbeat } from '../../lib/format'
import { useViewer } from '../auth/context'
import { useNow, useSummary } from './useSummary'
import { usePreferences } from '../../preferences/context'
import type { PublicNode } from '../../api/contracts'

const heartbeatFilters = [
  { value: 'all', label: 'All Server', tone: 'all' },
  { value: 'Online', label: 'Online', tone: 'online' },
  { value: 'Stale', label: 'Stale', tone: 'stale' },
  { value: 'Offline', label: 'Offline', tone: 'offline' },
] as const

type SortKey = 'default' | 'name' | 'cpu' | 'memory' | 'disk' | 'inbound' | 'outbound' | 'uptime'
type ViewMode = 'strip' | 'grid'

function readViewMode(): ViewMode {
  try {
    return localStorage.getItem('argus.viewMode') === 'grid' ? 'grid' : 'strip'
  } catch {
    return 'strip'
  }
}

function OsBadge({ os }: { os: string | null }) {
  const lower = (os ?? '').toLowerCase()
  if (lower.includes('ubuntu')) {
    return (
      <span className="os-badge os-ubuntu" title={os ?? undefined}>
        <Terminal size={15} strokeWidth={2} />
      </span>
    )
  }
  if (lower.includes('debian')) {
    return (
      <span className="os-badge os-debian" title={os ?? undefined}>
        <Cpu size={15} strokeWidth={2} />
      </span>
    )
  }
  return (
    <span className="os-badge" title={os ?? undefined}>
      <Server size={15} strokeWidth={1.8} />
    </span>
  )
}

export function AgentOverview() {
  const { relativeTime, timestampLabel, quantity } = useFormat()
  const { t, language } = usePreferences()
  const identity = useViewer()
  const summary = useSummary()
  const now = useNow(1_000)
  const [viewMode, setViewMode] = useState<ViewMode>(readViewMode)
  const [sortBy, setSortBy] = useState<SortKey>('default')
  const [sortDesc, setSortDesc] = useState(true)

  const toggleViewMode = (mode: ViewMode) => {
    setViewMode(mode)
    try {
      localStorage.setItem('argus.viewMode', mode)
    } catch {
      // ignore storage errors
    }
  }

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

  // Aggregate fleet-wide network totals and current throughput
  const totalInBytes = data.nodes.reduce(
    (acc, n) => acc + (n.traffic.sampled_inbound_bytes ?? 0),
    0,
  )
  const totalOutBytes = data.nodes.reduce(
    (acc, n) => acc + (n.traffic.sampled_outbound_bytes ?? 0),
    0,
  )
  const totalInRate = data.nodes.reduce((acc, n) => acc + (n.traffic.inbound_bps ?? 0), 0)
  const totalOutRate = data.nodes.reduce((acc, n) => acc + (n.traffic.outbound_bps ?? 0), 0)

  const sorted = [...filtered].sort((a: PublicNode, b: PublicNode) => {
    if (sortBy === 'default') return 0
    const dir = sortDesc ? -1 : 1
    if (sortBy === 'name') return a.display_name.localeCompare(b.display_name) * -dir
    const metricVal = (n: PublicNode): number => {
      switch (sortBy) {
        case 'cpu':
          return n.resources.cpu_percent ?? -1
        case 'memory':
          return n.resources.memory_percent ?? -1
        case 'disk':
          return n.resources.disk_percent ?? -1
        case 'inbound':
          return n.traffic.inbound_bps ?? -1
        case 'outbound':
          return n.traffic.outbound_bps ?? -1
        case 'uptime':
          return n.system.uptime_seconds ?? -1
        default:
          return 0
      }
    }
    return (metricVal(a) - metricVal(b)) * dir
  })

  // Natural scrolling for normal fleets; lightweight 30-per-page pagination only for massive fleets (>60)
  const pageSize = 30
  const pages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const requestedPage = Number(params.get('page') ?? 1)
  const page =
    Number.isInteger(requestedPage) && requestedPage > 0 ? Math.min(requestedPage, pages) : 1
  const nodes = sorted.slice((page - 1) * pageSize, page * pageSize)

  return (
    <section className="agent-overview">
      <div className="compact-heading">
        <div>
          <h1 className="overview-greeting">
            <span className="greeting-wave" aria-hidden="true">
              👋
            </span>
            {t('Fleet overview')}
          </h1>
          <p className="overview-updated" title={timestampLabel(data.generated_at)}>
            <span>{t('Where the time is')} </span>
            <time className="live-clock" dateTime={new Date(now * 1000).toISOString()}>
              {localTime.format(now * 1000)}
            </time>
            {' · '}
            {t('Updated {time} · every 30s', { time: relativeTime(data.generated_at, now) })}
          </p>
        </div>
        <button
          className="button secondary compact-refresh"
          onClick={() => void summary.refetch()}
          disabled={summary.isFetching}
        >
          <RefreshCw size={14} className={summary.isFetching ? 'spin' : ''} />
          {t('Refresh')}
        </button>
      </div>

      {now - data.generated_at > 90 && (
        <Notice kind="warning">
          {t('This summary is stale. Each observation keeps its original collection time.')}
        </Notice>
      )}

      {/* 4-Card Bento Summary Row (inspired by qio.ng / nezha-dash) */}
      <div className="bento-summary-grid" role="region" aria-label={t('Fleet overview')}>
        <button
          type="button"
          className={`bento-stat-card filter-all ${status === 'all' ? 'is-active' : ''}`}
          aria-pressed={status === 'all'}
          onClick={() => change('status', 'all')}
        >
          <span className="bento-stat-title">{t('All Server')}</span>
          <div className="bento-stat-value">
            <span className="bento-dot dot-all" aria-hidden="true" />
            <strong>{matching.length}</strong>
          </div>
          <span className="bento-stat-sub">
            {counts.Online ?? 0} {t('Online')} · {counts.Stale ?? 0} {t('Stale')}
          </span>
        </button>

        <button
          type="button"
          className={`bento-stat-card filter-online ${status === 'Online' ? 'is-active' : ''}`}
          aria-pressed={status === 'Online'}
          onClick={() => change('status', 'Online')}
        >
          <span className="bento-stat-title">{t('Online')}</span>
          <div className="bento-stat-value">
            <span className="bento-dot dot-online pulse" aria-hidden="true" />
            <strong>{counts.Online ?? 0}</strong>
          </div>
          <span className="bento-stat-sub">{t('Active heartbeat ≤ 90s')}</span>
        </button>

        <button
          type="button"
          className={`bento-stat-card filter-offline ${status === 'Offline' || status === 'Stale' ? 'is-active' : ''}`}
          aria-pressed={status === 'Offline'}
          onClick={() => change('status', status === 'Offline' ? 'Stale' : 'Offline')}
        >
          <div className="bento-stat-header-row">
            <span className="bento-stat-title">{t('Offline')}</span>
            {(counts.Stale ?? 0) > 0 && (
              <span
                className={`stale-pill ${status === 'Stale' ? 'is-active' : ''}`}
                onClick={(e) => {
                  e.stopPropagation()
                  change('status', status === 'Stale' ? 'all' : 'Stale')
                }}
              >
                {counts.Stale ?? 0} {t('Stale')}
              </span>
            )}
          </div>
          <div className="bento-stat-value">
            <span className="bento-dot dot-offline" aria-hidden="true" />
            <strong>{counts.Offline ?? 0}</strong>
          </div>
          <span className="bento-stat-sub">
            {status === 'Stale' ? t('Filtering stale observations') : t('Click to filter offline')}
          </span>
        </button>

        <div className="bento-stat-card bento-network-card">
          <div className="bento-stat-header-row">
            <span className="bento-stat-title">{t('Network')}</span>
            <Link to="/traffic" className="bento-network-link" title={t('Network traffic')}>
              <ArrowUpRight size={14} />
            </Link>
          </div>
          <div className="bento-network-totals">
            <span className="net-up">↑ {quantity(totalOutBytes, 'bytes')}</span>
            <span className="net-down">↓ {quantity(totalInBytes, 'bytes')}</span>
          </div>
          <div className="bento-network-rates">
            <span>↑ {quantity(totalOutRate, 'rate')}</span>
            <span>↓ {quantity(totalInRate, 'rate')}</span>
          </div>
        </div>
      </div>

      {/* Dedicated Control Bar: View Toggle + Status Pills + Search + Sort */}
      <div className="overview-toolbar">
        <div className="toolbar-left">
          <div className="view-toggle-group" role="group" aria-label={t('View mode')}>
            <button
              type="button"
              className={`view-pill-btn ${viewMode === 'strip' ? 'is-active' : ''}`}
              onClick={() => toggleViewMode('strip')}
              title={t('Compact strip view')}
              aria-label={t('Compact strip view')}
              aria-pressed={viewMode === 'strip'}
            >
              <Rows3 size={15} />
            </button>
            <button
              type="button"
              className={`view-pill-btn ${viewMode === 'grid' ? 'is-active' : ''}`}
              onClick={() => toggleViewMode('grid')}
              title={t('Card grid view')}
              aria-label={t('Card grid view')}
              aria-pressed={viewMode === 'grid'}
            >
              <LayoutGrid size={15} />
            </button>
          </div>

          <div className="status-pill-group" role="group" aria-label={t('Filter heartbeat status')}>
            {heartbeatFilters.map((filter) => (
              <button
                key={filter.value}
                type="button"
                className={`status-filter-pill tone-${filter.tone} ${status === filter.value ? 'is-active' : ''}`}
                aria-pressed={status === filter.value}
                onClick={() => change('status', filter.value)}
              >
                <span className="status-dot" aria-hidden="true" />
                <span>{t(filter.label)}</span>
                <small>
                  {filter.value === 'all' ? matching.length : (counts[filter.value] ?? 0)}
                </small>
              </button>
            ))}
          </div>
        </div>

        <div className="toolbar-right">
          <div className="search-input">
            <Search size={15} aria-hidden="true" />
            <input
              aria-label={t('Search agents')}
              placeholder={t('Search…')}
              value={search}
              onChange={(event) => change('q', event.target.value)}
            />
          </div>

          <div className="sort-control-capsule">
            <button
              type="button"
              className="sort-dir-btn"
              disabled={sortBy === 'default'}
              onClick={() => setSortDesc((prev) => !prev)}
              aria-label={t('Toggle sort direction')}
              title={t('Toggle sort direction')}
            >
              {sortDesc ? <ArrowDownUp size={14} /> : <ArrowUpDown size={14} />}
              <span>{t('Sort')}</span>
            </button>
            <span className="sort-divider" aria-hidden="true">
              |
            </span>
            <select
              aria-label={t('Sort metric')}
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortKey)}
            >
              <option value="default">{t('Default')}</option>
              <option value="name">{t('Name')}</option>
              <option value="cpu">CPU</option>
              <option value="memory">{t('Memory')}</option>
              <option value="disk">{t('Disk')}</option>
              <option value="inbound">{t('Inbound')}</option>
              <option value="outbound">{t('Outbound')}</option>
              <option value="uptime">{t('Uptime')}</option>
            </select>
          </div>
        </div>
      </div>

      {nodes.length ? (
        <div
          className={`agent-grid ${viewMode === 'strip' ? 'agent-grid-strip' : 'agent-grid-cards'}`}
        >
          {nodes.map((node) => {
            const nodeStatus = heartbeat(node.last_seen_at, now)
            const isOffline = nodeStatus === 'Offline'
            const stale =
              !isOffline &&
              ((node.resources.as_of !== null && now - node.resources.as_of > 90) ||
                (node.traffic.as_of !== null && now - node.traffic.as_of > 90))
            return (
              <article
                className={`agent-card ${viewMode === 'strip' ? 'agent-card-strip' : ''} ${isOffline ? 'agent-offline-collapsed' : ''} ${stale ? 'agent-stale' : ''}`}
                data-status={nodeStatus}
                key={node.public_id}
                aria-label={node.display_name}
                title={`${t('Resources')}: ${timestampLabel(node.resources.as_of)} · ${t('Traffic')}: ${timestampLabel(node.traffic.as_of)}`}
              >
                <div className="agent-card-header">
                  <span
                    className={`live-indicator-dot dot-${nodeStatus.toLowerCase()}`}
                    aria-hidden="true"
                  />
                  <OsBadge os={node.system.os} />
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
                      {node.system.os ?? t('System unavailable')}
                      {node.system.architecture ? ` · ${node.system.architecture}` : ''}
                    </p>
                  </div>
                  <div className="agent-badges">
                    <Status>{nodeStatus}</Status>
                    {stale && <span className="stale-flag">{t('Stale observations')}</span>}
                  </div>
                </div>
                {isOffline ? (
                  <div
                    className={`utilization-strip offline-strip-slot ${viewMode === 'strip' ? 'utilization-strip-compact' : ''}`}
                    aria-label={t('Offline')}
                  >
                    <div className="offline-summary-pill">
                      <span className="offline-summary-text">
                        {t('Last heartbeat')}:{' '}
                        <strong>{relativeTime(node.last_seen_at, now)}</strong>
                      </span>
                      {node.traffic.sampled_inbound_bytes !== null && (
                        <span className="offline-summary-traffic">
                          ↓ {quantity(node.traffic.sampled_inbound_bytes, 'bytes')} · ↑{' '}
                          {quantity(node.traffic.sampled_outbound_bytes, 'bytes')}
                        </span>
                      )}
                    </div>
                  </div>
                ) : (
                  <UtilizationStrip node={node} compact={viewMode === 'strip'} />
                )}
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

      {pages > 1 && (
        <div className="overview-bottomline">
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
        </div>
      )}
    </section>
  )
}
