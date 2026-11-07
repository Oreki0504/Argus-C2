import { useFormat } from '../../lib/useFormat'
import { useSearchParams, Link } from 'react-router-dom'
import {
  Activity,
  ArrowDownLeft,
  ArrowRight,
  CircleHelp,
  RefreshCw,
  Search,
  Server,
} from 'lucide-react'
import { EmptyState, ErrorState, Loading, Notice, PageHeader } from '../../components/ui'
import { heartbeat } from '../../lib/format'
import { useIdentity } from '../auth/context'
import { NodeTable } from './NodeTable'
import { useNow, useSummary } from './useSummary'

export function FleetPage({ overview = false }: { overview?: boolean }) {
  const { quantity, timestampLabel } = useFormat()
  const identity = useIdentity()
  const summary = useSummary()
  const now = useNow()
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const status = params.get('status') ?? 'all'
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
  if (!identity.capabilities.includes('summary:read'))
    return (
      <EmptyState title="Your console is ready">
        Fleet summaries will appear after your administrator enables the Console data service.
      </EmptyState>
    )
  if (summary.isPending) return <Loading label="Loading fleet summary" />
  if (summary.isError)
    return <ErrorState error={summary.error} retry={() => void summary.refetch()} />
  const data = summary.data
  const counts = data.nodes.reduce(
    (result, node) => {
      const state = heartbeat(node.last_seen_at, now)
      result[state] = (result[state] ?? 0) + 1
      return result
    },
    {} as Record<string, number>,
  )
  const reporting = data.nodes.filter(
    (node) =>
      node.traffic.inbound_bps !== null &&
      node.traffic.as_of !== null &&
      now - node.traffic.as_of <= 90,
  )
  const inbound = reporting.length
    ? reporting.reduce((total, node) => total + node.traffic.inbound_bps!, 0)
    : null
  const filtered = data.nodes.filter(
    (node) =>
      node.display_name.toLowerCase().includes(search.toLowerCase()) &&
      (status === 'all' || heartbeat(node.last_seen_at, now) === status),
  )
  const pageSize = 20
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const requestedPage = Number(params.get('page') ?? 1)
  const page =
    Number.isInteger(requestedPage) && requestedPage > 0 ? Math.min(requestedPage, pages) : 1
  const visible = overview
    ? filtered.slice(0, 6)
    : filtered.slice((page - 1) * pageSize, page * pageSize)
  return (
    <>
      <PageHeader
        eyebrow="YOUR INFRASTRUCTURE, IN FOCUS"
        title={overview ? 'Fleet overview' : 'Your fleet'}
        description={
          overview
            ? 'A little less noise. A clearer view of every server.'
            : 'Heartbeat and resource observations across your authorized fleet.'
        }
      >
        <button
          className="button secondary"
          onClick={() => void summary.refetch()}
          disabled={summary.isFetching}
        >
          <RefreshCw size={15} className={summary.isFetching ? 'spin' : ''} />
          Refresh
        </button>
      </PageHeader>
      <div className="observation-bar">
        <span className="observation-dot" />
        <span>
          Last refreshed <time>{timestampLabel(data.generated_at)}</time>
        </span>
        <span>Auto-refresh every 30s</span>
      </div>
      {now - data.generated_at > 90 && (
        <Notice kind="warning">
          This summary is stale. Resource observations keep their original collection times.
        </Notice>
      )}
      {overview && (
        <div className="metric-grid">
          <Metric
            label="Total servers"
            value={String(data.nodes.length)}
            hint="In your authorized fleet"
            icon={<Server size={18} />}
          />
          <Metric
            label="Online"
            value={String(counts.Online ?? 0)}
            hint="Heartbeat within 90 seconds"
            icon={<Activity size={18} />}
            good
          />
          <Metric
            label="Needs a look"
            value={String(data.nodes.length - (counts.Online ?? 0))}
            hint={`${counts.Stale ?? 0} stale · ${counts.Offline ?? 0} offline`}
            icon={<CircleHelp size={18} />}
          />
          <Metric
            label="Inbound traffic"
            value={quantity(inbound, 'rate')}
            hint={`${reporting.length} of ${data.nodes.length} servers · recent samples`}
            icon={<ArrowDownLeft size={18} />}
          />
        </div>
      )}
      {data.nodes.length === 0 ? (
        <section className="panel">
          <EmptyState title="Your fleet starts here">
            No servers have been enrolled yet. Once a server joins, its public summary will appear
            here.
          </EmptyState>
        </section>
      ) : (
        <>
          <section className="panel fleet-panel">
            <div className="panel-heading">
              <div>
                <h2>
                  {overview ? 'Servers at a glance' : 'All servers'}
                  <span className="count-badge">{data.nodes.length}</span>
                </h2>
                <p>Latest observations, with their original collection time.</p>
              </div>
              {overview && (
                <Link className="text-link" to="/fleet">
                  View fleet
                  <ArrowRight size={15} />
                </Link>
              )}
            </div>
            <div className="table-toolbar">
              <div className="search-input">
                <Search size={16} />
                <input
                  aria-label="Search servers"
                  placeholder="Search servers…"
                  value={search}
                  onChange={(event) => change('q', event.target.value)}
                />
              </div>
              <select
                aria-label="Filter heartbeat status"
                value={status}
                onChange={(event) => change('status', event.target.value)}
              >
                <option value="all">All Server</option>
                {['Online', 'Stale', 'Offline'].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
              <span className="table-count">{filtered.length} servers</span>
            </div>
            <NodeTable nodes={visible} now={now} />
            <div className="table-footer">
              <span>
                {filtered.length
                  ? `${overview ? 1 : (page - 1) * pageSize + 1}–${overview ? visible.length : Math.min(page * pageSize, filtered.length)} of ${filtered.length} servers`
                  : '0 servers'}
              </span>
              {!overview ? (
                <div className="pagination">
                  <button
                    className="button compact secondary"
                    disabled={page <= 1}
                    onClick={() => change('page', String(page - 1))}
                  >
                    Previous
                  </button>
                  <span>
                    Page {page} of {pages}
                  </span>
                  <button
                    className="button compact secondary"
                    disabled={page >= pages}
                    onClick={() => change('page', String(page + 1))}
                  >
                    Next
                  </button>
                </div>
              ) : (
                <span>Public names · Read-only observations</span>
              )}
            </div>
          </section>
          {overview && (
            <div className="overview-bottom">
              <section className="panel insight-panel">
                <div className="insight-icon">
                  <Activity size={22} />
                </div>
                <div>
                  <p className="eyebrow">TRAFFIC, WITH CONTEXT</p>
                  <h2>Every sample tells part of the story.</h2>
                  <p>
                    View inbound and outbound totals alongside collection windows and coverage. Gaps
                    remain visible.
                  </p>
                  <Link to="/traffic" className="text-link">
                    Explore traffic
                    <ArrowRight size={15} />
                  </Link>
                </div>
              </section>
              <section className="panel heartbeat-guide">
                <h2>Reading heartbeat states</h2>
                <dl>
                  <div>
                    <dt>
                      <span className="mini-dot green" />
                      Online
                    </dt>
                    <dd>Up to 90 seconds</dd>
                  </div>
                  <div>
                    <dt>
                      <span className="mini-dot amber" />
                      Stale
                    </dt>
                    <dd>90 seconds – 5 minutes</dd>
                  </div>
                  <div>
                    <dt>
                      <span className="mini-dot gray" />
                      Offline
                    </dt>
                    <dd>Over 5 minutes</dd>
                  </div>
                </dl>
                <p>A recent heartbeat confirms contact, not overall health.</p>
              </section>
            </div>
          )}
        </>
      )}
    </>
  )
}

function Metric({
  label,
  value,
  hint,
  icon,
  good = false,
}: {
  label: string
  value: string
  hint: string
  icon: React.ReactNode
  good?: boolean
}) {
  return (
    <section className={`metric-card ${good ? 'metric-good' : ''}`}>
      <div className="metric-label">
        {label}
        <span>{icon}</span>
      </div>
      <strong className="metric-value">{value}</strong>
      <p>
        {good && <span className="mini-dot green" />}
        {hint}
      </p>
    </section>
  )
}
