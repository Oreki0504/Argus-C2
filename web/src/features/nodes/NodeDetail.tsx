import { useFormat } from '../../lib/useFormat'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ArrowUpRight } from 'lucide-react'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { UtilizationStrip } from '../../components/UtilizationStrip'
import { heartbeat } from '../../lib/format'
import { historyRangeSchema } from '../../api/contracts'
import { useViewer } from '../auth/context'
import { useNow, useSummary } from '../fleet/useSummary'
import { NodeHistory } from './NodeHistory'
import { usePreferences } from '../../preferences/context'
import { canManage } from '../management/access'

export function NodeDetail() {
  const { quantity, timestampLabel, relativeTime } = useFormat()
  const { t } = usePreferences()
  const { publicId } = useParams()
  const identity = useViewer()
  const summary = useSummary()
  const now = useNow()
  const [params, setParams] = useSearchParams()
  const range = historyRangeSchema.safeParse(params.get('range')).data ?? '1h'
  if (identity && !identity.capabilities.includes('summary:read'))
    return (
      <EmptyState title="Summary unavailable">
        The Console data service has not been enabled.
      </EmptyState>
    )
  if (summary.isPending) return <Loading />
  if (summary.isError)
    return <ErrorState error={summary.error} retry={() => void summary.refetch()} />
  const node = summary.data.nodes.find((node) => node.public_id === publicId)
  if (!node)
    return (
      <EmptyState title="Agent unavailable">
        {t('This agent is not available.')} <Link to="/">{t('Return to overview')}</Link>
      </EmptyState>
    )
  const stale =
    (node.resources.as_of !== null && now - node.resources.as_of > 90) ||
    (node.traffic.as_of !== null && now - node.traffic.as_of > 90)

  const uptimeText =
    node.system.uptime_seconds === null
      ? t('Unavailable')
      : t('{days}d {hours}h', {
          days: Math.floor(node.system.uptime_seconds / 86400),
          hours: Math.floor((node.system.uptime_seconds % 86400) / 3600),
        })

  const specs = [
    { label: 'Operating system', value: node.system.os ?? t('Unavailable') },
    { label: 'Architecture', value: node.system.architecture ?? t('Unavailable') },
    {
      label: 'Kernel',
      value: node.system.kernel ? 'Linux ' + node.system.kernel : t('Unavailable'),
    },
    { label: 'Uptime', value: uptimeText },
    {
      label: 'Last heartbeat',
      value: relativeTime(node.last_seen_at, now),
      title: timestampLabel(node.last_seen_at),
    },
    {
      label: 'Sampled traffic',
      value: `↑ ${quantity(node.traffic.sampled_outbound_bytes, 'bytes')} · ↓ ${quantity(node.traffic.sampled_inbound_bytes, 'bytes')}`,
    },
  ]

  return (
    <section className="agent-detail">
      <div className="detail-titlebar">
        <Link className="round-button" to="/" aria-label={t('All agents')} title={t('All agents')}>
          <ArrowLeft size={18} />
        </Link>
        <h1>{node.display_name}</h1>
        <Status>{heartbeat(node.last_seen_at, now)}</Status>
        {canManage(identity, 'tasks:read') &&
          canManage(identity, 'tasks:write') &&
          canManage(identity, 'agents:read') && (
            <Link
              className="button secondary detail-dispatch"
              to={`/manage/tasks?new=1&agent=${node.public_id}`}
            >
              {t('Dispatch task')}
            </Link>
          )}
        <Link className="text-link detail-traffic-link" to="/traffic">
          {t('Traffic totals and coverage')}
          <ArrowUpRight size={14} />
        </Link>
      </div>

      {/* Top Spec Matrix inspired by qio.ng/server/:id */}
      <div className="detail-spec-strip" aria-label={t('Host specifications')}>
        {specs.map((spec) => (
          <div className="detail-spec-item" key={spec.label}>
            <span className="detail-spec-label">{t(spec.label)}</span>
            <strong className="detail-spec-val" title={spec.title}>
              {spec.value}
            </strong>
          </div>
        ))}
      </div>

      <section className="panel node-current">
        <div className="node-current-heading">
          <h2>{t('Current utilization')}</h2>
          <span>
            <span title={timestampLabel(node.resources.as_of)}>
              {t('Resources')} {relativeTime(node.resources.as_of, now)}
            </span>{' '}
            ·{' '}
            <span title={timestampLabel(node.traffic.as_of)}>
              {t('Traffic')} {relativeTime(node.traffic.as_of, now)}
            </span>
          </span>
        </div>
        <UtilizationStrip node={node} />
      </section>

      {stale && (
        <Notice kind="warning">
          {t('These observations are stale. The charts retain their original sample times.')}
        </Notice>
      )}

      <div className="history-heading">
        <h2>{t('Utilization history')}</h2>
        <div className="range-control" role="group" aria-label={t('History time range')}>
          {(['1h', '24h', '7d'] as const).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={range === value}
              onClick={() =>
                setParams(
                  (previous) => {
                    const next = new URLSearchParams(previous)
                    next.set('range', value)
                    return next
                  },
                  { replace: true },
                )
              }
            >
              <span className="range-dot" aria-hidden="true" />
              {t(value === '1h' ? '1 hour' : value === '24h' ? '24 hours' : '7 days')}
            </button>
          ))}
        </div>
      </div>

      <NodeHistory publicId={node.public_id} range={range}>
        <section className="node-facts panel" aria-label={t('System information')}>
          <h3>{t('System information')}</h3>
          <dl>
            {[
              ['Operating system', node.system.os],
              ['Architecture', node.system.architecture],
              ['Kernel', node.system.kernel],
              ['Uptime', uptimeText],
              ['Last heartbeat', relativeTime(node.last_seen_at, now)],
              ['Inbound capacity', quantity(node.traffic.inbound_capacity_bps, 'rate')],
              ['Outbound capacity', quantity(node.traffic.outbound_capacity_bps, 'rate')],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{t(label!)}</dt>
                <dd
                  title={label === 'Last heartbeat' ? timestampLabel(node.last_seen_at) : undefined}
                >
                  {value ?? t('Unavailable')}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      </NodeHistory>
    </section>
  )
}
