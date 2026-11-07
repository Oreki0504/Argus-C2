import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { ArrowDownLeft, ArrowUpRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Direction, EmptyState, ErrorState, Loading, Notice, PageHeader } from '../../components/ui'
import { useViewer } from '../auth/context'
import { useNow, useSummary } from '../fleet/useSummary'

export function TrafficPage() {
  const { t } = usePreferences()
  const { percent, quantity, timestampLabel } = useFormat()
  const identity = useViewer()
  const summary = useSummary()
  const now = useNow()
  if (identity && !identity.capabilities.includes('summary:read'))
    return (
      <EmptyState title="Traffic unavailable">
        The Console data service has not been enabled.
      </EmptyState>
    )
  if (summary.isPending) return <Loading label="Loading traffic observations" />
  if (summary.isError)
    return <ErrorState error={summary.error} retry={() => void summary.refetch()} />
  const data = summary.data
  const incoming = data.nodes.filter((node) => node.traffic.sampled_inbound_bytes !== null)
  const outgoing = data.nodes.filter((node) => node.traffic.sampled_outbound_bytes !== null)
  const totalIn = incoming.length
    ? incoming.reduce((sum, node) => sum + node.traffic.sampled_inbound_bytes!, 0)
    : null
  const totalOut = outgoing.length
    ? outgoing.reduce((sum, node) => sum + node.traffic.sampled_outbound_bytes!, 0)
    : null
  return (
    <>
      <PageHeader
        eyebrow="OBSERVE THE FLOW"
        title="Network traffic"
        description="Aggregate inbound and outbound observations. Every gap accounted for."
      />
      <div className="window-label">
        {t('Sample window')}{' '}
        <strong>
          {timestampLabel(data.window_start)} — {timestampLabel(data.window_end)}
        </strong>
        <span>{t('Sampling interval {seconds}s', { seconds: data.sample_interval_seconds })}</span>
      </div>
      <div className="traffic-totals">
        <section className="panel traffic-total">
          <ArrowDownLeft size={24} />
          <div>
            <Direction inbound />
            <strong>{quantity(totalIn, 'bytes')}</strong>
            <p>
              {t('Sampled inbound · {count}/{total} servers reporting', {
                count: incoming.length,
                total: data.nodes.length,
              })}
            </p>
          </div>
        </section>
        <section className="panel traffic-total">
          <ArrowUpRight size={24} />
          <div>
            <Direction inbound={false} />
            <strong>{quantity(totalOut, 'bytes')}</strong>
            <p>
              {t('Sampled outbound · {count}/{total} servers reporting', {
                count: outgoing.length,
                total: data.nodes.length,
              })}
            </p>
          </div>
        </section>
      </div>
      <Notice>
        {t(
          'Totals include measured intervals only. Missing samples and counter resets are unmeasured; these totals are not provider billing figures.',
        )}
      </Notice>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>{t('Traffic by server')}</h2>
            <p>{t('Rates use bits per second. Sampled totals use bytes.')}</p>
          </div>
        </div>
        {data.nodes.length === 0 ? (
          <EmptyState title="No traffic observations yet">
            Data will appear once authorized servers begin reporting samples.
          </EmptyState>
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label={t('Traffic observations')}
            tabIndex={0}
          >
            <table>
              <thead>
                <tr>
                  <th scope="col">{t('Server')}</th>
                  <th scope="col">
                    <Direction inbound />
                  </th>
                  <th scope="col">
                    <Direction inbound={false} />
                  </th>
                  <th scope="col">{t('Sampled in / out')}</th>
                  <th scope="col">{t('Coverage')}</th>
                  <th scope="col">{t('Quality')}</th>
                </tr>
              </thead>
              <tbody>
                {data.nodes.map((node) => (
                  <tr key={node.public_id}>
                    <th scope="row">
                      <Link className="text-link" to={`/fleet/${node.public_id}`}>
                        {node.display_name}
                      </Link>
                      <small title={timestampLabel(node.traffic.as_of)}>
                        {timestampLabel(node.traffic.as_of)}
                      </small>
                    </th>
                    <td className="numeric">{quantity(node.traffic.inbound_bps, 'rate')}</td>
                    <td className="numeric">{quantity(node.traffic.outbound_bps, 'rate')}</td>
                    <td className="numeric">
                      {quantity(node.traffic.sampled_inbound_bytes, 'bytes')}
                      <small>{quantity(node.traffic.sampled_outbound_bytes, 'bytes')}</small>
                    </td>
                    <td>{percent(node.traffic.coverage_percent)}</td>
                    <td>
                      <span
                        className={`quality ${node.traffic.coverage_percent === 100 ? 'quality-good' : ''}`}
                      >
                        {t(
                          node.traffic.coverage_percent === null
                            ? 'No samples'
                            : node.traffic.as_of === null || now - node.traffic.as_of > 90
                              ? 'Stale'
                              : node.traffic.coverage_percent < 100
                                ? 'Partial'
                                : 'Observed',
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <p className="traffic-note">
        {t('Open an agent’s details to explore its sampled resource and bandwidth utilization.')}
      </p>
    </>
  )
}
