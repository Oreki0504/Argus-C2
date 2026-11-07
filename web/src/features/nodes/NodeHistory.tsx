import { useFormat } from '../../lib/useFormat'
import { useRef, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { usePreferences } from '../../preferences/context'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { HistoryRange } from '../../api/contracts'
import { consoleKey } from '../../api/query'
import { useViewer } from '../auth/context'
import { ErrorState, Loading } from '../../components/ui'
import { metrics } from '../../lib/utilization'
import { UtilizationChart } from './UtilizationChart'

export function NodeHistory({
  publicId,
  range,
  children,
}: {
  publicId: string
  range: HistoryRange
  children?: ReactNode
}) {
  const { timestampLabel, utilizationLabel } = useFormat()
  const { t } = usePreferences()
  const dialog = useRef<HTMLDialogElement>(null)
  const identity = useViewer()
  const query = useQuery({
    queryKey: [
      ...(identity ? consoleKey(identity) : ['public-console']),
      'history',
      publicId,
      range,
    ],
    queryFn: ({ signal }) => api.history(publicId, range, identity === null, signal),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
  })
  if (query.isPending || query.isError)
    return (
      <>
        {query.isPending ? (
          <Loading label="Loading utilization history" />
        ) : (
          <ErrorState error={query.error} retry={() => void query.refetch()} />
        )}
        {children}
      </>
    )
  const history = query.data
  return (
    <>
      <div className="history-window">
        <p>
          {timestampLabel(history.window_start)} — {timestampLabel(history.window_end)}
          <span>
            {t('Sampling interval {seconds}s', { seconds: history.sample_interval_seconds })}
          </span>
        </p>
        {history.points.length > 0 && (
          <button className="sample-data-button" onClick={() => dialog.current?.showModal()}>
            {t('View sample data')}
          </button>
        )}
      </div>
      <div className="history-grid">
        {metrics.map((metric) => (
          <UtilizationChart
            key={`${publicId}:${range}:${metric.key}`}
            history={history}
            metricKey={metric.key}
            title={metric.title}
            tone={metric.tone}
          />
        ))}
        {children}
      </div>
      {history.points.length > 0 && (
        <dialog className="sample-dialog" ref={dialog} aria-labelledby="sample-dialog-title">
          <div className="sample-dialog-heading">
            <div>
              <h2 id="sample-dialog-title">{t('View sample data')}</h2>
              <p>{t('{count} timestamps', { count: history.points.length })}</p>
            </div>
            <button
              autoFocus
              className="round-button"
              aria-label={t('Close sample data')}
              onClick={() => dialog.current?.close()}
            >
              <X size={18} />
            </button>
          </div>
          <div
            className="table-scroll history-data-scroll"
            role="region"
            aria-label={t('Utilization samples')}
            tabIndex={0}
          >
            <table>
              <caption className="sr-only">
                {t('Timestamped utilization percentages. A dash means unmeasured, not zero.')}
              </caption>
              <thead>
                <tr>
                  <th scope="col">{t('Time')}</th>
                  {metrics.map((metric) => (
                    <th key={metric.key} scope="col">
                      {t(metric.label)} %
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.points.map((point) => (
                  <tr key={point.timestamp}>
                    <th scope="row">{timestampLabel(point.timestamp)}</th>
                    {metrics.map((metric) => (
                      <td className="numeric" key={metric.key}>
                        {point[metric.key] === null
                          ? t('Unmeasured')
                          : utilizationLabel(point[metric.key])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </dialog>
      )}
    </>
  )
}
