import { useFormat } from '../../lib/useFormat'
import { usePreferences } from '../../preferences/context'
import { useId, useState } from 'react'
import type { NodeHistory } from '../../api/contracts'
import { seriesSegments, utilizationSeverity, type MetricKey } from '../../lib/utilization'

export function UtilizationChart({
  history,
  metricKey,
  title,
  tone,
}: {
  history: NodeHistory
  metricKey: MetricKey
  title: string
  tone: string
}) {
  const { timestampLabel, utilizationLabel } = useFormat()
  const { t, language } = usePreferences()
  const id = useId()
  const [inspected, setInspected] = useState<number | null>(null)
  const valid = history.points.filter((point) => point[metricKey] !== null)
  const segments = seriesSegments(history, metricKey)
  const max = Math.max(
    100,
    Math.ceil(Math.max(0, ...valid.map((point) => point[metricKey]!)) / 25) * 25,
  )
  const x = (time: number) =>
    32 + ((time - history.window_start) / (history.window_end - history.window_start)) * 314
  const y = (value: number) => 76 - (value / max) * 62

  const latestValid = valid.length ? valid[valid.length - 1] : null
  const activePoint = inspected !== null ? history.points[inspected] : latestValid
  const mean = valid.length
    ? valid.reduce((sum, point) => sum + point[metricKey]!, 0) / valid.length
    : null
  const severity = utilizationSeverity(latestValid?.[metricKey] ?? mean)

  const timeLabel = (value: number) =>
    new Intl.DateTimeFormat(language, {
      hour: '2-digit',
      minute: '2-digit',
      ...(history.range === '7d' ? { month: 'short', day: 'numeric' } : {}),
    }).format(value * 1000)

  return (
    <section
      className={`history-chart panel tone-${tone} severity-${severity}`}
      aria-label={t('Inspect {title} sample', { title: t(title) })}
    >
      <div className="chart-heading">
        <h3 id={`${id}-heading`}>
          <span className="chart-dot" />
          {t(title)}
        </h3>
        <div className="chart-stats-meta">
          {inspected !== null && activePoint ? (
            <span className="chart-live-readout">
              <time>{timeLabel(activePoint.timestamp)}</time>
              <strong>
                {activePoint[metricKey] === null
                  ? t('Unmeasured')
                  : utilizationLabel(activePoint[metricKey])}
              </strong>
            </span>
          ) : (
            <>
              {latestValid && (
                <span className="chart-latest-badge">
                  <strong>{utilizationLabel(latestValid[metricKey])}</strong>
                </span>
              )}
              <span className="chart-avg-label">
                {t('Average')} <strong>{utilizationLabel(mean)}</strong>
              </span>
            </>
          )}
        </div>
      </div>

      {valid.length ? (
        <svg
          className="utilization-chart"
          viewBox="0 0 360 100"
          preserveAspectRatio="none"
          role="slider"
          tabIndex={0}
          aria-label={t('Inspect {title} sample', { title: t(title) })}
          aria-valuemin={0}
          aria-valuemax={Math.max(0, history.points.length - 1)}
          aria-valuenow={inspected ?? history.points.length - 1}
          aria-valuetext={
            activePoint
              ? `${timestampLabel(activePoint.timestamp)}: ${
                  activePoint[metricKey] === null
                    ? t('Unmeasured')
                    : utilizationLabel(activePoint[metricKey])
                }`
              : t('Unavailable')
          }
          onKeyDown={(event) => {
            if (!history.points.length) return
            const current = inspected ?? history.points.length - 1
            if (event.key === 'ArrowLeft') {
              event.preventDefault()
              setInspected(Math.max(0, current - 1))
            } else if (event.key === 'ArrowRight') {
              event.preventDefault()
              setInspected(Math.min(history.points.length - 1, current + 1))
            } else if (event.key === 'Home') {
              event.preventDefault()
              setInspected(0)
            } else if (event.key === 'End') {
              event.preventDefault()
              setInspected(history.points.length - 1)
            } else if (event.key === 'Escape') {
              setInspected(null)
            }
          }}
          onBlur={() => setInspected(null)}
          onPointerLeave={() => setInspected(null)}
          onPointerMove={(event) => {
            const bounds = event.currentTarget.getBoundingClientRect()
            const time =
              history.window_start +
              Math.max(
                0,
                Math.min(1, (((event.clientX - bounds.left) / bounds.width) * 360 - 32) / 314),
              ) *
                (history.window_end - history.window_start)
            let nearest = 0
            for (let i = 1; i < history.points.length; i++)
              if (
                Math.abs(history.points[i].timestamp - time) <
                Math.abs(history.points[nearest].timestamp - time)
              )
                nearest = i
            setInspected(nearest)
          }}
        >
          <title id={`${id}-title`}>{t('{title} history', { title: t(title) })}</title>
          <desc id={`${id}-description`}>
            {t('{count} measured samples. Average {average}. Gaps are unmeasured.', {
              count: valid.length,
              average: utilizationLabel(mean),
            })}
          </desc>
          <defs>
            <linearGradient id={`${id}-fill`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="currentColor" stopOpacity=".18" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0, 0.5, 1].map((fraction) => (
            <g key={fraction}>
              <line
                className="chart-gridline"
                x1={32}
                x2={346}
                y1={y(fraction * max)}
                y2={y(fraction * max)}
              />
              <text x={26} y={y(fraction * max) + 3} textAnchor="end" className="chart-axis">
                {fraction * max}%
              </text>
            </g>
          ))}
          {segments.map((segment, i) => {
            const line = segment
              .map(
                (point, index) =>
                  `${index ? 'L' : 'M'}${x(point.timestamp)},${y(point[metricKey]!)}`,
              )
              .join(' ')
            return (
              <g key={i}>
                <path
                  d={`${line} L${x(segment[segment.length - 1].timestamp)},76 L${x(segment[0].timestamp)},76 Z`}
                  fill={`url(#${id}-fill)`}
                />
                <path className="chart-line" d={line} />
                {segment.length === 1 && (
                  <circle
                    cx={x(segment[0].timestamp)}
                    cy={y(segment[0][metricKey]!)}
                    r={3}
                    fill="currentColor"
                  />
                )}
              </g>
            )
          })}
          {inspected !== null && activePoint && (
            <g>
              <line
                className="chart-crosshair"
                x1={x(activePoint.timestamp)}
                x2={x(activePoint.timestamp)}
                y1={14}
                y2={76}
              />
              {activePoint[metricKey] !== null && (
                <circle
                  className="chart-point"
                  cx={x(activePoint.timestamp)}
                  cy={y(activePoint[metricKey])}
                  r={4}
                />
              )}
            </g>
          )}
          {[0, 0.5, 1].map((fraction, i) => (
            <text
              key={i}
              className="chart-axis"
              x={32 + 314 * fraction}
              y={94}
              textAnchor={i === 0 ? 'start' : i === 2 ? 'end' : 'middle'}
            >
              {timeLabel(
                history.window_start + (history.window_end - history.window_start) * fraction,
              )}
            </text>
          ))}
        </svg>
      ) : (
        <div className="chart-unavailable">
          <span>{t('No measured utilization')}</span>
          <p>
            {metricKey.endsWith('bound_percent')
              ? t('Waiting for traffic samples and a configured bandwidth capacity.')
              : t('This agent has no resource samples in the selected window.')}
          </p>
        </div>
      )}
    </section>
  )
}
