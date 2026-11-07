import { useFormat } from '../../lib/useFormat'
import { usePreferences } from '../../preferences/context'
import { useId, useState } from 'react'
import type { NodeHistory } from '../../api/contracts'
import { seriesSegments, type MetricKey } from '../../lib/utilization'

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
  const y = (value: number) => 72 - (value / max) * 60
  const index = Math.min(inspected ?? history.points.length - 1, history.points.length - 1)
  const selected = history.points[index]
  const mean = valid.length
    ? valid.reduce((sum, point) => sum + point[metricKey]!, 0) / valid.length
    : null
  const timeLabel = (value: number) =>
    new Intl.DateTimeFormat(language, {
      hour: '2-digit',
      minute: '2-digit',
      ...(history.range === '7d' ? { month: 'short', day: 'numeric' } : {}),
    }).format(value * 1000)
  return (
    <section className={`history-chart panel tone-${tone}`} aria-labelledby={`${id}-heading`}>
      <div className="chart-heading">
        <h3 id={`${id}-heading`}>
          <span className="chart-dot" />
          {t(title)}
        </h3>
        <span>
          {t('Average')} <strong>{utilizationLabel(mean)}</strong>
        </span>
      </div>
      {valid.length ? (
        <>
          <svg
            className="utilization-chart"
            viewBox="0 0 360 100"
            preserveAspectRatio="none"
            role="img"
            aria-labelledby={`${id}-title ${id}-description`}
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
              {t(
                '{count} measured samples. Average {average}. Gaps are unmeasured. Use the sample slider or data table for exact values.',
                { count: valid.length, average: utilizationLabel(mean) },
              )}
            </desc>
            <defs>
              <linearGradient id={`${id}-fill`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="currentColor" stopOpacity=".14" />
                <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[0, 0.25, 0.5, 0.75, 1].map((fraction) => (
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
                    d={`${line} L${x(segment[segment.length - 1].timestamp)},72 L${x(segment[0].timestamp)},72 Z`}
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
            {selected && (
              <g>
                <line
                  className="chart-crosshair"
                  x1={x(selected.timestamp)}
                  x2={x(selected.timestamp)}
                  y1={12}
                  y2={72}
                />
                {selected[metricKey] !== null && (
                  <circle
                    className="chart-point"
                    cx={x(selected.timestamp)}
                    cy={y(selected[metricKey])}
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
          <div className="chart-inspector">
            <label htmlFor={`${id}-sample`} className="sr-only">
              {t('Inspect {title} sample', { title: t(title) })}
            </label>
            <input
              id={`${id}-sample`}
              type="range"
              min={0}
              max={history.points.length - 1}
              value={index}
              onChange={(event) => setInspected(Number(event.target.value))}
              aria-valuetext={
                selected
                  ? `${timestampLabel(selected.timestamp)}: ${selected[metricKey] === null ? t('Unmeasured') : utilizationLabel(selected[metricKey])}`
                  : t('Unavailable')
              }
            />
            <output htmlFor={`${id}-sample`}>
              <time>{selected ? timeLabel(selected.timestamp) : '—'}</time>
              <strong>
                {selected?.[metricKey] == null
                  ? t('Unmeasured')
                  : utilizationLabel(selected[metricKey])}
              </strong>
            </output>
          </div>
        </>
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
      <div className="chart-footnote">
        <span>
          {t('{valid} / {total} returned samples measured', {
            valid: valid.length,
            total: history.points.length,
          })}
        </span>
        <span>{t('Gaps stay unmeasured')}</span>
      </div>
    </section>
  )
}
