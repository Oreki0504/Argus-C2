import { useFormat } from '../lib/useFormat'
import { ArrowDownLeft, ArrowUpRight, Cpu, HardDrive, MemoryStick } from 'lucide-react'
import type { PublicNode } from '../api/contracts'
import { usePreferences } from '../preferences/context'

const icons = [Cpu, MemoryStick, HardDrive, ArrowDownLeft, ArrowUpRight]

export function UtilizationStrip({
  node,
  compact = false,
}: {
  node: PublicNode
  compact?: boolean
}) {
  const { nodeMetrics, utilizationLabel } = useFormat()
  const { t } = usePreferences()
  return (
    <div className={`utilization-strip ${compact ? 'utilization-strip-compact' : ''}`}>
      {nodeMetrics(node).map((metric, index) => {
        const Icon = icons[index]
        return (
          <div
            className={`utilization-cell severity-${metric.severity} ${metric.isTraffic ? 'is-traffic' : ''}`}
            key={metric.key}
          >
            <span className="utilization-label">
              <Icon size={13} aria-hidden="true" />
              {t(metric.label)}
            </span>
            <strong className="utilization-value">{metric.displayValue}</strong>
            {metric.value !== null ? (
              <meter
                aria-label={t(`${metric.label} utilization`)}
                min={0}
                max={100}
                value={Math.min(100, metric.value)}
                aria-valuetext={utilizationLabel(metric.value)}
              >
                {utilizationLabel(metric.value)}
              </meter>
            ) : metric.isTraffic ? (
              <small className="traffic-sub">{metric.subLabel ?? metric.hint}</small>
            ) : (
              <span
                className="utilization-unknown"
                role="img"
                aria-label={t(`${metric.label} utilization unavailable`)}
              />
            )}
            {metric.isTraffic && metric.value !== null && (
              <small className="traffic-sub">{metric.subLabel ?? metric.hint}</small>
            )}
          </div>
        )
      })}
    </div>
  )
}
