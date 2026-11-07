import { useFormat } from '../lib/useFormat'
import { ArrowDownLeft, ArrowUpRight, Cpu, HardDrive, MemoryStick } from 'lucide-react'
import type { PublicNode } from '../api/contracts'

import { usePreferences } from '../preferences/context'

const icons = [Cpu, MemoryStick, HardDrive, ArrowDownLeft, ArrowUpRight]
export function UtilizationStrip({ node }: { node: PublicNode }) {
  const { nodeMetrics, utilizationLabel } = useFormat()
  const { t } = usePreferences()
  return (
    <div className="utilization-strip">
      {nodeMetrics(node).map((metric, index) => {
        const Icon = icons[index]
        return (
          <div className={`utilization-cell tone-${metric.tone}`} key={metric.key}>
            <span className="utilization-label">
              <Icon size={14} aria-hidden="true" />
              {t(metric.label)}
            </span>
            <strong className="utilization-value">{utilizationLabel(metric.value)}</strong>
            {metric.value === null ? (
              <span
                className="utilization-unknown"
                role="img"
                aria-label={t(`${metric.label} utilization unavailable`)}
              />
            ) : (
              <meter
                aria-label={t(`${metric.label} utilization`)}
                min={0}
                max={100}
                value={Math.min(100, metric.value)}
                aria-valuetext={utilizationLabel(metric.value)}
              >
                {utilizationLabel(metric.value)}
              </meter>
            )}
            <small>{t(metric.hint)}</small>
          </div>
        )
      })}
    </div>
  )
}
