import { usePreferences } from '../preferences/context'
import * as format from './format'
import * as utilization from './utilization'
import type { PublicNode } from '../api/contracts'

export function useFormat() {
  const { language } = usePreferences()
  return {
    quantity: (value: number | null, kind: 'bytes' | 'rate') =>
      format.quantity(value, kind, language),
    relativeTime: (timestamp: number | null, now?: number) =>
      format.relativeTime(timestamp, now, language),
    timestampLabel: (timestamp: number | null) => format.timestampLabel(timestamp, language),
    percent: (value: number | null) => format.percent(value, language),
    utilizationLabel: (value: number | null) => utilization.utilizationLabel(value, language),
    nodeMetrics: (node: PublicNode) => utilization.nodeMetrics(node, language),
  }
}
