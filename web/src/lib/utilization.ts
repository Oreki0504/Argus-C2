import type { HistoryPoint, NodeHistory, PublicNode } from '../api/contracts'
import { quantity } from './format'
import type { Language } from '../preferences/messages'

export const metrics = [
  { key: 'cpu_percent', label: 'CPU', title: 'CPU utilization', tone: 'cpu' },
  { key: 'memory_percent', label: 'Memory', title: 'Memory utilization', tone: 'memory' },
  { key: 'disk_percent', label: 'Disk', title: 'Disk utilization', tone: 'disk' },
  { key: 'inbound_percent', label: 'Inbound', title: 'Inbound bandwidth', tone: 'inbound' },
  { key: 'outbound_percent', label: 'Outbound', title: 'Outbound bandwidth', tone: 'outbound' },
] as const
export type MetricKey = (typeof metrics)[number]['key']

export function bandwidthPercent(rate: number | null, capacity: number | null) {
  if (rate === null || capacity === null || capacity <= 0) return null
  return (rate / capacity) * 100
}
export function utilizationLabel(value: number | null, language: Language = 'en') {
  return value === null
    ? '—'
    : `${new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(value)}%`
}
export function nodeMetrics(node: PublicNode, language: Language = 'en') {
  const values: Record<MetricKey, number | null> = {
    cpu_percent: node.resources.cpu_percent,
    memory_percent: node.resources.memory_percent,
    disk_percent: node.resources.disk_percent,
    inbound_percent: bandwidthPercent(node.traffic.inbound_bps, node.traffic.inbound_capacity_bps),
    outbound_percent: bandwidthPercent(
      node.traffic.outbound_bps,
      node.traffic.outbound_capacity_bps,
    ),
  }
  return metrics.map((metric) => ({
    ...metric,
    value: values[metric.key],
    hint:
      metric.key === 'inbound_percent'
        ? quantity(node.traffic.inbound_bps, 'rate', language)
        : metric.key === 'outbound_percent'
          ? quantity(node.traffic.outbound_bps, 'rate', language)
          : values[metric.key] === null
            ? 'Unavailable'
            : 'Utilization',
  }))
}

// Break both explicit null observations and missing intervals. Never bridge gaps.
export function seriesSegments(history: NodeHistory, key: MetricKey): HistoryPoint[][] {
  const segments: HistoryPoint[][] = []
  let segment: HistoryPoint[] = []
  let previous: number | null = null
  for (const point of history.points) {
    if (
      point[key] === null ||
      (previous !== null && point.timestamp - previous > history.sample_interval_seconds * 1.5)
    ) {
      if (segment.length) segments.push(segment)
      segment = []
    }
    if (point[key] !== null) segment.push(point)
    previous = point.timestamp
  }
  if (segment.length) segments.push(segment)
  return segments
}
