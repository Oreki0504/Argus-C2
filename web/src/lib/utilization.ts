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
export type SeverityTone = 'normal' | 'warning' | 'critical' | 'unknown'

export function utilizationSeverity(value: number | null): SeverityTone {
  if (value === null || Number.isNaN(value)) return 'unknown'
  if (value >= 80) return 'critical'
  if (value >= 60) return 'warning'
  return 'normal'
}

export function bandwidthPercent(rate: number | null, capacity: number | null) {
  if (rate === null || capacity === null || capacity <= 0) return null
  return (rate / capacity) * 100
}

export function utilizationLabel(value: number | null, language: Language = 'en') {
  return value === null
    ? '—'
    : `${new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(value)}%`
}

export function compactRate(bps: number | null, language: Language = 'en') {
  if (bps === null) return '—'
  const units = ['b/s', 'K/s', 'M/s', 'G/s', 'T/s']
  let scaled = bps
  let index = 0
  while (scaled >= 1000 && index < units.length - 1) {
    scaled /= 1000
    index++
  }
  const digits = scaled >= 100 ? 0 : 1
  return `${new Intl.NumberFormat(language, { maximumFractionDigits: digits }).format(scaled)}${units[index]}`
}

export function compactBytes(bytes: number | null, language: Language = 'en') {
  if (bytes === null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let scaled = bytes
  let index = 0
  while (scaled >= 1000 && index < units.length - 1) {
    scaled /= 1000
    index++
  }
  return `${new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(scaled)} ${units[index]}`
}

export function nodeMetrics(node: PublicNode, language: Language = 'en') {
  const inboundPct = bandwidthPercent(node.traffic.inbound_bps, node.traffic.inbound_capacity_bps)
  const outboundPct = bandwidthPercent(
    node.traffic.outbound_bps,
    node.traffic.outbound_capacity_bps,
  )
  const values: Record<MetricKey, number | null> = {
    cpu_percent: node.resources.cpu_percent,
    memory_percent: node.resources.memory_percent,
    disk_percent: node.resources.disk_percent,
    inbound_percent: inboundPct,
    outbound_percent: outboundPct,
  }
  return metrics.map((metric) => {
    const isTraffic = metric.key === 'inbound_percent' || metric.key === 'outbound_percent'
    const rawBps =
      metric.key === 'inbound_percent' ? node.traffic.inbound_bps : node.traffic.outbound_bps
    const totalBytes =
      metric.key === 'inbound_percent'
        ? node.traffic.sampled_inbound_bytes
        : node.traffic.sampled_outbound_bytes
    const pct = values[metric.key]
    return {
      ...metric,
      value: pct,
      severity: utilizationSeverity(pct),
      isTraffic,
      displayValue: isTraffic ? compactRate(rawBps, language) : utilizationLabel(pct, language),
      subLabel:
        metric.key === 'inbound_percent'
          ? totalBytes !== null
            ? `↓ ${compactBytes(totalBytes, language)}`
            : compactRate(node.traffic.inbound_bps, language)
          : metric.key === 'outbound_percent'
            ? totalBytes !== null
              ? `↑ ${compactBytes(totalBytes, language)}`
              : compactRate(node.traffic.outbound_bps, language)
            : null,
      hint:
        metric.key === 'inbound_percent'
          ? quantity(node.traffic.inbound_bps, 'rate', language)
          : metric.key === 'outbound_percent'
            ? quantity(node.traffic.outbound_bps, 'rate', language)
            : pct === null
              ? 'Unavailable'
              : 'Utilization',
    }
  })
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
