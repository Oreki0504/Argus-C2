import { describe, expect, it } from 'vitest'
import { nodeHistorySchema } from '../api/contracts'
import { fleetFixture, historyFixture } from '../mocks/fixtures'
import { bandwidthPercent, nodeMetrics, seriesSegments } from './utilization'

describe('bandwidth and sampled chart semantics', () => {
  it('uses configured capacity and distinguishes missing, zero and over-capacity traffic', () => {
    expect(bandwidthPercent(12_400_000, 100_000_000)).toBeCloseTo(12.4)
    expect(bandwidthPercent(0, 100_000_000)).toBe(0)
    expect(bandwidthPercent(null, 100_000_000)).toBeNull()
    expect(bandwidthPercent(12_400_000, null)).toBeNull()
    expect(bandwidthPercent(12_400_000, 0)).toBeNull()
    expect(bandwidthPercent(120_000_000, 100_000_000)).toBe(120)
    const node = fleetFixture().nodes[3]
    expect(nodeMetrics(node)[3].value).toBeNull()
    expect(nodeMetrics(node)[3].hint).toBe('640 kbit/s')
  })
  it('breaks lines across explicit missing data and absent timestamps', () => {
    const base = historyFixture(fleetFixture().nodes[0], '1h')
    const start = base.window_start
    const point = base.points[0]
    const history = {
      ...base,
      points: [
        { ...point, timestamp: start, cpu_percent: 0 },
        { ...point, timestamp: start + 60, cpu_percent: 20 },
        { ...point, timestamp: start + 120, cpu_percent: null },
        { ...point, timestamp: start + 180, cpu_percent: 30 },
        { ...point, timestamp: start + 360, cpu_percent: 40 },
      ],
    }
    expect(
      seriesSegments(history, 'cpu_percent').map((segment) => segment.map((p) => p.cpu_percent)),
    ).toEqual([[0, 20], [30], [40]])
  })
  it('rejects unordered, out-of-window or sensitive history fields', () => {
    const history = historyFixture(fleetFixture().nodes[0], '1h')
    expect(nodeHistorySchema.safeParse(history).success).toBe(true)
    expect(
      nodeHistorySchema.safeParse({ ...history, points: [...history.points].reverse() }).success,
    ).toBe(false)
    expect(
      nodeHistorySchema.safeParse({
        ...history,
        points: [{ ...history.points[0], timestamp: history.window_end + 1 }],
      }).success,
    ).toBe(false)
    expect(
      nodeHistorySchema.safeParse({
        ...history,
        points: [{ ...history.points[0], ip: '192.0.2.1' }],
      }).success,
    ).toBe(false)
  })
})
