import {
  capabilitySchema,
  type Identity,
  type PublicNode,
  type Summary,
  type NodeHistory,
  type HistoryRange,
} from '../api/contracts'

export const scenarios = [
  'guest',
  'admin',
  'user',
  'setup',
  'login',
  'empty',
  'large-fleet',
  'expired',
  'forbidden',
  'unavailable',
  'oidc-error',
  'no-capability',
] as const
export type Scenario = (typeof scenarios)[number]
export const csrf = 'development-only-csrf-proof'
export function identity(role: 'Admin' | 'User'): Identity {
  return {
    principal_id: `preview-${role.toLowerCase()}`,
    name: role === 'Admin' ? 'Alex Morgan' : 'Sam Taylor',
    role,
    csrf_token: csrf,
    capabilities: role === 'Admin' ? [...capabilitySchema.options] : ['summary:read'],
  }
}

const names = [
  'Production · North',
  'Production · West',
  'Edge · Tokyo',
  'Build runner · 01',
  'Staging · Atlas',
  'Archive · 01',
]
export function fleetFixture(count = 6, now = Math.floor(Date.now() / 1000)): Summary {
  const nodes: PublicNode[] = Array.from({ length: count }, (_, index) => {
    const i = index % 6
    const available = i !== 5
    const stale = i === 3 || i === 4
    return {
      public_id: `srv-${String(index + 1).padStart(4, '0')}`,
      display_name: count <= 6 ? names[i] : `Server · ${String(index + 1).padStart(3, '0')}`,
      last_seen_at: now - [12, 28, 41, 180, 740, 3600][i],
      system: {
        os: available ? ['Ubuntu 24.04', 'Debian 13', 'Ubuntu 24.04'][i % 3] : null,
        architecture: available ? 'x86_64' : null,
        kernel: available ? '6.8.0' : null,
        uptime_seconds: available ? 2419200 + index * 120 : null,
      },
      resources: {
        as_of: available ? now - (stale ? 780 : 35) : null,
        cpu_percent: available ? [24, 42, 17, 68, 8, 0][i] : null,
        memory_percent: available ? [58, 64, 31, 76, 22, 0][i] : null,
        disk_percent: available ? [36, 52, 28, 61, 44, 0][i] : null,
      },
      traffic: {
        as_of: available ? now - (stale ? 780 : 35) : null,
        inbound_bps: available ? [12400000, 8600000, 2100000, 640000, 0, 0][i] : null,
        outbound_bps: available ? [4200000, 1700000, 980000, 120000, 0, 0][i] : null,
        inbound_capacity_bps: available && i !== 3 ? 100_000_000 : null,
        outbound_capacity_bps: available && i !== 3 ? 50_000_000 : null,
        sampled_inbound_bytes: available ? 1260000000 * (i + 1) : null,
        sampled_outbound_bytes: available ? 480000000 * (i + 1) : null,
        coverage_percent: available ? [100, 100, 96, 71, 42, 0][i] : null,
      },
    }
  })
  return {
    generated_at: now,
    window_start: now - 86400,
    window_end: now,
    sample_interval_seconds: 30,
    nodes,
  }
}

// Illustrative periodic observations, only imported by explicit development mocks.
export function historyFixture(
  node: PublicNode,
  range: HistoryRange,
  now = Math.floor(Date.now() / 1000),
): NodeHistory {
  const duration = { '1h': 3600, '24h': 86400, '7d': 604800 }[range]
  const interval = { '1h': 60, '24h': 900, '7d': 3600 }[range]
  const start = now - duration
  const variation = Number(node.public_id.slice(-4))
  const lastResource = node.resources.as_of ?? 0
  const lastTraffic = node.traffic.as_of ?? 0
  const clamp = (value: number) => Math.round(Math.max(0, Math.min(100, value)) * 10) / 10
  const wave = (index: number) => Math.sin(index * 0.35 + variation) * 6 + Math.cos(index * 0.9) * 3
  const points =
    node.last_seen_at === 0
      ? []
      : Array.from({ length: duration / interval + 1 }, (_, index) => {
          const timestamp = start + index * interval
          const gap = variation === 3 && index >= 21 && index <= 26
          const resources = !gap && timestamp <= lastResource
          const traffic = !gap && timestamp <= lastTraffic
          return {
            timestamp,
            cpu_percent:
              resources && node.resources.cpu_percent !== null
                ? clamp(node.resources.cpu_percent + wave(index) * 1.6)
                : null,
            memory_percent:
              resources && node.resources.memory_percent !== null
                ? clamp(node.resources.memory_percent + wave(index) * 0.35)
                : null,
            disk_percent:
              resources && node.resources.disk_percent !== null
                ? clamp(node.resources.disk_percent - (duration / interval - index) * 0.015)
                : null,
            inbound_percent:
              traffic &&
              node.traffic.inbound_capacity_bps !== null &&
              node.traffic.inbound_bps !== null
                ? clamp(
                    (node.traffic.inbound_bps / node.traffic.inbound_capacity_bps) * 100 +
                      wave(index) * 0.7,
                  )
                : null,
            outbound_percent:
              traffic &&
              node.traffic.outbound_capacity_bps !== null &&
              node.traffic.outbound_bps !== null
                ? clamp(
                    (node.traffic.outbound_bps / node.traffic.outbound_capacity_bps) * 100 +
                      wave(index) * 0.4,
                  )
                : null,
          }
        })
  return {
    public_id: node.public_id,
    range,
    window_start: start,
    window_end: now,
    sample_interval_seconds: interval,
    points,
  }
}
