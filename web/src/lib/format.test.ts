import { describe, expect, it } from 'vitest'
import { heartbeat, percent, quantity, timestampLabel } from './format'

describe('observation semantics', () => {
  it('keeps heartbeat boundary states separate', () => {
    const now = 2000
    expect(heartbeat(0, now)).toBe('Never seen')
    expect(heartbeat(now - 90, now)).toBe('Online')
    expect(heartbeat(now - 91, now)).toBe('Stale')
    expect(heartbeat(now - 300, now)).toBe('Stale')
    expect(heartbeat(now - 301, now)).toBe('Offline')
  })
  it('never presents missing data as zero and keeps bytes distinct from bit rates', () => {
    expect(quantity(null, 'rate')).toBe('Unavailable')
    expect(quantity(0, 'rate')).toBe('0 bit/s')
    expect(quantity(1000, 'rate')).toBe('1 kbit/s')
    expect(quantity(1000, 'bytes')).toBe('1 kB')
    expect(percent(null)).toBe('Unavailable')
    expect(percent(0)).toBe('0%')
    expect(timestampLabel(null)).toBe('Not observed')
  })
})
