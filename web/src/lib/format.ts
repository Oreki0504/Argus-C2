import { translate, type Language } from '../preferences/messages'

export function heartbeat(lastSeen: number, now: number) {
  if (lastSeen === 0) return 'Never seen'
  const age = Math.max(0, now - lastSeen)
  return age <= 90 ? 'Online' : age <= 300 ? 'Stale' : 'Offline'
}

export function relativeTime(
  timestamp: number | null,
  now = Date.now() / 1000,
  language: Language = 'en',
): string {
  if (!timestamp) return translate(language, 'Not observed')
  const seconds = Math.max(0, Math.floor(now - timestamp))
  if (language === 'zh-CN') {
    if (seconds < 60) return `${seconds} 秒前`
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
    return `${Math.floor(seconds / 86400)} 天前`
  }
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export function timestampLabel(timestamp: number | null, language: Language = 'en') {
  if (!timestamp) return translate(language, 'Not observed')
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'long' }).format(
    timestamp * 1000,
  )
}

export function quantity(value: number | null, kind: 'bytes' | 'rate', language: Language = 'en') {
  if (value === null) return translate(language, 'Unavailable')
  const units =
    kind === 'bytes'
      ? ['B', 'kB', 'MB', 'GB', 'TB']
      : ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']
  let scaled = value
  let index = 0
  while (scaled >= 1000 && index < units.length - 1) {
    scaled /= 1000
    index++
  }
  return `${new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(scaled)} ${units[index]}`
}

export function percent(value: number | null, language: Language = 'en') {
  return value === null ? translate(language, 'Unavailable') : `${Math.round(value)}%`
}
