import type { ReactNode } from 'react'
import { AlertCircle, ArrowDownLeft, ArrowUpRight, LoaderCircle, ShieldCheck } from 'lucide-react'
import { ApiError } from '../api/client'
import { useFormat } from '../lib/useFormat'
import { usePreferences } from '../preferences/context'

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck size={23} strokeWidth={1.6} />
      </span>
      <span>ARGUS</span>
      {!compact && <span className="brand-caption">CONSOLE</span>}
    </div>
  )
}

export function Status({ children }: { children: string }) {
  const { t } = usePreferences()
  return (
    <span className={`status status-${children.toLowerCase().replaceAll(' ', '-')}`}>
      <span className="status-dot" />
      {t(children)}
    </span>
  )
}

export function Notice({
  children,
  kind = 'info',
}: {
  children: ReactNode
  kind?: 'info' | 'warning'
}) {
  return (
    <div className={`notice notice-${kind}`}>
      <AlertCircle size={17} aria-hidden="true" />
      <div>{children}</div>
    </div>
  )
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const { t } = usePreferences()
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={22} />
      <div>
        <strong>{t('We couldn’t complete that request')}</strong>
        <p>
          {t(error instanceof ApiError ? error.message : 'Something went wrong. Please try again.')}
        </p>
        {retry && (
          <button className="button secondary" onClick={retry}>
            {t('Try again')}
          </button>
        )}
      </div>
    </div>
  )
}

export function Loading({ label = 'Loading console' }: { label?: string }) {
  const { t } = usePreferences()
  return (
    <div className="loading-state" role="status">
      <LoaderCircle className="spin" size={22} />
      {t(label)}…
    </div>
  )
}

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  const { t } = usePreferences()
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <ShieldCheck size={28} />
      </span>
      <h2>{t(title)}</h2>
      <p>{typeof children === 'string' ? t(children) : children}</p>
    </div>
  )
}

export function PageHeader({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string
  title: string
  description: string
  children?: ReactNode
}) {
  const { t } = usePreferences()
  return (
    <div className="page-header">
      <div>
        <p className="eyebrow">{t(eyebrow)}</p>
        <h1>{t(title)}</h1>
        <p className="page-description">{t(description)}</p>
      </div>
      {children && <div className="page-actions">{children}</div>}
    </div>
  )
}

export function ResourceMeter({ value, label }: { value: number | null; label: string }) {
  const { percent } = useFormat()
  return (
    <span className="resource-meter">
      <span>{percent(value)}</span>
      {value !== null && (
        <meter aria-label={label} min={0} max={100} low={70} high={90} optimum={30} value={value}>
          {percent(value)}
        </meter>
      )}
    </span>
  )
}

export function Direction({ inbound }: { inbound: boolean }) {
  const { t } = usePreferences()
  return (
    <span className={`direction ${inbound ? 'inbound' : 'outbound'}`}>
      {inbound ? <ArrowDownLeft size={16} /> : <ArrowUpRight size={16} />}
      {t(inbound ? 'Inbound' : 'Outbound')}
    </span>
  )
}
