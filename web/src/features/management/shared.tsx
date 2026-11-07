import { uncertainWrite, useManagement } from './hooks'
import { useEffect, useId, useRef, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, X } from 'lucide-react'
import { usePreferences } from '../../preferences/context'
import { ErrorState, Notice } from '../../components/ui'

export function Pager({
  total,
  visible,
  cursor,
  next,
  onNext,
  onBack,
}: {
  total: number
  visible: number
  cursor: string
  next: string | null
  onNext: (cursor: string) => void
  onBack: () => void
}) {
  const { t } = usePreferences()
  return (
    <div className="management-pagination">
      <span>{t('{visible} shown · {total} total', { visible, total })}</span>
      <div className="pagination">
        <button className="button secondary compact" disabled={!cursor} onClick={onBack}>
          {t('Previous')}
        </button>
        <button
          className="button secondary compact"
          disabled={!next}
          onClick={() => next && onNext(next)}
        >
          {t('Next')}
        </button>
      </div>
    </div>
  )
}

export function SectionHeading({
  title,
  description,
  busy,
  refresh,
  children,
}: {
  title: string
  description?: string
  busy: boolean
  refresh: () => void
  children?: ReactNode
}) {
  const { t } = usePreferences()
  return (
    <div className="management-section-heading">
      <div>
        <h2>{t(title)}</h2>
        {description && <p>{t(description)}</p>}
      </div>
      <div className="management-actions">
        <button className="button secondary" disabled={busy} onClick={refresh}>
          <RefreshCw size={14} className={busy ? 'spin' : ''} />
          {t('Refresh')}
        </button>
        {children}
      </div>
    </div>
  )
}

export function Dialog({
  title,
  children,
  onClose,
  busy = false,
  wide = false,
}: {
  title: string
  children: ReactNode
  onClose: () => void
  busy?: boolean
  wide?: boolean
}) {
  const { t } = usePreferences()
  const dialog = useRef<HTMLDialogElement>(null)
  const id = useId()
  useEffect(() => {
    const element = dialog.current
    const previous = document.activeElement
    element?.showModal()
    return () => {
      element?.close()
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [])
  return (
    <dialog
      className={`management-dialog ${wide ? 'dialog-wide' : ''}`}
      ref={dialog}
      aria-labelledby={id}
      onCancel={(event) => {
        event.preventDefault()
        if (!busy) onClose()
      }}
    >
      <div className="management-dialog-heading">
        <h2 id={id}>{title}</h2>
        <button
          className="round-button"
          type="button"
          disabled={busy}
          onClick={onClose}
          aria-label={t('Close dialog')}
        >
          <X size={18} />
        </button>
      </div>
      <div className="management-dialog-body">{children}</div>
    </dialog>
  )
}

export function MutationError({ error }: { error: unknown }) {
  const { t } = usePreferences()
  if (!error) return null
  return (
    <>
      <ErrorState error={error} />
      {uncertainWrite(error) && (
        <Notice kind="warning">
          {t(
            'The request may have reached the server. Refresh the relevant records before submitting again.',
          )}
        </Notice>
      )}
    </>
  )
}
export function AuditLink({
  nodeId,
  taskId,
  subjectId,
}: {
  nodeId?: string
  taskId?: string
  subjectId?: string
}) {
  const { t } = usePreferences()
  const { identity } = useManagement()
  if (!identity.capabilities.includes('audit:read')) return null
  const params = new URLSearchParams()
  if (nodeId) params.set('node_id', nodeId)
  if (taskId) params.set('task_id', taskId)
  if (subjectId) params.set('subject_id', subjectId)
  return (
    <Link className="text-link" to={`/manage/audit?${params}`}>
      {t('Related audit')}
    </Link>
  )
}
