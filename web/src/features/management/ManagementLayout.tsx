import { Link, Navigate, NavLink, Outlet, useLocation } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { useViewer } from '../auth/context'
import { usePreferences } from '../../preferences/context'
import { EmptyState } from '../../components/ui'
import { canManage, managementSections } from './access'

export function ManagementLayout() {
  const viewer = useViewer()
  const { t } = usePreferences()
  const { pathname } = useLocation()
  const sections = managementSections.filter((section) => canManage(viewer, section.capability))
  const current = pathname.split('/')[2]
  if (!sections.length || (current && !sections.some((section) => section.path === current)))
    return (
      <EmptyState title="Management unavailable">
        {t('Your account does not have access to this page.')}{' '}
        <Link className="text-link" to="/">
          {t('Return to overview')}
        </Link>
      </EmptyState>
    )
  if (!current) return <Navigate to={`/manage/${sections[0].path}`} replace />
  return (
    <section className="management-page">
      <div className="management-heading">
        <div>
          <h1>{t('Management')}</h1>
          <p>{t('Operate your fleet and control access.')}</p>
        </div>
        <span className="management-badge">
          <ShieldCheck size={15} />
          {t('Administrator')}
        </span>
      </div>
      <nav className="management-tabs" aria-label={t('Management sections')}>
        {sections.map((section) => (
          <NavLink key={section.path} to={`/manage/${section.path}`}>
            {t(section.label)}
          </NavLink>
        ))}
      </nav>
      <Outlet />
    </section>
  )
}
