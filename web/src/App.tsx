import { lazy, Suspense, useEffect } from 'react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { EmptyState } from './components/ui'
import { Login } from './features/auth/Login'
import { AccountPage } from './features/auth/Account'
import { SessionGate } from './features/auth/SessionGate'
import { FleetPage } from './features/fleet/Fleet'
import { AgentOverview } from './features/fleet/AgentOverview'
import { useViewer } from './features/auth/context'
import { usePreferences } from './preferences/context'
import { translate } from './preferences/messages'
import { NodeDetail } from './features/nodes/NodeDetail'
import { SetupPage } from './features/setup/Setup'
import { TrafficPage } from './features/traffic/Traffic'
import { ManagementLayout } from './features/management/ManagementLayout'
import { TasksPage, TaskDetailPage } from './features/management/Tasks'
import { AgentsPage } from './features/management/Agents'
import { AuditPage } from './features/management/Audit'
import { UsersPage } from './features/management/Users'

const PreviewToolbar =
  import.meta.env.DEV && import.meta.env.MODE === 'mock'
    ? lazy(() => import('./mocks/PreviewToolbar'))
    : null
export function App() {
  const { pathname } = useLocation()
  const { language } = usePreferences()
  useEffect(() => {
    const label =
      pathname === '/'
        ? 'Overview'
        : pathname.startsWith('/manage')
          ? 'Management'
          : pathname.startsWith('/fleet/')
            ? 'Server detail'
            : pathname.slice(1)
    document.title = `ARGUS · ${translate(language, label.charAt(0).toUpperCase() + label.slice(1))}`
  }, [pathname, language])
  useEffect(() => {
    document.getElementById('main-content')?.focus()
  }, [pathname])
  return (
    <>
      {PreviewToolbar && (
        <Suspense>
          <PreviewToolbar />
        </Suspense>
      )}
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route element={<SessionGate />}>
          <Route element={<AppShell />}>
            <Route index element={<AgentOverview />} />
            <Route path="/fleet" element={<FleetRoute />} />
            <Route path="/fleet/:publicId" element={<NodeDetail />} />
            <Route path="/traffic" element={<TrafficPage />} />
            <Route path="/account" element={<AccountPage />} />
            <Route path="/manage" element={<ManagementLayout />}>
              <Route path="tasks" element={<TasksPage />} />
              <Route path="tasks/:taskId" element={<TaskDetailPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="users" element={<UsersPage />} />
            </Route>
          </Route>
        </Route>
        <Route
          path="*"
          element={
            <EmptyState title="Page not found">
              This page is not available. <Link to="/">Return to overview</Link>
            </EmptyState>
          }
        />
      </Routes>
    </>
  )
}

function FleetRoute() {
  const identity = useViewer()
  return identity?.role === 'Admin' ? <FleetPage /> : <AgentOverview />
}
