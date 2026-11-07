import { uncertainWrite, useListNavigation, useManagement } from './hooks'
import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { management } from '../../api/management'
import type { ManagedUser } from '../../api/management-contracts'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { EmptyState, ErrorState, Loading, Notice, Status } from '../../components/ui'
import { canManage } from './access'
import { AuditLink, Dialog, MutationError, Pager, SectionHeading } from './shared'

export function UsersPage() {
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const { identity, key } = useManagement()
  const nav = useListNavigation(['q', 'status'])
  const [selected, setSelected] = useState<ManagedUser | null>(null)
  const [notice, setNotice] = useState('')
  const filters = { ...nav.filters, cursor: nav.cursor, limit: 8 }
  const query = useQuery({
    queryKey: [...key, 'users', filters],
    queryFn: ({ signal }) => management.users(filters, signal),
  })
  return (
    <>
      <SectionHeading
        title="Users & access"
        description="Approve identities and manage their Console access."
        busy={query.isFetching}
        refresh={() => void query.refetch()}
      />
      {notice && (
        <p className="management-success" role="status">
          {t(notice)}
        </p>
      )}
      <div className="management-filters">
        <input
          aria-label={t('Search users')}
          placeholder={t('Name or identity subject')}
          value={nav.filters.q}
          onChange={(event) => nav.change('q', event.target.value)}
        />
        <select
          aria-label={t('User access')}
          value={nav.filters.status}
          onChange={(event) => nav.change('status', event.target.value)}
        >
          <option value="">{t('All access states')}</option>
          {['pending', 'active', 'disabled'].map((state) => (
            <option key={state} value={state}>
              {t(state)}
            </option>
          ))}
        </select>
      </div>
      {query.isPending ? (
        <Loading label="Loading users" />
      ) : query.isError ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : (
        <section className="panel management-table-panel">
          {query.data.items.length ? (
            <div
              className="table-scroll"
              role="region"
              aria-label={t('Console users')}
              tabIndex={0}
            >
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t('User')}</th>
                    <th scope="col">{t('Role')}</th>
                    <th scope="col">{t('Access')}</th>
                    <th scope="col">{t('Last sign-in')}</th>
                    <th scope="col">{t('Actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((user) => (
                    <tr key={user.id}>
                      <th scope="row">
                        {user.name}
                        <small>{user.subject}</small>
                      </th>
                      <td>
                        <Status>{user.role}</Status>
                      </td>
                      <td>
                        <Status>{user.status}</Status>
                      </td>
                      <td className="management-time">{timestampLabel(user.last_login_at)}</td>
                      <td>
                        {user.id === identity.principal_id ? (
                          <span className="muted">{t('Current account')}</span>
                        ) : canManage(identity, 'users:write') ? (
                          <button
                            className="text-action"
                            aria-label={t(
                              user.status === 'pending'
                                ? 'Review access for {name}'
                                : 'Edit access for {name}',
                              { name: user.name },
                            )}
                            onClick={() => {
                              setNotice('')
                              setSelected(user)
                            }}
                          >
                            {t(user.status === 'pending' ? 'Review access' : 'Edit access')}
                          </button>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No matching users">Try another name or access filter.</EmptyState>
          )}
          <Pager
            total={query.data.total}
            visible={query.data.items.length}
            cursor={nav.cursor}
            next={query.data.next_cursor}
            onNext={nav.advance}
            onBack={nav.back}
          />
        </section>
      )}
      <p className="management-note">
        {t(
          'New users appear after signing in with the configured identity provider. Approval is required before Console access is granted.',
        )}
      </p>
      {selected && (
        <UserAccessDialog
          user={selected}
          onClose={() => setSelected(null)}
          onDone={(message) => {
            setNotice(message)
            setSelected(null)
          }}
        />
      )}
    </>
  )
}

function UserAccessDialog({
  user,
  onClose,
  onDone,
}: {
  user: ManagedUser
  onClose: () => void
  onDone: (message: string) => void
}) {
  const { t } = usePreferences()
  const { identity, refresh } = useManagement()
  const [role, setRole] = useState(user.role)
  const [status, setStatus] = useState<'active' | 'disabled'>(
    user.status === 'disabled' ? 'disabled' : 'active',
  )
  const [confirm, setConfirm] = useState('')
  const [grant, setGrant] = useState(false)
  const [mode, setMode] = useState<'edit' | 'revoke'>('edit')
  const promotion = user.role !== 'Admin' && role === 'Admin'
  const mutation = useMutation({
    mutationFn: async () => {
      if (mode === 'revoke') await management.revokeSessions(user.id, identity.csrf_token)
      else
        await management.updateUser(
          user.id,
          { role, status, expected_version: user.version, confirm_subject: confirm },
          identity.csrf_token,
        )
    },
    onSuccess: () => {
      void refresh()
      onDone(
        mode === 'revoke'
          ? 'Sessions revoked.'
          : 'Access updated. Existing sessions have been revoked.',
      )
    },
  })
  return (
    <Dialog
      title={t(mode === 'revoke' ? 'Revoke user sessions' : 'Edit user access')}
      onClose={onClose}
      busy={mutation.isPending}
    >
      <form
        className="management-form"
        onSubmit={(event) => {
          event.preventDefault()
          if (confirm === user.subject && (!promotion || grant || mode === 'revoke'))
            mutation.mutate()
        }}
      >
        <div className="user-identity">
          <strong>{user.name}</strong>
          <span>{user.issuer}</span>
          <code>{user.subject}</code>
        </div>
        {mode === 'edit' ? (
          <>
            <div className="form-two-columns">
              <div>
                <label htmlFor="user-role">{t('Role')}</label>
                <select
                  id="user-role"
                  value={role}
                  onChange={(event) => {
                    setRole(event.target.value as ManagedUser['role'])
                    setGrant(false)
                  }}
                >
                  <option value="User">{t('User')}</option>
                  <option value="Admin">{t('Administrator')}</option>
                </select>
              </div>
              <div>
                <label htmlFor="user-status">{t('Access')}</label>
                <select
                  id="user-status"
                  value={status}
                  onChange={(event) => setStatus(event.target.value as 'active' | 'disabled')}
                >
                  <option value="active">{t('Active')}</option>
                  <option value="disabled">{t('Disabled')}</option>
                </select>
              </div>
            </div>
            <Notice kind={promotion || status === 'disabled' ? 'warning' : 'info'}>
              {t(
                promotion
                  ? 'Administrators can dispatch tasks, enroll or disable agents, and change other users’ access.'
                  : status === 'disabled'
                    ? 'Disabling this account prevents sign-in and revokes its existing sessions.'
                    : 'Changing access revokes existing sessions. At least one active administrator must remain.',
              )}
            </Notice>
            {promotion && (
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={grant}
                  onChange={(event) => setGrant(event.target.checked)}
                  required
                />
                {t('I intend to grant administrator access.')}
              </label>
            )}
          </>
        ) : (
          <Notice kind="warning">
            {t(
              'This signs the user out of all current sessions. The account can sign in again if it remains active.',
            )}
          </Notice>
        )}
        <label htmlFor="user-confirm">{t('Type the identity subject to confirm')}</label>
        <input
          id="user-confirm"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          required
        />
        <MutationError error={mutation.error} />
        <div className="dialog-actions">
          <button
            type="button"
            className="button secondary"
            disabled={mutation.isPending}
            onClick={onClose}
          >
            {t('Cancel')}
          </button>
          <button
            className={`button ${status === 'disabled' || mode === 'revoke' ? 'danger' : 'primary'}`}
            disabled={
              mutation.isPending ||
              confirm !== user.subject ||
              (mode === 'edit' && promotion && !grant) ||
              uncertainWrite(mutation.error)
            }
          >
            {t(
              mutation.isPending
                ? 'Submitting…'
                : mode === 'revoke'
                  ? 'Revoke sessions'
                  : 'Save access',
            )}
          </button>
        </div>
        <div className="user-access-links">
          <AuditLink subjectId={user.id} />
          {user.status === 'active' && (
            <button
              type="button"
              className="text-action"
              disabled={mutation.isPending}
              onClick={() => {
                setMode(mode === 'edit' ? 'revoke' : 'edit')
                setConfirm('')
                mutation.reset()
              }}
            >
              {t(mode === 'edit' ? 'Revoke sessions only' : 'Back to access settings')}
            </button>
          )}
        </div>
      </form>
    </Dialog>
  )
}
