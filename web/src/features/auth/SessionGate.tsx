import { useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Navigate, Outlet } from 'react-router-dom'
import { api, ApiError } from '../../api/client'
import { consoleKey } from '../../api/query'
import { ErrorState, Loading } from '../../components/ui'
import { IdentityContext } from './context'

export function SessionGate() {
  const client = useQueryClient()
  const session = useQuery({
    queryKey: ['me'],
    queryFn: async ({ signal }) => {
      try {
        return await api.me(signal)
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null
        throw error
      }
    },
    refetchInterval: 60_000,
  })
  const previous = useRef<readonly string[] | null>(null)
  const previousCapabilities = useRef<string | null>(null)
  const identity = session.data
  useEffect(() => {
    if (session.isError) {
      void client
        .cancelQueries({ queryKey: ['console'] })
        .then(() => client.removeQueries({ queryKey: ['console'] }))
    }
  }, [client, session.isError])
  useEffect(() => {
    const next = identity ? consoleKey(identity) : null
    const capabilities = identity ? [...identity.capabilities].sort().join(',') : null
    if (
      previous.current &&
      (JSON.stringify(previous.current) !== JSON.stringify(next) ||
        previousCapabilities.current !== capabilities)
    ) {
      const old = previous.current
      void client
        .cancelQueries({ queryKey: old })
        .then(() => client.removeQueries({ queryKey: old }))
    }
    previous.current = next
    previousCapabilities.current = capabilities
  }, [client, identity])

  if (session.isPending) return <Loading label="Restoring your session" />
  if (session.isError) {
    if (session.error instanceof ApiError && session.error.status === 403)
      return <Navigate to="/login?reason=forbidden" replace />
    return (
      <main className="standalone">
        <ErrorState error={session.error} retry={() => void session.refetch()} />
      </main>
    )
  }
  return (
    <IdentityContext.Provider value={session.data}>
      <Outlet
        key={
          session.data
            ? `${session.data.principal_id}:${session.data.role}:${[...session.data.capabilities].sort().join(',')}`
            : 'anonymous'
        }
      />
    </IdentityContext.Provider>
  )
}
