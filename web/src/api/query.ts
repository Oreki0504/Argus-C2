import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'
import type { Identity } from './contracts'
import { ApiError } from './client'

// No persistence plugin: identity and responses remain in memory only.
export const consoleKey = (identity: Identity) =>
  ['console', identity.principal_id, identity.role] as const
export function createQueryClient(onSessionInvalid: (status: number) => void) {
  const onError = (error: Error) => {
    if (
      error instanceof ApiError &&
      (error.status === 401 ||
        (error.status === 403 &&
          error.code !== 'csrf_invalid' &&
          error.code !== 'reauthentication_required'))
    )
      onSessionInvalid(error.status)
  }
  return new QueryClient({
    queryCache: new QueryCache({
      onError: (error, query) => {
        if (query.queryKey[0] === 'console') onError(error)
      },
    }),
    mutationCache: new MutationCache({ onError }),
    defaultOptions: {
      queries: { retry: false, staleTime: 15_000, refetchOnWindowFocus: true },
      // Retrying writes can duplicate operations after an uncertain response.
      mutations: { retry: false, gcTime: 0 },
    },
  })
}

export async function clearSession(client: QueryClient) {
  await client.cancelQueries()
  client.clear()
}
