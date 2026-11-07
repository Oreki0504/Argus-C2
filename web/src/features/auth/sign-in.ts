import type { NavigateFunction } from 'react-router-dom'
import type { QueryClient } from '@tanstack/react-query'
import type { ProviderKind } from '../../api/contracts'
import { clearSession } from '../../api/query'
import { api } from '../../api/client'

export async function beginSignIn(
  csrf: string,
  setup: boolean,
  provider: ProviderKind,
  client: QueryClient,
  navigate: NavigateFunction,
) {
  if (import.meta.env.DEV && import.meta.env.MODE === 'mock') {
    const { simulateOIDC } = await import('../../mocks/browser')
    await simulateOIDC(setup ? '/v1/console/setup/bind' : '/v1/console/auth/login', csrf, provider)
    await clearSession(client)
    await navigate('/', { replace: true })
  } else {
    const start = await api.beginOIDC(csrf, setup, provider)
    window.location.assign(start.redirect_path)
  }
}
