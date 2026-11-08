import { getResponse } from 'msw'
import { emptySchema } from '../api/contracts'
import { request } from '../api/client'
import { makeHandlers } from './handlers'
import { scenarios, type Scenario } from './fixtures'

const raw = new URLSearchParams(window.location.search).get('scenario')
export const previewScenario: Scenario = scenarios.find((value) => value === raw) ?? 'guest'

export async function startMocks() {
  const scenario = previewScenario
  const handlers = makeHandlers(scenario)
  // Plain HTTP LAN origins cannot register Service Workers. Resolve the same
  // handlers in memory in this explicit mock mode, with state local to each tab.
  if (!window.isSecureContext || !('serviceWorker' in navigator)) {
    const originalFetch = window.fetch.bind(window)
    window.fetch = async (input, init) => {
      const request = new Request(
        input instanceof Request ? input : new URL(String(input), window.location.href),
        init,
      )
      const url = new URL(request.url)
      if (url.origin !== window.location.origin || !url.pathname.startsWith('/v1/')) {
        return originalFetch(input, init)
      }
      request.signal.throwIfAborted()
      const response = await getResponse(handlers, request)
      request.signal.throwIfAborted()
      if (!response) throw new Error('No development mock handles this Console request')
      return response
    }
    return
  }
  const { setupWorker } = await import('msw/browser')
  const worker = setupWorker(...handlers)
  await worker.start({
    quiet: true,
    // Every /v1/* request has a catch-all denial handler. Other requests are
    // Vite assets or fonts and may pass through to the local development server.
    onUnhandledFrame: 'bypass',
  })
}

export async function simulateOIDC(
  path: string,
  csrf: string,
  provider: import('../api/contracts').ProviderKind,
) {
  await request(path, emptySchema, { body: { provider }, csrf })
}

export async function simulateAccountBinding(
  provider: import('../api/contracts').ProviderKind,
  csrf: string,
) {
  await request('/v1/console/account/bind', emptySchema, { body: { provider }, csrf })
}
