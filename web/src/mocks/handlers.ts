import { delay, http, HttpResponse } from 'msw'
import { csrf, fleetFixture, historyFixture, identity, type Scenario } from './fixtures'
import { historyRangeSchema, type Setup } from '../api/contracts'
import { managementFixture, managementHandlers } from './management'

// This state belongs to the development preview. It is not an authentication
// implementation and has no backing store, OIDC exchange or real credentials.
export function makeHandlers(scenario: Scenario) {
  let active = scenario !== 'setup'
  let session = !['guest', 'setup', 'login', 'expired', 'empty', 'unavailable'].includes(scenario)
  let setup: Setup | null = null
  const role = scenario === 'user' ? 'User' : 'Admin'
  const problem = (code: string, status: number) =>
    HttpResponse.json({ code }, { status, headers: { 'Cache-Control': 'no-store' } })
  const reply = (body: Parameters<typeof HttpResponse.json>[0]) =>
    HttpResponse.json(body, { headers: { 'Cache-Control': 'no-store' } })
  const validCSRF = (request: Request) => request.headers.get('X-CSRF-Token') === csrf
  const size = scenario === 'empty' ? 0 : scenario === 'large-fleet' ? 300 : 6
  const managed = managementFixture(fleetFixture(size))
  const summary = () => {
    const data = fleetFixture(size)
    for (const node of data.nodes) {
      const agent = managed.agents.find((agent) => agent.public_id === node.public_id)
      if (agent?.status === 'disabled') node.last_seen_at = agent.last_seen_at
    }
    return data
  }
  const history = (request: Request, id: string) => {
    const range = historyRangeSchema.safeParse(new URL(request.url).searchParams.get('range'))
    if (!range.success) return problem('invalid_range', 400)
    const data = summary()
    const node = data.nodes.find((node) => node.public_id === id)
    return node
      ? reply(historyFixture(node, range.data, data.generated_at))
      : problem('not_found', 404)
  }
  return [
    http.get('/v1/console/auth/status', () =>
      reply({
        state: active ? 'ACTIVE' : 'SETUP_PENDING',
        provider_name: 'Organization SSO',
        csrf_token: csrf,
      }),
    ),
    http.get('/v1/me', async () => {
      await delay(160)
      if (!session) return problem('session_expired', 401)
      if (scenario === 'forbidden') return problem('forbidden', 403)
      const user = identity(role)
      if (scenario === 'no-capability') user.capabilities = []
      return reply(user)
    }),
    http.post('/v1/console/auth/logout', ({ request }) => {
      if (!validCSRF(request)) return problem('csrf_invalid', 403)
      session = false
      return reply({})
    }),
    http.post('/v1/console/auth/login', async ({ request }) => {
      if (!validCSRF(request)) return problem('csrf_invalid', 403)
      if (scenario === 'oidc-error') return problem('oidc_callback_invalid', 400)
      session = true
      return reply({})
    }),
    http.get('/v1/console/setup', () =>
      active
        ? problem('setup_closed', 403)
        : setup
          ? reply(setup)
          : problem('session_expired', 401),
    ),
    http.post('/v1/console/setup/prove', async ({ request }) => {
      if (active) return problem('setup_closed', 403)
      if (!validCSRF(request)) return problem('csrf_invalid', 403)
      const body = (await request.json()) as { secret?: string }
      if (!/^[a-fA-F0-9]{64}$/.test(body.secret ?? '')) return problem('bootstrap_invalid', 400)
      setup = {
        step: 'provider',
        csrf_token: csrf,
        callback_uri: 'https://console.example.test/v1/console/auth/callback',
        issuer: '',
        client_id: '',
      }
      return reply(setup)
    }),
    http.post('/v1/console/setup/provider', async ({ request }) => {
      if (active) return problem('setup_closed', 403)
      if (!setup) return problem('session_expired', 401)
      if (!validCSRF(request)) return problem('csrf_invalid', 403)
      const body = (await request.json()) as { issuer: string; client_id: string }
      if (!body.issuer.startsWith('https://') || !body.client_id)
        return problem('oidc_unavailable', 400)
      setup = { ...setup, issuer: body.issuer, client_id: body.client_id, step: 'bind' }
      return reply(setup)
    }),
    http.post('/v1/console/setup/bind', ({ request }) => {
      if (active) return problem('setup_closed', 403)
      if (setup?.step !== 'bind') return problem('forbidden', 403)
      if (!validCSRF(request)) return problem('csrf_invalid', 403)
      active = true
      session = true
      setup = null
      return reply({})
    }),
    http.get('/v1/console/summary', async () => {
      await delay(250)
      if (!session) return problem('session_expired', 401)
      if (scenario === 'forbidden' || scenario === 'no-capability') return problem('forbidden', 403)
      if (scenario === 'unavailable') return problem('service_unavailable', 503)
      return reply(summary())
    }),
    http.get('/v1/console/nodes/:id/history', async ({ request, params }) => {
      if (!session) return problem('session_expired', 401)
      if (scenario === 'forbidden' || scenario === 'no-capability') return problem('forbidden', 403)
      return history(request, String(params.id))
    }),
    http.get('/v1/console/public/summary', async () => {
      await delay(200)
      if (!active) return problem('forbidden', 403)
      if (scenario === 'unavailable') return problem('service_unavailable', 503)
      return reply(summary())
    }),
    http.get('/v1/console/public/nodes/:id/history', ({ request, params }) => {
      if (!active) return problem('forbidden', 403)
      if (scenario === 'unavailable') return problem('service_unavailable', 503)
      return history(request, String(params.id))
    }),
    ...managementHandlers(
      managed,
      () => {
        if (!session) return null
        const user = identity(role)
        if (scenario === 'no-capability' || scenario === 'forbidden') user.capabilities = []
        return user
      },
      csrf,
    ),
    http.all('/v1/*', () => problem('forbidden', 403)),
  ]
}
