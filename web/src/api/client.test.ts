import { afterEach, describe, expect, it, vi } from 'vitest'
import { z } from 'zod'
import { api, ApiError, request } from './client'
import { oidcStartSchema, summarySchema } from './contracts'
import { clearSession, consoleKey, createQueryClient } from './query'
import { fleetFixture, identity } from '../mocks/fixtures'

afterEach(() => vi.unstubAllGlobals())
describe('Console transport boundary', () => {
  it('sends same-origin cookies and CSRF without a Bearer credential', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json({}))
    vi.stubGlobal('fetch', fetcher)
    await api.logout('session-bound-csrf')
    expect(fetcher).toHaveBeenCalledWith(
      '/v1/console/auth/logout',
      expect.objectContaining({
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        method: 'POST',
        body: '{}',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'session-bound-csrf',
        },
      }),
    )
  })
  it('rejects external/Fleet paths and writes without CSRF before network access', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    for (const path of [
      'https://example.com/v1/me',
      '//example.com/v1/me',
      '/v1/nodes',
      '/v1/agent/poll',
      '/v1/console/../nodes',
    ])
      await expect(request(path, z.unknown())).rejects.toThrow()
    await expect(request('/v1/console/auth/logout', z.unknown(), { body: {} })).rejects.toThrow(
      'CSRF token required',
    )
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('does not disclose arbitrary JSON/HTML errors or retain rejected fields', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json(
          { code: 'internal_host_192.0.2.1', error: 'secret at /private/path' },
          { status: 503 },
        ),
      )
      .mockResolvedValueOnce(new Response('<html>secret error</html>', { status: 401 }))
      .mockResolvedValueOnce(Response.json({ ...identity('User'), hostname: 'private-host' }))
    vi.stubGlobal('fetch', fetcher)
    await expect(api.me()).rejects.toMatchObject({ status: 503, code: 'service_unavailable' })
    await expect(api.me()).rejects.toMatchObject({ status: 401, code: 'session_expired' })
    try {
      await api.me()
      expect.fail('invalid response accepted')
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError)
      expect(JSON.stringify(error)).not.toContain('private-host')
      expect(error).toMatchObject({ code: 'invalid_response' })
    }
  })
  it('preserves cancellation without converting it to an application error', async () => {
    const controller = new AbortController()
    controller.abort()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(controller.signal.reason))
    await expect(api.me(controller.signal)).rejects.toBe(controller.signal.reason)
  })
  it('accepts only the fixed same-origin OIDC navigation route', () => {
    expect(oidcStartSchema.safeParse({ redirect_path: '/v1/console/auth/redirect' }).success).toBe(
      true,
    )
    for (const redirect_path of [
      '//evil.test',
      'https://evil.test',
      '/v1/console/auth/redirect?next=https://evil.test',
      '/',
    ])
      expect(oidcStartSchema.safeParse({ redirect_path }).success).toBe(false)
  })
})

describe('Public DTO and session cache', () => {
  it('preserves actionable CSRF/reauthentication errors but invalidates revoked access', async () => {
    const invalid = vi.fn()
    const client = createQueryClient(invalid)
    for (const code of ['csrf_invalid', 'reauthentication_required', 'forbidden']) {
      const mutation = client.getMutationCache().build(client, {
        mutationFn: async () => {
          throw new ApiError(403, code)
        },
      })
      await expect(mutation.execute(undefined)).rejects.toMatchObject({ code })
      if (code !== 'forbidden') expect(invalid).not.toHaveBeenCalled()
    }
    expect(invalid).toHaveBeenCalledExactlyOnceWith(403)
    client.clear()
  })
  it('requires explicitly nullable observations and rejects unreviewed nested data', () => {
    const summary = fleetFixture()
    expect(summarySchema.parse(summary).nodes[5].resources.cpu_percent).toBeNull()
    expect(
      summarySchema.safeParse({
        ...summary,
        nodes: [{ ...summary.nodes[0], hostname: 'private-host', ip: '192.0.2.1' }],
      }).success,
    ).toBe(false)
    expect(
      summarySchema.safeParse({
        ...summary,
        nodes: [
          {
            ...summary.nodes[0],
            resources: { ...summary.nodes[0].resources, mounts: ['/private'] },
          },
        ],
      }).success,
    ).toBe(false)
  })
  it('namespaces by both principal and role, then cancels and clears on logout', async () => {
    const client = createQueryClient(vi.fn())
    const admin = identity('Admin')
    const key = consoleKey(admin)
    expect(key).not.toEqual(consoleKey({ ...admin, role: 'User' }))
    expect(key).not.toEqual(consoleKey({ ...admin, principal_id: 'another-user' }))
    client.setQueryData([...key, 'summary'], fleetFixture())
    let signal: AbortSignal | undefined
    const pending = client
      .fetchQuery({
        queryKey: [...key, 'pending'],
        queryFn: (ctx) => {
          signal = ctx.signal
          return new Promise(() => {})
        },
      })
      .catch(() => {})
    await clearSession(client)
    await pending
    expect(signal?.aborted).toBe(true)
    expect(client.getQueryCache().getAll()).toHaveLength(0)
    expect(client.getMutationCache().getAll()).toHaveLength(0)
  })
})
