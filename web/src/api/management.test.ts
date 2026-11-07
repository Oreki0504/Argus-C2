import { describe, expect, it } from 'vitest'
import { getResponse } from 'msw'
import {
  createTaskSchema,
  taskDetailSchema,
  installationSchema,
  installerStatusSchema,
} from './management-contracts'
import { makeHandlers } from '../mocks/handlers'
import { csrf, type Scenario } from '../mocks/fixtures'

function preview(scenario: Scenario) {
  const handlers = makeHandlers(scenario)
  return async (path: string, body?: unknown, token = csrf) => {
    const request = new Request(`http://localhost/v1/console/admin/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers:
        body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    const response = await getResponse(handlers, request, { baseUrl: 'http://localhost' })
    if (!response) throw new Error('Missing preview handler')
    return response
  }
}
const task = {
  node_id: 'node-0001',
  task_type: 'system.info',
  parameters: {},
  ttl_seconds: 300,
  execution_timeout_ms: 10000,
}

describe('Management contracts and development workflow semantics', () => {
  it('bounds task budgets and permits only the matching fixed collector parameters', () => {
    expect(createTaskSchema.safeParse(task).success).toBe(true)
    for (const change of [
      { task_type: 'shell.exec' },
      { parameters: { command: 'echo hello' } },
      { ttl_seconds: 9 },
      { ttl_seconds: 3601 },
      { execution_timeout_ms: 0 },
      { execution_timeout_ms: 30001 },
      { task_type: 'service.status', parameters: {} },
      { task_type: 'ssh.audit', parameters: { service_id: 'journal' } },
      { task_type: 'service.status', parameters: { service_id: '_invalid' } },
    ])
      expect(createTaskSchema.safeParse({ ...task, ...change }).success).toBe(false)
    expect(
      createTaskSchema.safeParse({
        ...task,
        task_type: 'ssh.audit',
        parameters: { profile_id: 'host' },
      }).success,
    ).toBe(true)
  })

  it('rejects guest/User reads and writes and invalid CSRF in the preview handlers', async () => {
    for (const scenario of ['guest', 'user', 'no-capability'] as const) {
      const call = preview(scenario)
      const status = scenario === 'guest' ? 401 : 403
      for (const path of ['agents', 'tasks', 'audit', 'users', 'installer'])
        expect((await call(path)).status).toBe(status)
      for (const [path, body] of [
        ['tasks', task],
        ['enrollment-tokens', { ttl_seconds: 300 }],
        ['installations', { ttl_seconds: 900 }],
        ['agents/node-0001/disable', { confirm_node_id: 'node-0001' }],
        ['users/preview-user/revoke-sessions', {}],
      ] as const)
        expect((await call(path, body)).status).toBe(status)
    }
    expect((await preview('admin')('tasks', task, 'wrong-csrf')).status).toBe(403)
  })

  it('disabling an agent fails queued tasks and blocks new dispatch', async () => {
    const call = preview('admin')
    const created = await (await call('tasks', task)).json()
    expect(created.status).toBe('PENDING')
    expect((await call('agents/node-0001/disable', { confirm_node_id: 'node-0002' })).status).toBe(
      400,
    )
    expect((await call('agents/node-0001/disable', { confirm_node_id: 'node-0001' })).status).toBe(
      200,
    )
    const result = taskDetailSchema.parse(await (await call(`tasks/${created.id}`)).json())
    expect(result.task.status).toBe('FAILED')
    expect(result.result?.error).toBe('node_disabled')
    expect((await call('tasks', task)).status).toBe(409)
    const audit = await (await call('audit?action=node.disable')).json()
    expect(audit.items).toHaveLength(1)
  })

  it('protects the last Admin and rejects stale user edits while recording approvals', async () => {
    const call = preview('admin')
    const blocked = await call('users/preview-admin', {
      role: 'User',
      status: 'active',
      expected_version: 1,
      confirm_subject: 'alex-preview',
    })
    expect(await blocked.json()).toEqual({ code: 'last_admin' })
    const update = {
      role: 'Admin',
      status: 'active',
      expected_version: 1,
      confirm_subject: 'jamie-preview',
    }
    expect((await call('users/preview-pending', update)).status).toBe(200)
    const stale = await call('users/preview-pending', update)
    expect(stale.status).toBe(409)
    expect(await stale.json()).toEqual({ code: 'user_conflict' })
    const audit = await (await call('audit?subject_id=preview-pending')).json()
    expect(audit.items.map((item: { action: string }) => item.action)).toEqual([
      'user.sessions.revoke',
      'user.approve',
    ])
  })

  it('creates a short-lived token without claiming an agent has enrolled', async () => {
    const call = preview('admin')
    expect((await call('enrollment-tokens', { ttl_seconds: 59 })).status).toBe(400)
    const token = await (await call('enrollment-tokens', { ttl_seconds: 300 })).json()
    expect(token.token).toMatch(/^preview-enrollment-/)
    expect(token.expires_at).toBeGreaterThan(Date.now() / 1000 + 295)
    expect((await (await call('agents')).json()).total).toBe(6)
  })
  it('previews installation with a non-routable HTTPS URL and enforces CSRF and TTL', async () => {
    const call = preview('admin')
    expect(
      installerStatusSchema.parse(await (await call('installer')).json()).platforms,
    ).toHaveLength(2)
    expect((await call('installations', { ttl_seconds: 900 }, 'wrong')).status).toBe(403)
    expect((await call('installations', { ttl_seconds: 3601 })).status).toBe(400)
    const result = installationSchema.parse(
      await (await call('installations', { ttl_seconds: 900 })).json(),
    )
    expect(new URL(result.url).hostname).toBe('console.example.invalid')
    for (const url of [
      'http://console.test/v1/console/install/id',
      "https://bad'host/v1/console/install/id",
      'https://console.test/v1/console/install/id?x=y',
    ]) {
      expect(installationSchema.safeParse({ ...result, url }).success).toBe(false)
    }
    expect((await (await call('agents')).json()).total).toBe(6)
  })
})
