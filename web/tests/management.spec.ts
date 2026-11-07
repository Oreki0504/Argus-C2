import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { identity } from '../src/mocks/fixtures'
import { managementFixture } from '../src/mocks/management'
import { fleetFixture } from '../src/mocks/fixtures'

test('anonymous and User deep links never fetch management data', async ({ page }) => {
  const requests: string[] = []
  page.on('request', (request) => {
    if (request.url().includes('/v1/console/admin/')) requests.push(request.url())
  })
  for (const scenario of ['guest', 'user', 'no-capability']) {
    await page.goto(`/manage/tasks?scenario=${scenario}`)
    await expect(page.getByRole('heading', { name: 'Management unavailable' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Management', exact: true })).toHaveCount(0)
  }
  expect(requests).toEqual([])
})

test('Admin can dispatch a constrained task from an agent and inspect its audit', async ({
  page,
}) => {
  const submissions: unknown[] = []
  page.on('request', (request) => {
    if (
      request.method() === 'POST' &&
      new URL(request.url()).pathname === '/v1/console/admin/tasks'
    )
      submissions.push(request.postDataJSON())
  })
  await page.goto('/fleet/srv-0001?scenario=admin')
  await page.getByRole('link', { name: 'Dispatch task', exact: true }).click()
  const form = page.getByRole('dialog', { name: 'New task' })
  await expect(form.getByLabel('Agent', { exact: true })).toHaveValue('node-0001')
  await form.getByLabel('Task type', { exact: true }).selectOption('service.status')
  await form.getByLabel('Service ID', { exact: true }).fill('journal')
  await form.getByLabel('Dispatch TTL (seconds)').fill('180')
  await form.getByLabel('Execution timeout (ms)').fill('5000')
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await form.getByRole('button', { name: 'Dispatch task', exact: true }).click()
  await expect(page).toHaveURL(/\/manage\/tasks\/task-/)
  await expect(page.getByRole('heading', { name: 'Dispatch details' })).toBeVisible()
  expect(submissions).toEqual([
    {
      node_id: 'node-0001',
      task_type: 'service.status',
      parameters: { service_id: 'journal' },
      ttl_seconds: 180,
      execution_timeout_ms: 5000,
    },
  ])
  await expect(page.getByText('service_id: journal', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'Related audit' }).click()
  await expect(page.getByRole('heading', { name: 'Audit', exact: true })).toBeVisible()
  await expect(page.getByRole('row').filter({ hasText: 'task.create' })).toHaveCount(1)
  await expect(page.getByLabel('Agent ID', { exact: true })).toHaveValue('node-0001')
})

test('enrollment is shown once and disable requires an exact agent ID', async ({ page }) => {
  await page.goto('/manage/agents?scenario=admin')
  await page.getByRole('button', { name: 'Add agent', exact: true }).click()
  const enrollment = page.getByRole('dialog', { name: 'Add agent' })
  await enrollment.getByRole('button', { name: 'Manual enrollment', exact: true }).click()
  await enrollment.getByRole('button', { name: 'Create enrollment token' }).click()
  const token = await enrollment.getByLabel('Enrollment token', { exact: true }).inputValue()
  expect(token).toMatch(/^preview-enrollment-/)
  await expect(
    enrollment.getByText(
      'agent enroll -config /etc/argus-c2/agent.json -token-file /private/agent.token',
    ),
  ).toBeVisible()
  const storage = await page.evaluate(() =>
    JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
  )
  expect(storage).not.toContain(token)
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await enrollment.getByRole('button', { name: 'Done', exact: true }).click()
  await expect(page.getByLabel('Enrollment token', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Add agent', exact: true })).toBeFocused()
  await page.getByRole('button', { name: 'Manage Production · North' }).click()
  await page.getByRole('button', { name: 'Disable agent', exact: true }).click()
  const disable = page.getByRole('dialog', { name: 'Disable agent' })
  await disable.getByLabel('Type the agent ID to confirm').fill('node-0002')
  await expect(disable.getByRole('button', { name: 'Disable agent', exact: true })).toBeDisabled()
  await disable.getByLabel('Type the agent ID to confirm').fill('node-0001')
  await disable.getByRole('button', { name: 'Disable agent', exact: true }).click()
  const row = page.getByRole('row').filter({ hasText: 'Production · North' })
  await expect(row.getByText('Disabled', { exact: true })).toBeVisible()
  await row.getByRole('button').click()
  await expect(page.getByRole('link', { name: 'Dispatch task', exact: true })).toHaveCount(0)
  await page.getByRole('link', { name: 'Related audit', exact: true }).click()
  await expect(page.getByRole('row').filter({ hasText: 'node.disable' })).toHaveCount(1)
})

test('pending identities can be approved, promoted explicitly and have sessions revoked', async ({
  page,
}) => {
  await page.goto('/manage/users?scenario=admin')
  await expect(
    page.getByRole('row').filter({ hasText: 'Alex Morgan' }).getByText('Current account'),
  ).toBeVisible()
  await page.getByRole('button', { name: 'Review access for Jamie Chen' }).click()
  const edit = page.getByRole('dialog', { name: 'Edit user access' })
  await edit.getByLabel('Role', { exact: true }).selectOption('Admin')
  await edit.getByLabel('Type the identity subject to confirm').fill('jamie-preview')
  await expect(edit.getByRole('button', { name: 'Save access' })).toBeDisabled()
  await edit.getByRole('checkbox', { name: 'I intend to grant administrator access.' }).check()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await edit.getByRole('button', { name: 'Save access' }).click()
  await expect(page.getByRole('status')).toContainText('Access updated.')
  const row = page.getByRole('row').filter({ hasText: 'Jamie Chen' })
  await expect(row.getByText('Admin', { exact: true })).toBeVisible()
  await expect(row.getByText('active', { exact: true })).toBeVisible()
  await row.getByRole('button').click()
  await page.getByRole('button', { name: 'Revoke sessions only' }).click()
  const revoke = page.getByRole('dialog', { name: 'Revoke user sessions' })
  await revoke.getByLabel('Type the identity subject to confirm').fill('jamie-preview')
  await revoke.getByRole('button', { name: 'Revoke sessions', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('Sessions revoked.')
  await page
    .getByRole('navigation', { name: 'Management sections' })
    .getByRole('link', { name: 'Audit', exact: true })
    .click()
  await page.getByLabel('User ID', { exact: true }).fill('preview-pending')
  await expect(page.getByRole('row').filter({ hasText: 'user.approve' })).toHaveCount(1)
})

test('management pagination and URL filters work without a sidebar', async ({ page }) => {
  await page.goto('/manage/agents?scenario=large-fleet')
  await expect(page.locator('tbody tr')).toHaveCount(8)
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(page).toHaveURL(/cursor=offset-8/)
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await page.goBack()
  await expect(page).toHaveURL(/cursor=offset-8/)
  await page.getByRole('button', { name: 'Previous', exact: true }).click()
  await expect(page).not.toHaveURL(/cursor=/)
  await page.getByRole('textbox', { name: 'Search managed agents' }).fill('Server · 019')
  await expect(page.locator('tbody tr')).toHaveCount(1)
  await page.reload()
  await expect(page.getByRole('textbox', { name: 'Search managed agents' })).toHaveValue(
    'Server · 019',
  )
  await expect(page.locator('.sidebar')).toHaveCount(0)
})

test('management is localized, accessible in dark mode and fits a narrow viewport', async ({
  page,
}) => {
  await page.goto('/manage/tasks?scenario=admin')
  await page.getByRole('button', { name: 'Switch to dark mode' }).click()
  await page.getByRole('button', { name: '切换为中文' }).click()
  const tabs = page.getByRole('navigation', { name: '管理分类' })
  for (const label of ['任务', 'Agent', '审计', '用户与权限']) {
    await tabs.getByRole('link', { name: label, exact: true }).click()
    await expect(page.getByRole('table')).toBeVisible()
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  }
  await page.setViewportSize({ width: 390, height: 844 })
  await tabs.getByRole('link', { name: 'Agent', exact: true }).click()
  await expect(page.getByRole('button', { name: '添加 Agent', exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.getByRole('button', { name: '添加 Agent', exact: true }).click()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: '添加 Agent', exact: true })).toBeFocused()
})

test('uncertain production writes are not automatically retried or reported as success', async ({
  page,
}) => {
  const data = managementFixture(fleetFixture())
  let writes = 0
  await page.route('**/v1/me', (route) => route.fulfill({ json: identity('Admin') }))
  await page.route('**/v1/console/admin/tasks?**', (route) =>
    route.fulfill({ json: { items: [], total: 0, next_cursor: null } }),
  )
  await page.route('**/v1/console/admin/agents?**', (route) =>
    route.fulfill({ json: { items: data.agents, total: 6, next_cursor: null } }),
  )
  await page.route('**/v1/console/admin/tasks', (route) => {
    writes++
    expect(route.request().headers()['x-csrf-token']).toBe(identity('Admin').csrf_token)
    expect(route.request().headers().authorization).toBeUndefined()
    return route.fulfill({ status: 503, json: { code: 'service_unavailable' } })
  })
  await page.goto('http://127.0.0.1:4173/manage/tasks?new=1')
  const dialog = page.getByRole('dialog', { name: 'New task' })
  await dialog.getByLabel('Agent', { exact: true }).selectOption('node-0001')
  await dialog.getByRole('button', { name: 'Dispatch task', exact: true }).click()
  await expect(
    dialog.getByText(
      'The request may have reached the server. Refresh the relevant records before submitting again.',
    ),
  ).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Dispatch task', exact: true })).toBeDisabled()
  expect(writes).toBe(1)
  await expect(page).toHaveURL(/\/manage\/tasks\?new=1$/)
})
