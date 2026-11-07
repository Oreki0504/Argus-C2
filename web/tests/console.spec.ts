import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { readFileSync, readdirSync } from 'node:fs'
import { fleetFixture } from '../src/mocks/fixtures'

test('anonymous overview uses five-column cards, login action and keyboard detail navigation', async ({
  page,
}) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'ARGUS', exact: true })).toBeVisible()
  const filters = page.getByRole('group', { name: 'Filter heartbeat status' })
  await expect(filters.getByRole('button')).toHaveCount(4)
  await expect(filters.getByRole('button', { name: 'All Server 6', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  await filters.getByRole('button', { name: 'Online 3', exact: true }).click()
  await expect(page.locator('.agent-card')).toHaveCount(3)
  await expect(page).toHaveURL(/status=Online/)
  await filters.getByRole('button', { name: 'Stale 1', exact: true }).click()
  await expect(page.getByRole('article', { name: 'Build runner · 01', exact: true })).toBeVisible()
  await expect(page.locator('.agent-card')).toHaveCount(1)
  await filters.getByRole('button', { name: 'Offline 2', exact: true }).click()
  await expect(page.getByRole('article', { name: 'Staging · Atlas', exact: true })).toBeVisible()
  await expect(page.getByRole('article', { name: 'Archive · 01', exact: true })).toBeVisible()
  await expect(filters.getByRole('button', { name: /Never seen/ })).toHaveCount(0)
  await filters.getByRole('button', { name: 'All Server 6', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('.agent-card')).toHaveCount(6)
  await expect(page.locator('.agent-card-footer')).toHaveCount(0)
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0)
  await expect(page.locator('.sidebar')).toHaveCount(0)
  const card = page.getByRole('article', { name: 'Production · North', exact: true })
  await expect(card.getByRole('meter')).toHaveCount(5)
  await expect(card.locator('.utilization-value').filter({ hasText: '12.4%' })).toBeVisible()
  await expect(card.locator('.utilization-value').filter({ hasText: '8.4%' })).toBeVisible()
  const positions = await card
    .locator('.utilization-cell')
    .evaluateAll((cells) => cells.map((cell) => cell.getBoundingClientRect().top))
  expect(new Set(positions).size).toBe(1)
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.getByRole('textbox', { name: 'Search agents' }).fill('Tokyo')
  await expect(page.locator('.agent-card')).toHaveCount(1)
  await expect(filters.getByRole('button', { name: 'All Server 1', exact: true })).toBeVisible()
  await expect(filters.getByRole('button', { name: 'Online 1', exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'View Edge · Tokyo' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Edge · Tokyo' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'CPU utilization' })).toBeVisible()
  await expect(page.locator('.history-chart')).toHaveCount(5)
  await expect(page.locator('.tone-cpu .chart-line')).toHaveCount(2)
  const slider = page.getByRole('slider', { name: 'Inspect CPU utilization sample' })
  await slider.focus()
  await page.keyboard.press('Home')
  await expect(slider).toHaveValue('0')
  await page.getByRole('button', { name: '24 hours', exact: true }).click()
  await expect(page).toHaveURL(/range=24h/)
  await expect(page.getByRole('button', { name: '24 hours', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  await expect(page.getByText('Sampling interval 900s')).toBeVisible()
  await page.getByRole('button', { name: 'View sample data' }).click()
  await expect(page.getByRole('region', { name: 'Utilization samples' })).toBeVisible()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'View sample data' })).toBeFocused()
  await expect(page.getByText('6.8.0', { exact: true })).toBeVisible()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  expect(errors).toEqual([])
})

test('overview clock follows browser local time without a timezone label', async ({ browser }) => {
  for (const [timezoneId, expected] of [
    ['Asia/Tokyo', '21:34:56'],
    ['America/New_York', '07:34:56'],
  ]) {
    const context = await browser.newContext({ timezoneId })
    const page = await context.newPage()
    await page.clock.install({ time: new Date('2026-11-08T12:34:56Z') })
    await page.clock.pauseAt(new Date('2026-11-08T12:34:56Z'))
    await page.goto('/')
    await expect(page.locator('.overview-updated time')).toHaveText(expected)
    await expect(page.locator('.overview-updated time')).not.toHaveAttribute('title')
    await page.clock.runFor(1000)
    await expect(page.locator('.overview-updated time')).toHaveText(expected.slice(0, -2) + '57')
    await context.close()
  }
})

test('unseen enrollment records do not enter overview counts or cards', async ({ page }) => {
  const data = fleetFixture()
  data.nodes[5].last_seen_at = 0
  await page.route('**/v1/me', (route) =>
    route.fulfill({ status: 401, json: { code: 'session_expired' } }),
  )
  await page.route('**/v1/console/public/summary', (route) => route.fulfill({ json: data }))
  await page.goto('http://127.0.0.1:4173/')
  await expect(page.getByRole('button', { name: 'All Server 5', exact: true })).toBeVisible()
  await expect(page.locator('.agent-card')).toHaveCount(5)
  await expect(page.getByRole('link', { name: 'View Archive · 01' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Never seen/ })).toHaveCount(0)
})

test('User and Admin have no sidebar, and Admin pages remain reachable from the header', async ({
  page,
}) => {
  await page.goto('/?scenario=user')
  await expect(page.getByText('Sam Taylor', { exact: true })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0)
  await expect(page.locator('.agent-card')).toHaveCount(6)
  await page.goto('/?scenario=admin')
  const navigation = page.getByRole('navigation', { name: 'Main navigation' })
  await expect(navigation).toBeVisible()
  await expect(page.locator('.sidebar')).toHaveCount(0)
  await expect(page.locator('header').getByRole('navigation')).toBeVisible()
  await expect(page.locator('.agent-card')).toHaveCount(6)
  await expect(page.getByText('Alex Morgan', { exact: true })).toBeVisible()
  await navigation.getByRole('link', { name: 'Management', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Tasks', exact: true })).toBeVisible()
  await expect(navigation.getByRole('link', { name: 'Management', exact: true })).toHaveAttribute(
    'aria-current',
    'page',
  )
  await navigation.getByRole('link', { name: 'Traffic', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Network traffic' })).toBeVisible()
  await navigation.getByRole('link', { name: 'Overview', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await page.getByRole('button', { name: 'Switch to dark mode' }).click()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await expect(navigation.getByRole('link', { name: 'Management', exact: true })).toBeInViewport()
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toHaveCount(0)
})

test('expired authentication defaults to anonymous User without manufacturing a session', async ({
  page,
}) => {
  await page.goto('/?scenario=expired')
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  await expect(page.locator('.sidebar')).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'View Production · North' })).toBeVisible()
})

test('large fleet pages and URL filters reset pagination', async ({ page }) => {
  await page.goto('/fleet?scenario=large-fleet')
  await expect(page.getByText('Page 1 of 15')).toBeVisible()
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(page.getByText('Page 2 of 15')).toBeVisible()
  await expect(page).toHaveURL(/page=2/)
  await page.getByRole('combobox', { name: 'Filter heartbeat status' }).selectOption('Online')
  await expect(page.getByText('Page 1 of 8')).toBeVisible()
  await expect(page).not.toHaveURL(/page=2/)
  await page.reload()
  await expect(page.getByRole('combobox', { name: 'Filter heartbeat status' })).toHaveValue(
    'Online',
  )
})

test('first-run preview proves ownership, configures provider, binds and closes setup', async ({
  page,
}) => {
  await page.goto('/setup?scenario=setup')
  await expect(page.getByRole('heading', { name: 'Verify console ownership' })).toBeVisible()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.getByLabel('Bootstrap secret', { exact: true }).fill('a'.repeat(64))
  await page.getByRole('button', { name: 'Verify & continue' }).click()
  await expect(page.getByRole('heading', { name: 'Connect your identity provider' })).toBeVisible()
  await page.getByLabel('Issuer URL').fill('https://identity.example.test')
  await page.getByLabel('Client ID', { exact: true }).fill('argus-preview')
  await page.getByLabel('Client secret').fill('preview-secret')
  await page.getByRole('button', { name: 'Validate & continue' }).click()
  await expect(page.getByRole('heading', { name: 'Make it yours' })).toBeVisible()
  await page.getByRole('button', { name: 'Verify identity & activate' }).click()
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  await expect(page.getByText('Alex Morgan', { exact: true })).toHaveCount(0)
  await expect(page.locator('.sidebar')).toHaveCount(0)
  const storage = await page.evaluate(() =>
    JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
  )
  expect(storage).not.toContain('preview-secret')
  expect(storage).not.toContain('a'.repeat(64))
  await expect(page.getByRole('link', { name: 'Set up your console' })).toHaveCount(0)
})

for (const [scenario, message] of [
  ['empty', 'Your fleet starts here'],
  ['forbidden', 'Your account does not have access to this page.'],
  ['unavailable', 'The console is temporarily unavailable. Please try again.'],
  ['no-capability', 'Your console is ready'],
] as const)
  test(`explicit ${scenario} state`, async ({ page }) => {
    await page.goto(`/?scenario=${scenario}`)
    await expect(page.getByText(message, { exact: true })).toBeVisible()
    await expect(page.getByText('Production · North')).toHaveCount(0)
  })

test('OIDC failure remains a failed sign-in', async ({ page }) => {
  await page.goto('/login?scenario=oidc-error')
  await page.getByRole('button', { name: 'Continue with SSO' }).click()
  await expect(
    page.getByText('Sign-in could not be verified. Start a new sign-in attempt.'),
  ).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toHaveCount(0)
})

test('mobile layout fits viewport and has usable navigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  )
  await expect(page.getByRole('button', { name: 'Toggle navigation' })).toHaveCount(0)
  const filterTops = await page
    .locator('.agent-toolbar .search-input, .heartbeat-filter')
    .evaluateAll((cards) => cards.map((card) => card.getBoundingClientRect().top))
  expect(new Set(filterTops).size).toBe(1)
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  const card = page.getByRole('article', { name: 'Production · North', exact: true })
  const positions = await card
    .locator('.utilization-cell')
    .evaluateAll((cells) => cells.map((cell) => cell.getBoundingClientRect().top))
  expect(new Set(positions).size).toBe(1)
  await card.click()
  await expect(page.getByRole('heading', { name: 'CPU utilization' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  )
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
})

test('production excludes fixtures and preview worker, and uses the proposed auth contract', async ({
  page,
}) => {
  const assets = readdirSync('../internal/webui/dist/assets')
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFileSync(`../internal/webui/dist/assets/${name}`, 'utf8'))
    .join('')
  for (const marker of [
    'preview-secret',
    'mockServiceWorker.js',
    'Production · North',
    'development-only-csrf-proof',
    'Simulated data and sign-in',
  ])
    expect(assets).not.toContain(marker)
  await page.route('**/v1/console/auth/status', (route) =>
    route.fulfill({
      json: { state: 'ACTIVE', provider_name: 'Test provider', csrf_token: 'test-csrf' },
    }),
  )
  await page.route('**/v1/console/auth/login', async (route) => {
    expect(route.request().headers()['x-csrf-token']).toBe('test-csrf')
    expect(route.request().headers().authorization).toBeUndefined()
    await route.fulfill({ json: { redirect_path: 'https://untrusted.example.test' } })
  })
  await page.goto('http://127.0.0.1:4173/login')
  await expect(page.getByText('Design preview')).toHaveCount(0)
  await page.getByRole('button', { name: 'Continue with SSO' }).click()
  await expect(page.getByText('The Console API returned an unexpected response.')).toBeVisible()
  await expect(page).toHaveURL('http://127.0.0.1:4173/login')
})

test('production anonymous browsing only requests public projections and never invents history', async ({
  page,
}) => {
  const protectedRequests: string[] = []
  await page.route('**/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/v1/me') return route.fulfill({ status: 401, json: { code: 'session_expired' } })
    if (path === '/v1/console/public/summary') return route.fulfill({ json: fleetFixture() })
    if (path === '/v1/console/public/nodes/srv-0001/history')
      return route.fulfill({ status: 503, json: { code: 'service_unavailable' } })
    protectedRequests.push(path)
    return route.fulfill({ status: 403, json: { code: 'forbidden' } })
  })
  await page.goto('http://127.0.0.1:4173/')
  await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
  await expect(page.locator('.sidebar')).toHaveCount(0)
  await page.getByRole('link', { name: 'View Production · North' }).click()
  await expect(
    page.getByText('The console is temporarily unavailable. Please try again.'),
  ).toBeVisible()
  await expect(page.locator('.chart-line')).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'System information' })).toBeVisible()
  expect(protectedRequests).toEqual([])
})

test('missing capacity and missing samples do not become zero utilization', async ({ page }) => {
  await page.goto('/')
  const unknownCapacity = page.getByRole('article', { name: 'Build runner · 01', exact: true })
  await expect(unknownCapacity.getByRole('meter')).toHaveCount(3)
  await expect(
    unknownCapacity.getByRole('img', { name: 'Inbound utilization unavailable' }),
  ).toBeVisible()
  await expect(unknownCapacity.getByText('640 kbit/s', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'View Archive · 01' }).click()
  await expect(page.getByText('No measured utilization', { exact: true })).toHaveCount(5)
  await expect(page.locator('.chart-line')).toHaveCount(0)
})

for (const viewport of [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
])
  test(`overview and details fit ${viewport.width}×${viewport.height} without page scrolling`, async ({
    page,
  }) => {
    await page.setViewportSize(viewport)
    await page.goto('/')
    await expect(page.locator('.agent-card')).toHaveCount(6)
    const controlTops = await page
      .locator('.agent-toolbar .search-input, .heartbeat-filter')
      .evaluateAll((controls) => controls.map((control) => control.getBoundingClientRect().top))
    expect(controlTops).toHaveLength(5)
    expect(new Set(controlTops).size).toBe(1)
    const fits = () =>
      page.evaluate(() => ({
        vertical: document.documentElement.scrollHeight <= innerHeight,
        horizontal: document.documentElement.scrollWidth <= innerWidth,
      }))
    expect(await fits()).toEqual({ vertical: true, horizontal: true })
    await page.getByRole('link', { name: 'View Production · North' }).click()
    await expect(page.locator('.history-chart')).toHaveCount(5)
    await expect(page.getByRole('region', { name: 'System information' })).toBeInViewport()
    expect(await fits()).toEqual({ vertical: true, horizontal: true })
    await page.getByRole('button', { name: '切换为中文' }).click()
    await expect(page.getByRole('heading', { name: '历史使用率', exact: true })).toBeVisible()
    expect(await fits()).toEqual({ vertical: true, horizontal: true })
  })

test('language and theme persist across routes and reload, with accessible dark pages', async ({
  page,
}) => {
  await page.emulateMedia({ colorScheme: 'light' })
  await page.goto('/')
  await page.getByRole('textbox', { name: 'Search agents' }).fill('North')
  await page.getByRole('button', { name: 'Switch to dark mode' }).click()
  await page.getByRole('button', { name: '切换为中文' }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.getByRole('button', { name: 'Switch to English' })).toBeFocused()
  await expect(page.getByRole('textbox', { name: '搜索服务器' })).toHaveValue('North')
  await expect(page.getByRole('heading', { name: '服务器概览' })).toBeVisible()
  await expect(page.getByRole('button', { name: '全部服务器 1', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.getByRole('link', { name: '查看 Production · North' }).click()
  await expect(page.getByRole('heading', { name: 'CPU 使用率', exact: true })).toBeVisible()
  await expect(page.locator('.node-current-heading')).toContainText('秒前')
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.getByRole('button', { name: '查看采样数据' }).click()
  await expect(page.getByRole('dialog', { name: '查看采样数据' })).toBeVisible()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.keyboard.press('Escape')
  await page.getByRole('link', { name: '登录', exact: true }).click()
  await expect(page.getByRole('heading', { name: '登录控制台' })).toBeVisible()
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.getByRole('button', { name: '切换浅色模式' }).click()
  await page.getByRole('button', { name: 'Switch to English' }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect(page.getByRole('heading', { name: 'Sign in to your console' })).toBeVisible()
})

test('card pagination adapts to window size and keeps the full fleet reachable', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1366, height: 768 })
  await page.route('**/v1/me', (route) =>
    route.fulfill({ status: 401, json: { code: 'session_expired' } }),
  )
  await page.route('**/v1/console/public/summary', (route) =>
    route.fulfill({ json: fleetFixture(19) }),
  )
  await page.goto('http://127.0.0.1:4173/')
  await expect(page.locator('.agent-card')).toHaveCount(6)
  await expect(page.getByText('Page 1 of 4')).toBeVisible()
  for (let i = 0; i < 3; i++) await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(page.getByRole('link', { name: 'View Server · 019' })).toBeVisible()
  await page.setViewportSize({ width: 1024, height: 768 })
  await expect(page.getByText('Page 4 of 5')).toBeVisible()
  await expect(page.locator('.agent-card')).toHaveCount(4)
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(page.getByRole('link', { name: 'View Server · 019' })).toBeVisible()
  await page.getByRole('button', { name: 'Online 10', exact: true }).click()
  await expect(page).not.toHaveURL(/page=/)
  await expect(page.getByText('Page 1 of 3')).toBeVisible()
  await page.reload()
  await expect(page.getByRole('button', { name: 'Online 10', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  await page.getByRole('textbox', { name: 'Search agents' }).fill('019')
  await expect(page).not.toHaveURL(/page=/)
  await expect(page.locator('.agent-card')).toHaveCount(1)
  await page.getByRole('textbox', { name: 'Search agents' }).fill('')
  await page.getByRole('button', { name: 'All Server 19', exact: true }).click()
  await page.setViewportSize({ width: 1440, height: 900 })
  await expect(page.locator('.agent-card')).toHaveCount(9)
  expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true)
})
