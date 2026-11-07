import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { identity } from '../src/mocks/fixtures'

test('one-command enrollment fits desktop, supports curl/wget and stays out of browser storage', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1366, height: 768 })
  const writes: unknown[] = []
  page.on('request', (request) => {
    if (request.method() === 'POST' && request.url().endsWith('/admin/installations'))
      writes.push(request.postDataJSON())
  })
  await page.goto('/manage/agents?scenario=admin')
  await page.getByRole('button', { name: 'Add agent', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Add agent' })
  await expect(
    dialog.getByRole('button', { name: 'Install command', exact: true }),
  ).toHaveAttribute('aria-pressed', 'true')
  await expect(
    dialog.getByText('Preview only: this sample command cannot install an Agent.'),
  ).toBeVisible()
  await expect(dialog.getByLabel('Command lifetime (minutes)')).toHaveValue('15')
  expect(await dialog.evaluate((el) => el.scrollHeight <= el.clientHeight)).toBe(true)
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await dialog.getByRole('button', { name: 'Generate install command' }).click()
  const command = dialog.getByLabel('Run on the agent machine', { exact: true })
  await expect(command).toHaveValue(/curl --fail/)
  const curl = await command.inputValue()
  expect(curl).toContain('https://console.example.invalid/v1/console/install/')
  expect(curl).toContain('sudo sh "$f"')
  expect(writes).toEqual([{ ttl_seconds: 900 }])
  await dialog.getByLabel('Download tool').selectOption('wget')
  await expect(command).toHaveValue(/wget --quiet --https-only/)
  const url = curl.match(
    /https:\/\/console\.example\.invalid\/v1\/console\/install\/[A-Za-z0-9_-]+/,
  )![0]
  expect(await command.inputValue()).toContain(url)
  await dialog.getByRole('button', { name: 'Copy command' }).click()
  await expect(dialog.getByRole('status')).toContainText(
    /Copied|Copy the selected command manually/,
  )
  expect(
    await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage })),
  ).not.toContain(url)
  expect(await dialog.evaluate((el) => el.scrollHeight <= el.clientHeight)).toBe(true)
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  await page.screenshot({ path: '/tmp/argus-install-command.png', fullPage: true })
  await dialog.getByRole('button', { name: 'Done', exact: true }).click()
  await page.getByRole('button', { name: 'Add agent', exact: true }).click()
  await expect(page.getByLabel('Run on the agent machine', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Generate install command' })).toBeVisible()
})

test('expired commands clear and Chinese dark mode remains usable on mobile', async ({ page }) => {
  await page.clock.install()
  await page.goto('/manage/agents?scenario=admin')
  await page.getByRole('button', { name: 'Switch to dark mode' }).click()
  await page.getByRole('button', { name: '切换为中文' }).click()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: '添加 Agent', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: '添加 Agent' })
  await dialog.getByLabel('命令有效期（分钟）').fill('1')
  await dialog.getByRole('button', { name: '生成安装命令' }).click()
  await expect(dialog.getByLabel('在 Agent 主机上运行')).not.toHaveValue('')
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([])
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.clock.fastForward(65000)
  await expect(dialog.getByLabel('在 Agent 主机上运行')).toHaveValue('')
  await expect(dialog.getByRole('button', { name: '复制命令' })).toBeDisabled()
})

test('unconfigured production installer explains the manual fallback', async ({ page }) => {
  await page.route('**/v1/me', (route) => route.fulfill({ json: identity('Admin') }))
  await page.route('**/v1/console/admin/agents?**', (route) =>
    route.fulfill({ json: { items: [], total: 0, next_cursor: null } }),
  )
  await page.route('**/v1/console/admin/installer', (route) =>
    route.fulfill({ json: { enabled: false, platforms: [], fleet_origin: '' } }),
  )
  await page.goto('http://127.0.0.1:4173/manage/agents')
  await page.getByRole('button', { name: 'Add agent', exact: true }).click()
  await expect(page.getByText(/Automatic installation is not configured/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Generate install command' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Manual enrollment', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Create enrollment token' })).toBeVisible()
})
