import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { expect, test } from '@playwright/test'

const infoFile = process.env.ARGUS_CONSOLE_BROWSER_INFO
test('real HTTPS Console logs in with token, binds OIDC and performs authenticated management', async ({
  browser,
}) => {
  test.skip(!infoFile, 'Requires the isolated Go Console browser harness')
  const info = JSON.parse(readFileSync(infoFile!, 'utf8')) as Record<string, string>
  // The opt-in harness has ephemeral self-signed test certificates. Production
  // clients and the Console OIDC transport retain certificate verification.
  const context = await browser.newContext({ ignoreHTTPSErrors: true })
  const page = await context.newPage()
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  try {
    await page.goto(`${info.origin}/setup`)
    await page.getByLabel('Administrator token').fill(info.bootstrap)
    await page.getByRole('button', { name: 'Enter console', exact: true }).click()
    await expect(page.getByRole('link', { name: 'Management', exact: true })).toBeVisible()
    await page.getByRole('link', { name: /Account & sign-in/ }).click()
    await page.getByText('Configure sign-in providers (optional)', { exact: true }).click()
    await page.getByRole('checkbox', { name: 'Enable GitHub', exact: true }).uncheck()
    await page.getByText('Other identity provider (Auth0 / OIDC)', { exact: true }).click()
    await page.getByRole('checkbox', { name: 'Enable custom SSO', exact: true }).check()
    await page.getByLabel('Issuer URL').fill(info.issuer)
    await page.getByLabel('SSO Client ID', { exact: true }).fill(info.client_id)
    await page.getByLabel('SSO Client Secret', { exact: true }).fill(info.client_secret)
    await page.getByRole('button', { name: 'Save sign-in methods', exact: true }).click()
    await page.getByRole('button', { name: /^Bind with / }).click()
    await expect(page.getByText('Account linked successfully.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Management', exact: true })).toBeVisible()
    await expect(page.getByText('Design preview', { exact: true })).toHaveCount(0)
    await page.getByRole('link', { name: 'Management', exact: true }).click()
    const tabs = page.getByRole('navigation', { name: 'Management sections' })
    await tabs.getByRole('link', { name: 'Agents', exact: true }).click()
    await page.getByRole('button', { name: 'Add agent' }).click()
    await page.getByRole('button', { name: 'Generate install command' }).click()
    const command = await page.getByLabel('Run on the agent machine', { exact: true }).inputValue()
    const installerURL = command.match(
      /https:\/\/localhost:\d+\/v1\/console\/install\/[A-Za-z0-9_-]+/,
    )?.[0]
    expect(installerURL).toBeTruthy()
    // Download only: this test never installs or runs the generated script.
    const script = await context.request.get(installerURL!)
    expect(script.status()).toBe(200)
    expect(script.headers()['cache-control']).toBe('no-store')
    const contents = await script.text()
    expect(contents).toContain('systemctl enable --now argus-c2-agent.service')
    const hash = contents.match(/arch=amd64; expected='([a-f0-9]{64})'/)?.[1]
    expect(hash).toBeTruthy()
    const asset = await context.request.get(
      `${info.origin}/v1/console/install/assets/amd64/${hash}`,
    )
    expect(asset.status()).toBe(200)
    expect(
      createHash('sha256')
        .update(await asset.body())
        .digest('hex'),
    ).toBe(hash)
    expect((await context.request.get(installerURL!)).status()).toBe(404)
    await page.getByRole('button', { name: 'Done', exact: true }).click()
    await page.getByRole('button', { name: 'Add agent' }).click()
    await page.getByRole('button', { name: 'Manual enrollment', exact: true }).click()
    await page.getByRole('button', { name: 'Create enrollment token' }).click()
    await expect(page.getByLabel('Enrollment token', { exact: true })).not.toHaveValue('')
    await page.getByRole('button', { name: 'Done', exact: true }).click()
    await tabs.getByRole('link', { name: 'Audit', exact: true }).click()
    await page.getByRole('textbox', { name: 'Action', exact: true }).fill('enrollment.create')
    await expect(page.getByRole('table')).toContainText('enrollment.create')
    await tabs.getByRole('link', { name: 'Users & access' }).click()
    await expect(page.getByRole('table')).toContainText('Administrator')
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page.getByRole('link', { name: 'Log in', exact: true })).toBeVisible()
    await page.getByRole('link', { name: 'Log in', exact: true }).click()
    await page.getByRole('button', { name: /Continue|Sign in/i }).click()
    await expect(page.getByRole('link', { name: 'Management', exact: true })).toBeVisible()
    expect(errors).toEqual([])
  } finally {
    try {
      await context.close()
    } finally {
      writeFileSync(`${infoFile}.done`, 'done')
    }
  }
})
