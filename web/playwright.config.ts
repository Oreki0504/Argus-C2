import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 2,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
    launchOptions: process.env.ARGUS_CHROMIUM_PATH
      ? { executablePath: process.env.ARGUS_CHROMIUM_PATH }
      : undefined,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: process.env.ARGUS_CONSOLE_BROWSER_INFO
    ? undefined
    : [
        { command: 'npm run dev:mock', url: 'http://127.0.0.1:5173', reuseExistingServer: false },
        {
          command: 'npm run preview -- --port 4173',
          url: 'http://127.0.0.1:4173',
          reuseExistingServer: false,
        },
      ],
})
