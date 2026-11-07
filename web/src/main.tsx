import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { PreferencesProvider } from './preferences/PreferencesProvider'
import { clearSession, createQueryClient } from './api/query'
import '@fontsource-variable/geist'
import './styles.css'
import './viewer.css'
import './appearance.css'
import './management.css'

async function main() {
  if (import.meta.env.DEV && import.meta.env.MODE === 'mock') {
    const { startMocks } = await import('./mocks/browser')
    await startMocks()
  }
  let invalidating = false
  const client = createQueryClient((status) => {
    if (invalidating) return
    invalidating = true
    void clearSession(client).then(() =>
      window.location.replace(status === 403 ? '/login?reason=forbidden' : '/'),
    )
  })
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <QueryClientProvider client={client}>
        <BrowserRouter>
          <PreferencesProvider>
            <App />
          </PreferencesProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  )
}

void main().catch(() => {
  // Fail closed if the preview worker or application cannot initialize.
  document.getElementById('root')!.textContent =
    'The console could not start. Reload the page to try again.'
})
