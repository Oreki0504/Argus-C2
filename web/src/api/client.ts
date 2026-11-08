import type { z } from 'zod'
import { nodeHistorySchema, type HistoryRange } from './contracts'
import {
  authStatusSchema,
  accountSchema,
  emptySchema,
  identitySchema,
  oidcStartSchema,
  setupSchema,
  summarySchema,
} from './contracts'

export const oauthCallbackReasons = [
  'oauth_callback_invalid',
  'oauth_cookie_missing',
  'oauth_flow_expired',
  'oauth_state_mismatch',
  'oauth_callback_mismatch',
  'oauth_issuer_mismatch',
  'oauth_provider_rejected',
  'oauth_configuration_changed',
  'oauth_account_failed',
] as const

export const githubAuthReasons = [
  'github_access_denied',
  'github_client_invalid',
  'github_redirect_mismatch',
  'github_code_rejected',
  'github_email_unverified',
  'github_exchange_failed',
  'github_profile_failed',
  'github_unavailable',
] as const

const messages: Record<string, string> = {
  oauth_callback_invalid:
    'The provider returned an incomplete authorization callback. Start sign-in again.',
  oauth_cookie_missing:
    'The browser did not return the login cookie. Use the same browser and Console address, allow cookies, then start sign-in again.',
  oauth_flow_expired:
    'This authorization attempt expired or was replaced, or the server restarted. Start sign-in again in one tab.',
  oauth_state_mismatch:
    'This callback belongs to a different authorization attempt. Close older sign-in tabs and start again.',
  oauth_callback_mismatch:
    'The callback path does not match the selected provider. Copy its exact callback URL from app settings.',
  oauth_issuer_mismatch:
    'The authorization issuer does not match the configured provider. Check the provider and callback settings.',
  oauth_provider_rejected:
    'The provider declined authorization or returned no code. Check the app permissions and try again.',
  oauth_configuration_changed:
    'Login settings changed during authorization. Start a fresh sign-in attempt.',
  oauth_account_failed:
    'ARGUS could not read or update the account state. Check the server callback diagnostics.',
  oauth_verification_required:
    'Sign in with a linked OAuth account, or complete linking, within ten minutes before disabling token login.',
  last_signin_method:
    'Token login is disabled. Keep a provider linked to your administrator account enabled.',

  github_access_denied:
    'GitHub authorization was cancelled. Start linking again and approve access.',
  github_client_invalid:
    'GitHub rejected the OAuth app credentials. Check that Client ID and Client Secret belong to the same OAuth App, then save the app settings again.',
  github_redirect_mismatch:
    'GitHub rejected the callback URL. Copy the complete GitHub callback URL from app settings into the GitHub OAuth App.',
  github_code_rejected:
    'GitHub rejected the authorization code. Start a fresh linking attempt; do not reuse or refresh the callback page.',
  github_email_unverified: 'Verify your email address in GitHub, then start linking again.',
  github_exchange_failed:
    'ARGUS could not exchange the GitHub authorization code. The server log records the token_exchange failure stage.',
  github_profile_failed:
    'ARGUS could not verify your GitHub user profile. The server log records the user_info failure stage.',
  github_unavailable:
    'The ARGUS server could not reach GitHub or GitHub is temporarily unavailable. Try again; the server log records the failed stage.',

  token_invalid:
    'The login token is invalid or has been replaced. Read the current token on your server.',
  identity_conflict:
    'This identity is already linked to another account. It cannot be transferred here.',
  installer_unavailable:
    'Automatic installation is not configured. Use manual enrollment or contact the server operator.',
  invalid_request: 'Check the form values and try again.',
  node_disabled: 'This agent is disabled and cannot receive tasks.',
  state_conflict: 'The agent queue is full or the record changed. Refresh before trying again.',
  not_found: 'This record is no longer available. Refresh the list.',
  user_conflict: 'This account changed. Close this form and refresh before editing again.',
  last_admin: 'At least one active administrator must remain.',
  self_change: 'Use another administrator account to change your own access.',
  reauthentication_required: 'Sign in again before changing administrator access.',
  session_expired: 'Your session has expired. Sign in again to continue.',
  forbidden: 'Your account does not have access to this page.',
  bootstrap_invalid: 'The setup secret is invalid, expired, or already used.',
  setup_closed: 'Setup is closed. This console has already been activated.',
  oidc_unavailable: 'The identity provider is unavailable. Please try again later.',
  oidc_callback_invalid: 'Sign-in could not be verified. Start a new sign-in attempt.',
  account_pending: 'Your identity is verified. An administrator must approve access.',
  csrf_invalid: 'This form has expired. Reload the page before trying again.',
  rate_limited: 'Too many attempts. Please wait before trying again.',
  service_unavailable: 'The console is temporarily unavailable. Please try again.',
  invalid_response: 'The Console API returned an unexpected response.',
  network_error: 'Unable to reach the console. Check your connection and try again.',
  console_unavailable:
    'The Console API is not available. Complete the server Console setup to connect.',
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(messages[code] ?? 'The request could not be completed. Please try again.')
    this.name = 'ApiError'
  }
}

export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: {
    signal?: AbortSignal
    body?: unknown
    csrf?: string
  } = {},
): Promise<T> {
  if (!/^\/v1\/(console\/|me$)/.test(path) || path.includes('..')) {
    throw new Error('Only same-origin Console API paths are allowed')
  }
  if (options.body !== undefined && !options.csrf) throw new Error('CSRF token required')
  let response: Response
  try {
    response = await fetch(path, {
      method: options.body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: options.signal,
      headers: {
        Accept: 'application/json',
        ...(options.body !== undefined
          ? { 'Content-Type': 'application/json', 'X-CSRF-Token': options.csrf! }
          : {}),
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch (error) {
    if (options.signal?.aborted) throw error
    throw new ApiError(0, 'network_error')
  }
  if (!response.ok) {
    let code =
      (
        {
          401: 'session_expired',
          403: 'forbidden',
          404: 'console_unavailable',
          429: 'rate_limited',
          503: 'service_unavailable',
        } as Record<number, string>
      )[response.status] ?? 'request_failed'
    try {
      const data: unknown = await response.json()
      if (
        data &&
        typeof data === 'object' &&
        'code' in data &&
        typeof data.code === 'string' &&
        Object.hasOwn(messages, data.code)
      )
        code = data.code
    } catch {
      /* Non-JSON errors must never be rendered as server HTML. */
    }
    throw new ApiError(response.status, code)
  }
  try {
    return schema.parse(await response.json())
  } catch {
    // Do not retain the raw body or validator errors (possibly sensitive fields).
    throw new ApiError(response.status, 'invalid_response')
  }
}

export const api = {
  tokenLogin: (token: string, csrf: string) =>
    request('/v1/console/auth/token', identitySchema, { body: { token }, csrf }),
  disableToken: (csrf: string) =>
    request('/v1/console/account/token/disable', emptySchema, { body: { confirm: true }, csrf }),
  account: (signal?: AbortSignal) => request('/v1/console/account', accountSchema, { signal }),
  accountProviders: (signal?: AbortSignal) =>
    request('/v1/console/account/providers', setupSchema, { signal }),
  accountProvider: (
    body: { providers: import('./contracts').ProviderCredentials[] },
    csrf: string,
  ) => request('/v1/console/account/providers', setupSchema, { body, csrf }),
  bindAccount: (provider: import('./contracts').ProviderKind, csrf: string) =>
    request('/v1/console/account/bind', oidcStartSchema, { body: { provider }, csrf }),
  me: (signal?: AbortSignal) => request('/v1/me', identitySchema, { signal }),
  authStatus: (signal?: AbortSignal) =>
    request('/v1/console/auth/status', authStatusSchema, { signal }),
  logout: (csrf: string) => request('/v1/console/auth/logout', emptySchema, { body: {}, csrf }),
  beginOIDC: (
    csrf: string,
    setup: boolean,
    provider: import('./contracts').ProviderKind = 'oidc',
  ) =>
    request(setup ? '/v1/console/setup/bind' : '/v1/console/auth/login', oidcStartSchema, {
      body: { provider },
      csrf,
    }),
  setup: (signal?: AbortSignal) => request('/v1/console/setup', setupSchema, { signal }),
  prove: (secret: string, csrf: string) =>
    request('/v1/console/setup/prove', setupSchema, { body: { secret }, csrf }),
  provider: (body: { providers: import('./contracts').ProviderCredentials[] }, csrf: string) =>
    request('/v1/console/setup/provider', setupSchema, { body, csrf }),
  summary: (signal?: AbortSignal) => request('/v1/console/summary', summarySchema, { signal }),
  publicSummary: (signal?: AbortSignal) =>
    request('/v1/console/public/summary', summarySchema, { signal }),
  history: async (id: string, range: HistoryRange, anonymous: boolean, signal?: AbortSignal) => {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new ApiError(404, 'console_unavailable')
    const data = await request(
      `/v1/console/${anonymous ? 'public/' : ''}nodes/${id}/history?range=${range}`,
      nodeHistorySchema,
      { signal },
    )
    if (data.public_id !== id || data.range !== range) throw new ApiError(200, 'invalid_response')
    return data
  },
}
