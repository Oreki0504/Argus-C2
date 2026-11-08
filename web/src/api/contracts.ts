import { z } from 'zod'

// Browser Console contracts, separate from the existing CLI Bearer API.
// Strict schemas detect contract drift; only the Go projection can prevent
// disclosure over the network. Never fetch full nodes/tasks for a Web User.
const timestamp = z.number().int().nonnegative()
const percentage = z.number().min(0).max(100).nullable()
export const capabilitySchema = z.enum([
  'summary:read',
  'tasks:read',
  'tasks:write',
  'agents:read',
  'agents:write',
  'audit:read',
  'users:read',
  'users:write',
])
export type Capability = z.infer<typeof capabilitySchema>
export const identitySchema = z.strictObject({
  principal_id: z.string().min(1),
  name: z.string().min(1),
  role: z.enum(['Admin', 'User']),
  csrf_token: z.string().min(1),
  capabilities: z.array(capabilitySchema),
})
export type Identity = z.infer<typeof identitySchema>

export const providerKindSchema = z.enum(['google', 'github', 'oidc'])
export type ProviderKind = z.infer<typeof providerKindSchema>
const providerSummarySchema = z.strictObject({ kind: providerKindSchema, name: z.string() })
export type LoginProvider = z.infer<typeof providerSummarySchema>
export type ProviderCredentials = {
  kind: ProviderKind
  issuer: string
  client_id: string
  client_secret: string
}
const callbackURI = z.url().refine((value) => new URL(value).protocol === 'https:')
export const authStatusSchema = z.strictObject({
  token_enabled: z.boolean().default(false),
  state: z.enum(['UNINITIALIZED', 'SETUP_PENDING', 'ACTIVE']),
  provider_name: z.string().nullable(),
  providers: z.array(providerSummarySchema).max(3).default([]),
  csrf_token: z.string().min(1),
})
export const setupSchema = z.strictObject({
  step: z.enum(['provider', 'bind']),
  csrf_token: z.string().min(1),
  callback_uri: callbackURI,
  callback_uris: z.strictObject({ google: callbackURI, github: callbackURI, oidc: callbackURI }),
  providers: z
    .array(providerSummarySchema.extend({ issuer: z.string(), client_id: z.string() }))
    .max(3),
  issuer: z.string(),
  client_id: z.string(),
})
export type Setup = z.infer<typeof setupSchema>

export const accountSchema = z.strictObject({
  token_enabled: z.boolean(),
  can_disable_token: z.boolean(),
  csrf_token: z.string().min(1),
  providers: z.array(providerSummarySchema.extend({ issuer: z.string() })),
  identities: z.array(
    z.strictObject({ issuer: z.string(), subject: z.string(), created_at: timestamp }),
  ),
})

export const publicNodeSchema = z.strictObject({
  public_id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  display_name: z.string(),
  last_seen_at: timestamp,
  system: z.strictObject({
    os: z.string().nullable(),
    architecture: z.string().nullable(),
    kernel: z.string().nullable(),
    uptime_seconds: z.number().nonnegative().nullable(),
  }),
  resources: z.strictObject({
    as_of: timestamp.nullable(),
    cpu_percent: percentage,
    memory_percent: percentage,
    disk_percent: percentage,
  }),
  traffic: z.strictObject({
    as_of: timestamp.nullable(),
    inbound_bps: z.number().nonnegative().nullable(),
    outbound_bps: z.number().nonnegative().nullable(),
    inbound_capacity_bps: z.number().positive().nullable(),
    outbound_capacity_bps: z.number().positive().nullable(),
    sampled_inbound_bytes: z.number().nonnegative().nullable(),
    sampled_outbound_bytes: z.number().nonnegative().nullable(),
    coverage_percent: percentage,
  }),
})
export type PublicNode = z.infer<typeof publicNodeSchema>
export const summarySchema = z.strictObject({
  generated_at: timestamp,
  window_start: timestamp,
  window_end: timestamp,
  sample_interval_seconds: z.number().positive(),
  nodes: z.array(publicNodeSchema),
})
export type Summary = z.infer<typeof summarySchema>

export const historyRangeSchema = z.enum(['1h', '24h', '7d'])
export type HistoryRange = z.infer<typeof historyRangeSchema>
export const historyPointSchema = z.strictObject({
  timestamp,
  cpu_percent: percentage,
  memory_percent: percentage,
  disk_percent: percentage,
  // Percentages use the capacity configured at the time of each observation.
  // They can exceed 100 when traffic exceeds the configured baseline.
  inbound_percent: z.number().nonnegative().nullable(),
  outbound_percent: z.number().nonnegative().nullable(),
})
export type HistoryPoint = z.infer<typeof historyPointSchema>
export const nodeHistorySchema = z
  .strictObject({
    public_id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
    range: historyRangeSchema,
    window_start: timestamp,
    window_end: timestamp,
    sample_interval_seconds: z.number().positive(),
    points: z.array(historyPointSchema).max(2000),
  })
  .superRefine((history, context) => {
    if (history.window_start >= history.window_end)
      context.addIssue({ code: 'custom', message: 'Invalid window' })
    let previous = -1
    for (const point of history.points) {
      if (
        point.timestamp <= previous ||
        point.timestamp < history.window_start ||
        point.timestamp > history.window_end
      ) {
        context.addIssue({ code: 'custom', message: 'Invalid sample order or time' })
        break
      }
      previous = point.timestamp
    }
  })
export type NodeHistory = z.infer<typeof nodeHistorySchema>

export const emptySchema = z.strictObject({})
// Top-level navigation to this same-origin route lets the server redirect to
// its configured provider without relaxing CSP form-action or CORS.
export const oidcStartSchema = z.strictObject({
  redirect_path: z.literal('/v1/console/auth/redirect'),
})
