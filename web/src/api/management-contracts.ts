import { z } from 'zod'

// Session-authenticated Console DTOs; never use the CLI Bearer API.
export const objectId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/)
const timestamp = z.number().int().nonnegative()
const resourceId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/)
export const taskTypes = [
  'system.info',
  'system.metrics',
  'service.status',
  'ssh.audit',
  'process.list',
  'network.listeners',
] as const
export const taskStates = [
  'PENDING',
  'ACCEPTED',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'UNKNOWN',
] as const
export const taskTypeSchema = z.enum(taskTypes)
const parameterSchema = z.union([
  z.strictObject({}),
  z.strictObject({ service_id: resourceId }),
  z.strictObject({ profile_id: resourceId }),
])
function parametersMatch(value: { task_type: string; parameters: Record<string, unknown> }) {
  const expected =
    value.task_type === 'service.status'
      ? 'service_id'
      : value.task_type === 'ssh.audit'
        ? 'profile_id'
        : null
  const keys = Object.keys(value.parameters)
  return expected ? keys.length === 1 && keys[0] === expected : keys.length === 0
}
export const createTaskSchema = z
  .strictObject({
    node_id: objectId,
    task_type: taskTypeSchema,
    parameters: parameterSchema,
    ttl_seconds: z.number().int().min(10).max(3600),
    execution_timeout_ms: z.number().int().min(1).max(30000),
  })
  .refine(parametersMatch, { message: 'Invalid task parameters', path: ['parameters'] })
export type CreateTask = z.infer<typeof createTaskSchema>
export const managedAgentSchema = z.strictObject({
  node_id: objectId,
  public_id: objectId,
  display_name: z.string(),
  hostname: z.string(),
  status: z.enum(['active', 'disabled']),
  last_seen_at: timestamp,
  created_at: timestamp,
  agent_version: z.string(),
  protocol_version: z.number().int().positive(),
  certificate_expires_at: timestamp,
})
export type ManagedAgent = z.infer<typeof managedAgentSchema>
export const managedTaskSchema = z
  .strictObject({
    id: objectId,
    node_id: objectId,
    agent_name: z.string(),
    task_type: taskTypeSchema,
    parameters: parameterSchema,
    status: z.enum(taskStates),
    created_at: timestamp,
    dispatch_expires_at: timestamp,
    execution_timeout_ms: z.number().int().min(1).max(30000),
    result_due_at: timestamp,
    execution_authorized_at: timestamp.nullable(),
    result_received_at: timestamp.nullable(),
  })
  .refine(parametersMatch, { message: 'Invalid task parameters' })
export type ManagedTask = z.infer<typeof managedTaskSchema>
export const taskDetailSchema = z.strictObject({
  task: managedTaskSchema,
  result: z
    .strictObject({
      status: z.enum(['SUCCEEDED', 'FAILED', 'UNKNOWN']),
      error: z.string().max(128),
      completed_at: timestamp,
      payload: z.record(z.string(), z.json()),
    })
    .nullable(),
})
export type TaskDetail = z.infer<typeof taskDetailSchema>
export const auditEventSchema = z.strictObject({
  id: z.number().int().positive(),
  timestamp,
  actor: z.string(),
  action: z.string(),
  node_id: objectId.nullable(),
  task_id: objectId.nullable(),
  subject_id: objectId.nullable(),
  status: z.string(),
})
export type AuditEvent = z.infer<typeof auditEventSchema>
export const managedUserSchema = z.strictObject({
  id: objectId,
  name: z.string(),
  issuer: z.string(),
  subject: z.string(),
  role: z.enum(['Admin', 'User']),
  status: z.enum(['pending', 'active', 'disabled']),
  created_at: timestamp,
  last_login_at: timestamp.nullable(),
  version: z.number().int().positive(),
})
export type ManagedUser = z.infer<typeof managedUserSchema>
export const updateUserSchema = z.strictObject({
  role: z.enum(['Admin', 'User']),
  status: z.enum(['active', 'disabled']),
  expected_version: z.number().int().positive(),
  confirm_subject: z.string().min(1),
})
export type UpdateUser = z.infer<typeof updateUserSchema>
export const enrollmentRequestSchema = z.strictObject({
  ttl_seconds: z.number().int().min(60).max(3600),
})
export const enrollmentSchema = z.strictObject({
  token: z.string().min(1).max(512),
  expires_at: timestamp,
})
export type Enrollment = z.infer<typeof enrollmentSchema>
export const installerStatusSchema = z.strictObject({
  enabled: z.boolean(),
  platforms: z.array(z.enum(['linux/amd64', 'linux/arm64'])).max(2),
  fleet_origin: z.string(),
})
export const installationSchema = z.strictObject({
  installation_id: objectId,
  url: z
    .string()
    .max(2048)
    .regex(/^https:\/\/[a-z0-9.[\]:-]+\/v1\/console\/install\/[A-Za-z0-9_-]{1,64}$/),
  expires_at: timestamp,
})
export const disableAgentSchema = z.strictObject({ confirm_node_id: objectId })
const page = <T extends z.ZodType>(item: T) =>
  z.strictObject({
    items: z.array(item).max(200),
    total: z.number().int().nonnegative(),
    next_cursor: z.string().max(2048).nullable(),
  })
export const agentsPageSchema = page(managedAgentSchema)
export const tasksPageSchema = page(managedTaskSchema)
export const auditPageSchema = page(auditEventSchema)
export const usersPageSchema = page(managedUserSchema)
