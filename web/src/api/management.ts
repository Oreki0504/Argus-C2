import { ApiError, request } from './client'
import { emptySchema } from './contracts'
import {
  objectId,
  agentsPageSchema,
  tasksPageSchema,
  auditPageSchema,
  usersPageSchema,
  createTaskSchema,
  managedTaskSchema,
  taskDetailSchema,
  enrollmentRequestSchema,
  enrollmentSchema,
  installerStatusSchema,
  installationSchema,
  managedAgentSchema,
  disableAgentSchema,
  managedUserSchema,
  updateUserSchema,
  type CreateTask,
  type UpdateUser,
} from './management-contracts'

export type ListFilters = Record<string, string | number | undefined>
const root = '/v1/console/admin'
function listPath(resource: string, filters: ListFilters) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters))
    if (value !== undefined && value !== '') params.set(key, String(value))
  return `${root}/${resource}?${params}`
}
const id = (value: string) => objectId.parse(value)
export const management = {
  installer: (signal?: AbortSignal) =>
    request(`${root}/installer`, installerStatusSchema, { signal }),
  install: (ttl_seconds: number, csrf: string) =>
    request(`${root}/installations`, installationSchema, {
      body: enrollmentRequestSchema.parse({ ttl_seconds }),
      csrf,
    }),
  agents: (filters: ListFilters, signal?: AbortSignal) =>
    request(listPath('agents', filters), agentsPageSchema, { signal }),
  tasks: (filters: ListFilters, signal?: AbortSignal) =>
    request(listPath('tasks', filters), tasksPageSchema, { signal }),
  task: async (taskId: string, signal?: AbortSignal) => {
    const detail = await request(`${root}/tasks/${id(taskId)}`, taskDetailSchema, { signal })
    if (detail.task.id !== taskId) throw new ApiError(200, 'invalid_response')
    return detail
  },
  createTask: (body: CreateTask, csrf: string) =>
    request(`${root}/tasks`, managedTaskSchema, { body: createTaskSchema.parse(body), csrf }),
  enroll: (ttl_seconds: number, csrf: string) =>
    request(`${root}/enrollment-tokens`, enrollmentSchema, {
      body: enrollmentRequestSchema.parse({ ttl_seconds }),
      csrf,
    }),
  disable: (nodeId: string, confirmation: string, csrf: string) =>
    request(`${root}/agents/${id(nodeId)}/disable`, managedAgentSchema, {
      body: disableAgentSchema.parse({ confirm_node_id: confirmation }),
      csrf,
    }),
  rename: (nodeId: string, display_name: string, csrf: string) =>
    request(`${root}/agents/${id(nodeId)}/rename`, emptySchema, { body: { display_name }, csrf }),
  remove: (nodeId: string, confirmation: string, csrf: string) =>
    request(`${root}/agents/${id(nodeId)}/delete`, emptySchema, {
      body: disableAgentSchema.parse({ confirm_node_id: confirmation }),
      csrf,
    }),
  audit: (filters: ListFilters, signal?: AbortSignal) =>
    request(listPath('audit', filters), auditPageSchema, { signal }),
  users: (filters: ListFilters, signal?: AbortSignal) =>
    request(listPath('users', filters), usersPageSchema, { signal }),
  updateUser: (userId: string, body: UpdateUser, csrf: string) =>
    request(`${root}/users/${id(userId)}`, managedUserSchema, {
      body: updateUserSchema.parse(body),
      csrf,
    }),
  revokeSessions: (userId: string, csrf: string) =>
    request(`${root}/users/${id(userId)}/revoke-sessions`, emptySchema, { body: {}, csrf }),
}
