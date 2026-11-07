import { readFileSync } from 'node:fs'
import { expect, test } from 'vitest'
import { identitySchema, summarySchema, nodeHistorySchema } from './contracts'
import {
  agentsPageSchema,
  tasksPageSchema,
  taskDetailSchema,
  usersPageSchema,
  auditPageSchema,
  enrollmentSchema,
} from './management-contracts'

const filename = process.env.ARGUS_CONSOLE_CONTRACT_FILE
test.skipIf(!filename)('actual Go Console responses satisfy the browser contracts', () => {
  const responses = JSON.parse(readFileSync(filename!, 'utf8')) as Record<string, unknown>
  const schemas = {
    identity: identitySchema,
    summary: summarySchema,
    history: nodeHistorySchema,
    agents: agentsPageSchema,
    tasks: tasksPageSchema,
    task: taskDetailSchema,
    users: usersPageSchema,
    audit: auditPageSchema,
    enrollment: enrollmentSchema,
  }
  for (const [name, schema] of Object.entries(schemas)) {
    expect(schema.safeParse(responses[name]).success, name).toBe(true)
  }
})
