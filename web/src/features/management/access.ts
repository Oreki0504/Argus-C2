import type { Capability, Identity } from '../../api/contracts'

export const managementSections = [
  { path: 'tasks', label: 'Tasks', capability: 'tasks:read' },
  { path: 'agents', label: 'Agents', capability: 'agents:read' },
  { path: 'audit', label: 'Audit', capability: 'audit:read' },
  { path: 'users', label: 'Users & access', capability: 'users:read' },
] as const
export const canManage = (identity: Identity | null, capability: Capability) =>
  identity?.role === 'Admin' && identity.capabilities.includes(capability)
export const hasManagement = (identity: Identity | null) =>
  managementSections.some((section) => canManage(identity, section.capability))
