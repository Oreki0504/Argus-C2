import { createContext, useContext } from 'react'
import type { Identity } from '../../api/contracts'

// null means an anonymous viewer, not a fabricated Web account or session.
export const IdentityContext = createContext<Identity | null | undefined>(undefined)
export function useViewer() {
  const identity = useContext(IdentityContext)
  if (identity === undefined) throw new Error('Viewer context required')
  return identity
}
export function useIdentity() {
  const identity = useViewer()
  if (!identity) throw new Error('Authenticated route required')
  return identity
}
