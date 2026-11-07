import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { consoleKey } from '../../api/query'
import { useViewer } from '../auth/context'

export function useSummary() {
  const identity = useViewer()
  return useQuery({
    queryKey: [...(identity ? consoleKey(identity) : ['public-console']), 'summary'],
    queryFn: ({ signal }) => (identity ? api.summary(signal) : api.publicSummary(signal)),
    enabled: !identity || identity.capabilities.includes('summary:read'),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  })
}

export function useNow() {
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now() / 1000), 15_000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}
