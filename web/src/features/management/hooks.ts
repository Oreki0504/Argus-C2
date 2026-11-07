import { useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { consoleKey } from '../../api/query'
import { ApiError } from '../../api/client'
import { useIdentity } from '../auth/context'

export function useManagement() {
  const identity = useIdentity()
  const client = useQueryClient()
  const key = [...consoleKey(identity), 'management']
  return { identity, key, refresh: () => client.invalidateQueries({ queryKey: key }) }
}

export function useListNavigation(keys: string[]) {
  const [params, setParams] = useSearchParams()
  const previous = useRef(new Map<string, string>())
  const cursor = params.get('cursor') ?? ''
  const filters = Object.fromEntries(keys.map((key) => [key, params.get(key) ?? '']))
  const signature = JSON.stringify(filters)
  const change = (key: string, value: string) => {
    previous.current.clear()
    setParams(
      (current) => {
        const next = new URLSearchParams(current)
        next.delete('cursor')
        if (value) next.set(key, value)
        else next.delete(key)
        return next
      },
      { replace: true },
    )
  }
  const advance = (nextCursor: string) => {
    previous.current.set(`${signature}:${nextCursor}`, cursor)
    setParams((current) => {
      const next = new URLSearchParams(current)
      next.set('cursor', nextCursor)
      return next
    })
  }
  const back = () => {
    const prior = previous.current.get(`${signature}:${cursor}`) ?? ''
    setParams((current) => {
      const next = new URLSearchParams(current)
      if (prior) next.set('cursor', prior)
      else next.delete('cursor')
      return next
    })
  }
  return { filters, cursor, change, advance, back }
}

export function uncertainWrite(error: unknown) {
  return (
    error instanceof ApiError &&
    (error.status === 0 || error.status >= 500 || error.code === 'invalid_response')
  )
}
