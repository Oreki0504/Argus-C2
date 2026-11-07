import { useEffect, useState } from 'react'

function measurePageSize() {
  const width = Math.min(window.innerWidth, 1488) - (window.innerWidth <= 672 ? 32 : 48)
  const columns = width >= 1140 ? 3 : width >= 740 ? 2 : 1
  // Reserve room for the heading, five filter cards, search and pagination.
  const rows = Math.max(1, Math.min(4, Math.floor((window.innerHeight - 350) / 170)))
  return columns * rows
}

// Matches the compact layout: bounded rows rather than a growing page.
export function useCardPageSize() {
  const [pageSize, setPageSize] = useState(measurePageSize)
  useEffect(() => {
    const onResize = () => setPageSize(measurePageSize())
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return pageSize
}
