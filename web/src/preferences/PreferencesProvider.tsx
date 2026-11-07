import { useLayoutEffect, useState, type ReactNode } from 'react'
import { PreferencesContext, type Theme } from './context'
import { readLanguage } from './messages'

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState(readLanguage)
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const value = localStorage.getItem('argus.theme')
      if (value === 'light' || value === 'dark') return value
    } catch {
      /* Storage may be unavailable. */
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })
  useLayoutEffect(() => {
    document.documentElement.lang = language
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('argus.language', language)
      localStorage.setItem('argus.theme', theme)
    } catch {
      /* Keep in-memory preferences functional. */
    }
  }, [language, theme])
  return (
    <PreferencesContext.Provider
      value={{
        language,
        theme,
        toggleLanguage: () => setLanguage((value) => (value === 'en' ? 'zh-CN' : 'en')),
        toggleTheme: () => setTheme((value) => (value === 'light' ? 'dark' : 'light')),
      }}
    >
      {children}
    </PreferencesContext.Provider>
  )
}
