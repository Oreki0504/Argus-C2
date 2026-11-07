import { createContext, useContext } from 'react'
import { translate, type Language } from './messages'

export type Theme = 'light' | 'dark'
export const PreferencesContext = createContext({
  language: 'en' as Language,
  theme: 'light' as Theme,
  toggleLanguage: () => {},
  toggleTheme: () => {},
})
export function usePreferences() {
  const preferences = useContext(PreferencesContext)
  return {
    ...preferences,
    t: (text: string, values?: Record<string, string | number>) =>
      translate(preferences.language, text, values),
  }
}
