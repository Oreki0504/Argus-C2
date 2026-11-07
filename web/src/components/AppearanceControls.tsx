import { Languages, Moon, Sun } from 'lucide-react'
import { usePreferences } from '../preferences/context'

export function AppearanceControls() {
  const { language, theme, toggleLanguage, toggleTheme } = usePreferences()
  const languageLabel = language === 'en' ? '切换为中文' : 'Switch to English'
  const themeLabel =
    language === 'en'
      ? theme === 'light'
        ? 'Switch to dark mode'
        : 'Switch to light mode'
      : theme === 'light'
        ? '切换深色模式'
        : '切换浅色模式'
  return (
    <div className="appearance-controls">
      <button
        className="round-button"
        type="button"
        onClick={toggleLanguage}
        aria-label={languageLabel}
        title={languageLabel}
      >
        <Languages size={18} aria-hidden="true" />
      </button>
      <button
        className="round-button"
        type="button"
        onClick={toggleTheme}
        aria-label={themeLabel}
        title={themeLabel}
      >
        {theme === 'light' ? (
          <Moon size={17} aria-hidden="true" />
        ) : (
          <Sun size={18} aria-hidden="true" />
        )}
      </button>
    </div>
  )
}
