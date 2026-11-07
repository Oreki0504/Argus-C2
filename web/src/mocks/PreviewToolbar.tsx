import { usePreferences } from '../preferences/context'
import { FlaskConical } from 'lucide-react'
import { scenarios } from './fixtures'
import { previewScenario } from './browser'

export default function PreviewToolbar() {
  const { language } = usePreferences()
  const chinese = language === 'zh-CN'
  return (
    <aside
      className="preview-toolbar"
      aria-label={chinese ? '开发预览控制' : 'Development preview controls'}
    >
      <span>
        <FlaskConical size={15} />
        <strong>{chinese ? '设计预览' : 'Design preview'}</strong>
        <span className="preview-description">
          {chinese
            ? '模拟数据与登录 · 未连接真实服务器'
            : 'Simulated data and sign-in · no live fleet connection'}
        </span>
      </span>
      <label>
        {chinese ? '场景' : 'Scenario'}
        <select
          value={previewScenario}
          onChange={(event) => {
            window.location.href = `/?scenario=${encodeURIComponent(event.target.value)}`
          }}
        >
          {scenarios.map((value) => (
            <option key={value}>{value}</option>
          ))}
        </select>
      </label>
    </aside>
  )
}
