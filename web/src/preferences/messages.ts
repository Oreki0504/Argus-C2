import { managementChinese } from './management-messages'

export type Language = 'en' | 'zh-CN'

const chinese: Record<string, string> = {
  ...managementChinese,
  'Rename agent': '重命名 Agent',
  'Delete agent': '删除 Agent',
  'Display name': '显示名称',
  'This name is visible in the public overview. Do not include private information.':
    '此名称会显示在公开概览中，请勿包含私密信息。',
  'Delete this agent and its task and metric history. Its credentials will stop working. Audit records remain. This does not uninstall software on the host.':
    '删除此 Agent 及其任务、指标历史，原凭据立即失效，审计记录保留。此操作不会卸载主机上的程序。',
  'Link Google or GitHub to this account, then manage how you sign in.':
    '将 Google 或 GitHub 关联到当前账号，再管理你的登录方式。',
  'Administrator token login': '管理员 Token 登录',
  Enabled: '已启用',
  'Token login disabled': 'Token 登录已禁用',
  'Disabling permanently invalidates the original token and ends token-only sessions. OAuth access stays available. Recovery requires access to the server.':
    '禁用后，原始 Token 永久失效，仅用 Token 登录的会话会结束，OAuth 登录不受影响。需要访问服务器本机才能恢复管理员访问。',
  'I can sign in with OAuth and want to disable the original token.':
    '我已确认可以通过 OAuth 登录，并希望禁用原始 Token。',
  'Disable token login': '禁用 Token 登录',
  'Sign in with a linked OAuth account, or complete linking, within ten minutes before disabling token login.':
    '请先使用已关联的 OAuth 账号登录，或完成账号关联，然后在十分钟内禁用 Token 登录。',
  'Token login is disabled. Keep a provider linked to your administrator account enabled.':
    'Token 登录已禁用，请至少保留一个已关联到当前管理员账号的登录平台。',
  'The provider returned an incomplete authorization callback. Start sign-in again.':
    '平台返回的授权回调不完整，请重新发起登录。',
  'The browser did not return the login cookie. Use the same browser and Console address, allow cookies, then start sign-in again.':
    '浏览器没有带回登录 Cookie。请使用同一浏览器和控制台地址，允许 Cookie 后重新发起登录。',
  'This authorization attempt expired or was replaced, or the server restarted. Start sign-in again in one tab.':
    '本次授权已过期、被新请求替换，或服务已重启。请在一个标签页内重新发起登录。',
  'This callback belongs to a different authorization attempt. Close older sign-in tabs and start again.':
    '回调与当前授权请求不匹配。请关闭旧的登录标签页，重新发起登录。',
  'The callback path does not match the selected provider. Copy its exact callback URL from app settings.':
    '回调路径与所选平台不匹配，请从应用设置中复制该平台的完整回调地址。',
  'The authorization issuer does not match the configured provider. Check the provider and callback settings.':
    '授权签发方与配置的平台不匹配，请核对平台与回调设置。',
  'The provider declined authorization or returned no code. Check the app permissions and try again.':
    '平台拒绝授权或未返回授权码，请核对应用权限后重试。',
  'Login settings changed during authorization. Start a fresh sign-in attempt.':
    '授权期间登录配置发生变化，请重新发起登录。',
  'ARGUS could not read or update the account state. Check the server callback diagnostics.':
    'ARGUS 无法读取或更新账号状态，请检查服务端回调诊断。',

  '1. Configure this Console’s OAuth apps (Admin)': '1. 配置本控制台的 OAuth 应用（管理员）',
  'Link your own account': '关联你自己的账号',
  '2. Link your own account': '2. 关联你自己的账号',
  'App configured · account not linked': '应用已配置 · 账号未关联',
  'App settings let this Console contact Google or GitHub. Linking proves which provider account belongs to you. Saving app settings alone does not link your account.':
    '应用配置让本控制台能与 Google / GitHub 通信；关联账号用于确认哪个第三方身份属于你。仅保存应用配置，还没有完成账号关联。',
  'App settings saved. Now link your account below to finish enabling sign-in for yourself.':
    '应用配置已保存。请在下面关联自己的账号，完成后才能使用该方式登录原账号。',
  'GitHub authorization was cancelled. Start linking again and approve access.':
    'GitHub 授权已取消，请重新关联并同意授权。',
  'GitHub rejected the OAuth app credentials. Check that Client ID and Client Secret belong to the same OAuth App, then save the app settings again.':
    'GitHub 拒绝了应用凭据。请确认 Client ID 和 Client Secret 来自同一个 OAuth App，然后重新保存应用配置。',
  'GitHub rejected the callback URL. Copy the complete GitHub callback URL from app settings into the GitHub OAuth App.':
    'GitHub 拒绝了回调地址。请将应用设置中的完整 GitHub 回调地址复制到 GitHub OAuth App。',
  'GitHub rejected the authorization code. Start a fresh linking attempt; do not reuse or refresh the callback page.':
    'GitHub 拒绝了授权码。请重新发起关联，不要重复使用或刷新回调页面。',
  'Verify your email address in GitHub, then start linking again.':
    '请先在 GitHub 验证邮箱，再重新关联。',
  'ARGUS could not exchange the GitHub authorization code. The server log records the token_exchange failure stage.':
    'ARGUS 无法交换 GitHub 授权码。服务日志记录了 token_exchange 阶段的错误分类。',
  'ARGUS could not verify your GitHub user profile. The server log records the user_info failure stage.':
    'ARGUS 无法验证 GitHub 用户资料。服务日志记录了 user_info 阶段的错误分类。',
  'The ARGUS server could not reach GitHub or GitHub is temporarily unavailable. Try again; the server log records the failed stage.':
    'ARGUS 服务端无法连接 GitHub，或 GitHub 暂时不可用。请稍后重试，服务日志会记录失败阶段。',

  'Enter your administrator token': '输入管理员 Token',
  'Use the random token from your installation terminal to enter the console. OAuth can be linked later.':
    '使用安装终端生成的随机 Token 直接进入后台，OAuth 可以稍后绑定。',
  'Administrator token': '管理员 Token',
  'Paste your installation token': '粘贴安装时生成的 Token',
  'Enter console': '进入后台',
  'Signing in…': '正在登录…',
  'Token setup help': 'Token 使用帮助',
  'Your login stays on this Console. Link OAuth later in account settings.':
    '登录当前控制台后，可在账号设置中绑定 OAuth。',
  'The login token is invalid or has been replaced. Read the current token on your server.':
    '登录 Token 无效或已被替换，请在服务器上读取当前 Token。',
  'This identity is already linked to another account. It cannot be transferred here.':
    '该第三方身份已绑定其他账号，不能在这里转移。',
  'Account & sign-in': '账号与登录',
  'Link Google or GitHub to this account. Your permissions and administrator token stay unchanged.':
    '将 Google 或 GitHub 绑定到当前账号，权限和管理员 Token 保持不变。',
  'Account linked successfully.': '账号绑定成功。',
  Linked: '已绑定',
  'Not linked': '未绑定',
  'No OAuth providers configured. You can keep using your administrator token.':
    '尚未配置 OAuth，你可以继续使用管理员 Token。',
  'Configure sign-in providers (optional)': '配置第三方登录（可选）',
  'OAuth is optional. Configure providers here, then link your own account in step 2.':
    'OAuth 为可选功能。在此配置平台后，即可在第 2 步关联自己的账号。',
  'Save sign-in methods': '保存登录方式',
  'How to create a {provider} OAuth app': '如何创建 {provider} OAuth 应用',
  'Open GitHub Settings → Developer settings → OAuth Apps → New OAuth App.':
    '打开 GitHub 的 Settings → Developer settings → OAuth Apps → New OAuth App（OAuth 应用，不是 GitHub App）。',
  'Set Application name to ARGUS and Homepage URL to:':
    'Application name 填 ARGUS，Homepage URL 填写当前控制台地址：',
  'Paste this exact address into Authorization callback URL, then click Register application:':
    '将下面地址完整粘贴到 Authorization callback URL，然后点击 Register application：',
  'Copy Client ID. Click Generate a new client secret, then paste both values into the fields below. Device Flow is not required.':
    '复制 Client ID，点击 Generate a new client secret 生成密钥，将两者填入下方对应输入框。不需要启用 Device Flow。',
  'In Google Cloud, select or create a project. Open Google Auth Platform and complete Branding with an app name, support email and developer contact.':
    '在 Google Cloud 选择或新建项目。打开 Google Auth Platform，在 Branding 中填写应用名称、支持邮箱和开发者联系邮箱。',
  'Under Audience, choose External for personal Google accounts. If the app is in Testing, add the Google account you will use under Test users.':
    '个人 Google 账号在 Audience 中选择 External（外部）。若应用处于 Testing（测试）状态，在 Test users 中加入准备登录的 Google 账号。',
  'Open Clients → Create client. Choose Web application, name it ARGUS, and add this address under Authorized redirect URIs:':
    '进入 Clients → Create client，类型选择 Web application，名称填 ARGUS。在 Authorized redirect URIs 中添加以下地址：',
  'Create the client and copy its Client ID and Client Secret into the fields below. Authorized JavaScript origins are not required for this server login flow.':
    '创建后复制 Client ID 和 Client Secret，填入下方对应输入框。当前登录由服务端处理，不需要填写 Authorized JavaScript origins。',
  'Click Save sign-in methods here, then Bind with Google or GitHub in the account card in step 2. Complete authorization until the card shows Linked.':
    '在此点击“保存登录方式”，再到第 2 步账号卡片点击“绑定 Google / GitHub 账号”，完成跳转授权，直到卡片显示“已绑定”。',
  'Keep the HTTPS scheme, hostname, port and callback path exactly as shown. If you see redirect_uri_mismatch, compare the full address in both places.':
    'HTTPS 协议、域名、端口和回调路径必须与这里完全一致。遇到 redirect_uri_mismatch 时，请核对两处的完整地址。',
  'Google requires an accepted HTTPS domain for a deployed app; a public IP address is not a valid redirect host. Use a domain for your Console before configuring Google.':
    'Google 的线上回调需要使用符合要求的 HTTPS 域名，不能直接填写公网 IP；请先为 Console 配置域名，再配置 Google。',
  'Official setup guide': '官方创建说明',
  'Loading account': '正在加载账号',
  'Loading providers': '正在加载登录方式',
  'No current login token? Run this command on your server, then read the new token file and refresh this page.':
    '没有可用的登录 Token？在服务器执行以下命令，读取新 Token 文件后刷新本页。',
  'Use a new output filename each time. Previously issued tokens and setup sessions will be invalidated.':
    '每次指定一个未使用的输出文件名。旧 Token 和初始化会话将失效。',
  'Choose how you want to sign in.': '选择登录方式。',
  'Your account is verified by your sign-in provider.': '由所选平台验证你的账号身份。',
  'Continue with {provider}': '使用 {provider} 登录',
  'Bind with {provider}': '绑定 {provider} 账号',
  'Enable {provider}': '启用 {provider}',
  'Enable one or both. Sign in below to bind your first administrator.':
    '可以启用一种或两种方式。配置后点击下方按钮，登录并绑定首位管理员。',
  'Other identity provider (Auth0 / OIDC)': '其他登录服务（Auth0 / OIDC）',
  'Enable custom SSO': '启用自定义 SSO',
  'Create OAuth app': '创建 OAuth 应用',
  'Callback URL': '回调地址',
  'Copy {provider} callback URL': '复制 {provider} 回调地址',
  'Paste this address into your OAuth app’s callback settings.':
    '将此地址填入 OAuth 应用的回调设置。',
  'Saved — leave blank to keep': '已保存，留空即可保留',
  'Application credentials are configured once. Future visits only need a sign-in button.':
    '应用凭据只需配置一次，以后直接点击登录按钮即可。',
  'Your console is already set up': '控制台已完成设置',
  'Waiting for the server owner': '等待服务器所有者初始化',
  'Sign in with your linked account.': '使用已绑定的账号登录。',
  'Generate a one-time setup code on the server to get started.':
    '请先在服务器上生成一次性初始化码。',
  'Return to sign in': '返回登录',
  'Back to sign in': '返回登录',
  'Verify ownership, then bind your Google or GitHub account.':
    '验证服务器所有权，然后绑定 Google 或 GitHub 账号。',
  'Setup progress': '设置进度',
  'Verify ownership': '验证所有权',
  'Bind administrator': '绑定管理员',
  'Choose your sign-in methods': '选择登录方式',
  'Verify console ownership': '验证服务器所有权',
  'Enter the setup code shown in your server’s installation terminal.':
    '输入服务器安装终端显示的初始化码。',
  'Bootstrap secret': '初始化码',
  '64-character setup code': '64 位初始化码',
  'Verifying…': '正在验证…',
  'Verify & continue': '验证并继续',
  'Issuer URL': 'Issuer 地址',
  'Search…': '搜索…',
  Login: '登录',
  Setup: '初始化',
  WORKSPACE: '工作区',
  'Traffic unavailable': '流量数据不可用',
  'Loading traffic observations': '正在加载流量观测',
  'OBSERVE THE FLOW': '流量观测',
  'Network traffic': '网络流量',
  'Aggregate inbound and outbound observations. Every gap accounted for.':
    '汇总上下行观测，明确呈现采样缺失。',
  'Sample window': '采样范围',
  'Sampled inbound · {count}/{total} servers reporting': '下行采样 · {count}/{total} 台服务器上报',
  'Sampled outbound · {count}/{total} servers reporting': '上行采样 · {count}/{total} 台服务器上报',
  'Totals include measured intervals only. Missing samples and counter resets are unmeasured; these totals are not provider billing figures.':
    '总量仅包含有效采样区间。缺失采样和计数器重置区间不补值；此处总量不代表服务商计费数据。',
  'Traffic by server': '各服务器流量',
  'Rates use bits per second. Sampled totals use bytes.': '速率以 bit/s 表示，采样总量以字节表示。',
  'No traffic observations yet': '暂无流量观测',
  'Data will appear once authorized servers begin reporting samples.':
    '已授权服务器开始上报采样后，数据将显示在这里。',
  'Traffic observations': '流量观测',
  Server: '服务器',
  'Sampled in / out': '下行／上行采样总量',
  Coverage: '覆盖率',
  Quality: '质量',
  'No samples': '无采样',
  Partial: '部分采样',
  Observed: '已采集',
  'Open an agent’s details to explore its sampled resource and bandwidth utilization.':
    '打开服务器详情可查看资源与带宽使用率采样。',
  'Fleet overview': '服务器概览',
  'Fleet monitor': '服务器监控',
  'Fleet observability': '服务器监测',
  'Public summaries · Local time': '公开摘要 · 本地时间',
  'Skip to content': '跳至内容',
  'Log in': '登录',
  'Sign out': '退出登录',
  'Signing out…': '正在退出…',
  Refresh: '刷新',
  'Search agents': '搜索服务器',
  'Search agents…': '搜索服务器…',
  'Filter heartbeat status': '筛选服务器状态',
  'All Server': '全部服务器',
  Online: '在线',
  Stale: '过期',
  Offline: '离线',
  'Never seen': '未连接',
  '{count} agents': '{count} 台服务器',
  '{count} online': '{count} 台在线',
  '{count} stale, offline or unseen': '{count} 台过期、离线或未连接',
  'Updated {time} · every 30s': '更新于 {time} · 每 30 秒刷新',
  Previous: '上一页',
  Next: '下一页',
  'Page {page} of {pages}': '第 {page} / {pages} 页',
  'View {name}': '查看 {name}',
  Resources: '资源',
  Traffic: '流量',
  'System unavailable': '系统信息不可用',
  'Stale observations': '观测已过期',
  'This summary is stale. Each observation keeps its original collection time.':
    '摘要已过期，各项观测保留原始采集时间。',
  'No matching agents': '没有匹配的服务器',
  'Your fleet starts here': '尚无服务器',
  'Try another name or heartbeat filter.': '请尝试其他名称或状态。',
  'Public agent summaries will appear here when observations become available.':
    '采集到观测数据后，服务器摘要会显示在这里。',
  'Your console is ready': '控制台已就绪',
  'Fleet summaries will appear after your administrator enables the Console data service.':
    '管理员启用控制台数据服务后将显示服务器摘要。',
  'Loading agents': '正在加载服务器',
  'Loading console': '正在加载控制台',
  'Restoring your session': '正在恢复会话',
  'Loading utilization history': '正在加载历史使用率',
  CPU: 'CPU',
  Memory: '内存',
  Disk: '磁盘',
  Inbound: '下行',
  Outbound: '上行',
  Utilization: '使用率',
  Unavailable: '不可用',
  Unmeasured: '未测量',
  'Not observed': '未采集',
  'CPU utilization': 'CPU 使用率',
  'Memory utilization': '内存使用率',
  'Disk utilization': '磁盘使用率',
  'Inbound utilization': '下行使用率',
  'Outbound utilization': '上行使用率',
  'CPU utilization unavailable': 'CPU 使用率不可用',
  'Memory utilization unavailable': '内存使用率不可用',
  'Disk utilization unavailable': '磁盘使用率不可用',
  'Inbound utilization unavailable': '下行使用率不可用',
  'Outbound utilization unavailable': '上行使用率不可用',
  'Inbound bandwidth': '下行带宽',
  'Outbound bandwidth': '上行带宽',
  'Bandwidth % uses configured capacity; — means unavailable.':
    '带宽占用按配置容量计算；— 表示不可用。',
  'All agents': '返回概览',
  'Current utilization': '当前使用率',
  'Utilization history': '历史使用率',
  'History time range': '历史时间范围',
  '1 hour': '1 小时',
  '24 hours': '24 小时',
  '7 days': '7 天',
  'Sampling interval {seconds}s': '采样间隔 {seconds} 秒',
  Average: '平均',
  'Inspect {title} sample': '查看{title}采样点',
  '{title} history': '{title}历史',
  '{count} measured samples. Average {average}. Gaps are unmeasured. Use the sample slider or data table for exact values.':
    '{count} 个有效采样，平均 {average}。缺测区间不补值，可通过滑块或数据表查看详情。',
  '{valid} / {total} returned samples measured': '{valid} / {total} 个采样有效',
  'Gaps stay unmeasured': '缺测不补值',
  'No measured utilization': '暂无使用率采样',
  'Waiting for traffic samples and a configured bandwidth capacity.':
    '等待流量采样及带宽容量配置。',
  'This agent has no resource samples in the selected window.':
    '该服务器在所选时间范围内没有资源采样。',
  'View sample data': '查看采样数据',
  'Utilization samples': '使用率采样',
  'Close sample data': '关闭采样数据',
  Time: '时间',
  '{count} timestamps': '{count} 个时间点',
  'Timestamped utilization percentages. A dash means unmeasured, not zero.':
    '带时间戳的使用率。缺测不等于零。',
  'Summary unavailable': '摘要不可用',
  'The Console data service has not been enabled.': '控制台数据服务尚未启用。',
  'Agent unavailable': '服务器不可用',
  'This agent is not available.': '该服务器暂不可用。',
  'Return to overview': '返回概览',
  'These observations are stale. The charts retain their original sample times.':
    '观测数据已过期，图表保留原始采样时间。',
  'Operating system': '操作系统',
  Architecture: '架构',
  Kernel: '内核',
  Uptime: '运行时间',
  'Last heartbeat': '最近心跳',
  'Inbound capacity': '下行容量',
  'Outbound capacity': '上行容量',
  'Traffic totals and coverage': '流量与覆盖率',
  'System information': '系统信息',
  '{days}d {hours}h': '{days} 天 {hours} 小时',
  'We couldn’t complete that request': '请求未能完成',
  'Try again': '重试',
  'Something went wrong. Please try again.': '发生错误，请重试。',
  'Your session has expired. Sign in again to continue.': '会话已过期，请重新登录。',
  'Your account does not have access to this page.': '你的账户没有访问该页面的权限。',
  'The console is temporarily unavailable. Please try again.': '控制台暂时不可用，请重试。',
  'The Console API returned an unexpected response.': '控制台 API 返回了意外的响应。',
  'Unable to reach the console. Check your connection and try again.':
    '无法连接控制台，请检查网络后重试。',
  'The Console API is not available. Complete the server Console setup to connect.':
    '控制台 API 不可用，请完成服务端配置。',
  'The request could not be completed. Please try again.': '请求未能完成，请重试。',
  'Sign-in could not be verified. Start a new sign-in attempt.': '无法验证登录，请重新发起登录。',
  'The identity provider is unavailable. Please try again later.':
    '身份提供方暂不可用，请稍后再试。',
  'Your identity is verified. An administrator must approve access.':
    '身份已验证，等待管理员批准访问。',
  'This form has expired. Reload the page before trying again.': '表单已过期，请刷新页面后重试。',
  'Too many attempts. Please wait before trying again.': '尝试过于频繁，请稍后重试。',
  'Back to overview': '返回概览',
  'WELCOME TO ARGUS': '欢迎使用 ARGUS',
  'Sign in to your console': '登录控制台',
  'Use your organization’s identity provider to continue.': '通过组织的身份提供方继续。',
  'Single sign-on': '单点登录',
  'Organization identity provider': '组织身份提供方',
  'Organization SSO': '组织单点登录',
  'Continue with SSO': '通过 SSO 继续',
  'Connecting…': '正在连接…',
  'Verify identity & activate': '验证身份并激活',
  'Access is assigned by your console administrator.': '访问权限由控制台管理员分配。',
  'Protected by your organization’s sign-in policy': '受组织登录策略保护',
  'Secure access. Purposeful diagnostics.': '安全访问，专注诊断。',
  'Checking console': '正在检查控制台',
  'VISIBILITY, WITH BOUNDARIES': '清晰可见，权限有界',
  'Your fleet.': '你的服务器，',
  'A clearer picture.': '一目了然。',
  'A focused workspace for authorized Linux fleet diagnostics. From the first heartbeat to the latest observation.':
    '专注于已授权 Linux 服务器诊断，从首次心跳到最新观测。',
  'This console is ready for its first administrator.': '控制台已准备好绑定首位管理员。',
  'This console has not been initialized. Ask the server owner to issue a setup secret locally.':
    '控制台尚未初始化，请联系服务端所有者在本地签发初始化密钥。',
  'Set up your console': '初始化控制台',
  Overview: '概览',
  Fleet: '服务器',
  'Server detail': '服务器详情',
  Workspace: '工作区',
  'Session authenticated': '会话已认证',
  'Main navigation': '主导航',
  'Toggle navigation': '切换导航',
  'Close navigation': '关闭导航',
  Administrator: '管理员',
  Viewer: '访客',
  'Fleet workspace': '服务器工作区',
  'Authorized diagnostics': '已授权诊断',
  'Visibility you can trust': '可靠的监测',
  'Read-only observations.': '只读观测。',
  'Explicit access boundaries.': '明确的访问权限。',
  'Design reference': '设计参考',
  'Authorized fleet diagnostics': '已授权服务器诊断',
  'Heartbeat ≠ system health': '心跳不等于系统健康',
  'Page not found': '页面不存在',
  'This page is not available.': '该页面不可用。',
}

export function translate(
  language: Language,
  text: string,
  values: Record<string, string | number> = {},
) {
  const template = language === 'zh-CN' ? (chinese[text] ?? text) : text
  return template.replace(/\{(\w+)\}/g, (match, key: string) => String(values[key] ?? match))
}

// Only presentation preferences are stored. No identity, credentials or data.
export function readLanguage(): Language {
  try {
    return localStorage.getItem('argus.language') === 'zh-CN' ? 'zh-CN' : 'en'
  } catch {
    return 'en'
  }
}
