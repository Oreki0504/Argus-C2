# Token 登录与可选 OAuth 绑定

安装 ARGUS 后，使用安装器生成的随机 **管理员 Token** 即可进入后台。首次登录不需要 Google/GitHub、不需要 Client ID 或 Client Secret，也没有 15 分钟内完成 OAuth 配置的要求。

## 首次进入后台

1. 打开安装器打印的 `https://HOST/login`（`/setup` 也提供 Token 登录）。
2. 输入安装终端显示的管理员 Token，即可进入管理页。重定向安装输出时不会打印 Token，需在服务器本机读取：

```sh
sudo cat /etc/argus-c2/setup/console.token
```

Token 是 32 字节安全随机数，以 64 位十六进制文本表示。文件仅允许 root 读取，数据库只保存摘要。它可以重复登录，退出登录或重启不会使 Token 过期；浏览器会话仍有 30 分钟空闲 / 8 小时绝对有效期。Token 不进入 URL、浏览器存储或审计日志。请把它作为管理员密码保管，它与 Fleet CLI 的 `server/admin.token` 不通用。

## 已安装的旧版本

新版 `install-server.py --update server` 会停服、备份状态和配置，在副本上完成 schema 102/103 → 104 迁移和检查后应用更新。已存在的用户、角色、OAuth 身份、Agent 和任务保留；已经激活的部署不会被自动改绑管理员。

尚未完成管理员初始化的部署，更新结束会签发新的登录 Token 并打印读取路径。若之前存在 Token 文件，新码写到新的文件中，以终端输出为准。旧初始化会话和旧码会失效。读取新 Token 后在 `/login` 登录即可。

手动签发（仅限尚未激活的 Console）：

```sh
sudo /usr/local/libexec/argus-c2/server console-token issue -config /etc/argus-c2/server-local.json -out /etc/argus-c2/setup/console-new.token
sudo cat /etc/argus-c2/setup/console-new.token
```

输出文件必须尚不存在。旧版本未使用且尚在有效期内的初始化码也可直接换取管理员登录，并成为该管理员的可重复登录 Token；过期或已消耗的旧码必须重新签发。

## 稍后绑定 Google / GitHub

点击顶栏账号图标或名称，进入 **账号与登录**：

1. 尚未配置平台时，可以继续使用 Token。管理员需要 OAuth 时，展开 **1. 配置本控制台的 OAuth 应用（管理员）**。
   每个平台的输入框旁提供 **如何创建 Google / GitHub OAuth 应用** 折叠教程，按当前界面语言显示。里面的主页与回调地址来自本机 Console 配置，可以直接照填；无需使用文档示例域名。
2. 配置 Google、GitHub 或两者，保存登录方式。Auth0 / 自定义 OIDC 也可选。
3. 在下方 **2. 关联你自己的账号** 中点击 **绑定 Google / GitHub 账号**，跳转平台授权后返回，显示“已绑定”。
4. 退出后可使用已绑定平台登录。Token 和 OAuth 对应同一本地管理员账号，共用权限，不会另建一位管理员。

配置与绑定要求最近 10 分钟内登录；超过时用 Token 或已绑定平台重新登录即可。已归属其他本地账号的第三方身份不能直接转移；系统不根据邮箱或昵称合并账号。未绑定的第三方身份直接登录时仍进入待批准状态。绑定 OAuth 不会自动禁用管理员 Token。

自托管的 OAuth 平台配置仍需管理员登记一次应用，但它是后台可选功能，不再阻塞安装和首次使用。

### GitHub 应用

打开 [GitHub → OAuth Apps → New OAuth App](https://github.com/settings/applications/new)，创建 OAuth App：

| 项目 | 示例 |
| --- | --- |
| Application name | `ARGUS` |
| Homepage URL | `https://argus.example.com` |
| Authorization callback URL | `https://argus.example.com/v1/console/auth/callback/github` |

以页面提供的回调地址为准，保留协议、端口和路径。点击 **Register application** 后复制 **Client ID**，再点击 **Generate a new client secret** 生成密钥。两项分别填到当前 Console 的对应输入框；不需要启用 Device Flow。请求范围为 `read:user`，不需要仓库权限。保存登录方式后，还需点击第二步账号卡片的“绑定 GitHub 账号”完成本人授权。

### Google 应用

打开 [Google Auth Platform → Clients](https://console.cloud.google.com/auth/clients)：

1. 选择或新建 Google Cloud 项目，在 **Branding** 填写应用名称、支持邮箱与开发者联系邮箱。
2. 个人 Google 账号在 **Audience** 选择 **External**；Testing 状态下，将用于登录的账号加入 **Test users**。
3. 进入 **Clients → Create client**，类型选择 **Web application**，名称填写 ARGUS。
4. 将 Console 页面提供的回调 URL 加入 **Authorized redirect URIs**，例如：

```text
https://argus.example.com/v1/console/auth/callback/google
```

5. 创建后将 **Client ID** 和 **Client Secret** 分别填到 ARGUS 对应输入框。当前为服务端登录流程，不必填写 Authorized JavaScript origins。
6. 保存登录方式，再点击第二步的“绑定 Google 账号”完成授权，确认显示“已绑定”。

使用 Google 接受的 HTTPS 域名；部署时不能直接使用公网 IP 作为回调主机。遇到 `redirect_uri_mismatch`，核对协议、域名、端口和路径是否与页面完整一致，新安装默认 443 不写端口，旧部署若仍用 9443 必须保留 `:9443`。ARGUS 使用 Authorization Code + PKCE 和 `openid profile`。参阅 [Google 官方配置说明](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred)。

### 绑定与应用配置的区别

第一步是给**这台 Console** 配置访问 Google/GitHub 的应用凭据；第二步是将**你本人的第三方身份**关联到当前 ARGUS 账号。只保存应用配置并不会完成绑定。先在当前账号完成关联，再退出尝试对应平台登录；不要用退出后首次登录来代替关联，这可能生成待批准的新身份。

### GitHub 授权后失败

preview.12 修复了 `oauth_issuer_mismatch` 的一个已复现原因：GitHub 在回调中返回的授权签发方是 `https://github.com/login/oauth`（见 [GitHub 官方元数据](https://github.com/login/oauth/.well-known/openid-configuration)），此前代码错误地用账号身份命名空间 `https://github.com` 比较。更新后无需重新创建 OAuth 应用、修改回调或重新填写密钥；重新发起关联即可。已有账号仍使用原来的身份命名空间，权限与关联关系不变。提供 `iss` 时仍要求唯一且严格匹配，不忽略错误值。

preview.10 起会区分应用凭据错误、回调不匹配、授权码被拒绝、用户资料失败与网络/上游不可用。服务端仅记录固定分类与 HTTP 状态码，不记录授权码、Token、Secret、响应正文或完整回调 URL。失败后在服务器本机检查：

```sh
sudo journalctl -u argus-c2-server -n 80 --no-pager
```

找到 `Console OAuth failed`，核对 `stage`（`callback`、`token_exchange` 或 `user_info`）、`reason`，以及存在时的 `category` 与 `upstream_status`。preview.11 进一步区分回调前置检查，页面与日志使用同一个固定原因码：

| reason | 含义与下一步 |
| --- | --- |
| `oauth_cookie_missing` | 浏览器未带回登录 Cookie；使用同一浏览器和控制台地址，允许 Cookie 后重新发起 |
| `oauth_flow_expired` | 授权已过期、被新请求替换或服务重启；在一个标签页重新发起 |
| `oauth_state_mismatch` | 回调不属于当前授权；关闭旧登录页，重新发起 |
| `oauth_callback_invalid` / `oauth_callback_mismatch` | 回调参数不完整或路径不属于所选平台；核对页面提供的完整回调地址 |
| `oauth_issuer_mismatch` / `oauth_provider_rejected` | 签发方不匹配，或平台未返回有效授权码 |
| `oauth_configuration_changed` | 授权期间修改了登录配置；重新发起 |
| `oauth_account_failed` | ARGUS 读取或保存账号状态失败；检查服务状态和存储 |

这些诊断不放宽 Cookie、state、PKCE 或账号归属校验。不要分享完整日志、回调 URL 或密钥；排查时只提供上述分类字段与页面提示。仅凭原来的通用提示无法确定 GitHub 失败根因。

## 禁用原始 Token 登录

1. 先成功关联 Google、GitHub 或其他 OAuth 身份。仅保存应用凭据不够。
2. 使用已关联的身份登录，或刚完成绑定后，在十分钟内进入 **账号与登录 → 管理员 Token 登录**。
3. 勾选确认并点击 **禁用 Token 登录**。

原 Token 永久失效，仅使用 Token 的其他会话立即结束；当前已验证 OAuth 的会话和后续 OAuth 登录保留。重启不会重新启用 Token。本机 `console.token` 文件可能仍存在，但其中旧值不能再登录。禁用后不允许移除当前管理员最后一个已关联平台；如果修改平台凭据，请重新验证可用性。

需要恢复时，只能由有服务器本机权限的所有者执行下面的显式恢复；它会替换管理员访问，不会重新启用原 Token。

## 本地恢复

如果已经激活，但 Token 遗失或需要撤销原管理员访问，在服务器本机执行显式恢复：

```sh
sudo /usr/local/libexec/argus-c2/server console-token recover -confirm-recovery -config /etc/argus-c2/server-local.json -out /etc/argus-c2/setup/console-recovery.token
sudo cat /etc/argus-c2/setup/console-recovery.token
```

恢复会立即使旧 Token、浏览器会话和未完成的绑定失效；用新 Token 登录后，旧 Admin 账号被禁用，创建新的本地管理员。它不是无影响的普通 Token 轮换。其他用户和 Fleet 身份保留，新管理员可重新绑定尚未归属其他账号的第三方身份。

schema 104 不能直接运行旧二进制。迁移失败时原始备份仍保留；若已替换数据库但启动验收失败，安装器保留新程序和当前状态并停止服务，打印备份路径供恢复，不会自动回退数据库而丢掉可能已接收的任务。见 [安装和更新说明](server-installation.zh-CN.md)。
