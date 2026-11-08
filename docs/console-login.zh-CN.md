# Token 登录与可选 OAuth 绑定

安装 ARGUS 后，使用安装器生成的随机 **管理员 Token** 即可进入后台。首次登录不需要 Google/GitHub、不需要 Client ID 或 Client Secret，也没有 15 分钟内完成 OAuth 配置的要求。

## 首次进入后台

1. 打开安装器打印的 `https://HOST:9443/login`（`/setup` 也提供 Token 登录）。
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

1. 尚未配置平台时，可以继续使用 Token。管理员需要 OAuth 时，展开 **配置第三方登录（可选）**。
2. 配置 Google、GitHub 或两者，保存登录方式。Auth0 / 自定义 OIDC 也可选。
3. 在上方平台卡片点击 **绑定 Google / GitHub 账号**，跳转平台授权后返回，显示“已绑定”。
4. 退出后可使用已绑定平台登录。Token 和 OAuth 对应同一本地管理员账号，共用权限，不会另建一位管理员。

配置与绑定要求最近 10 分钟内登录；超过时用 Token 或已绑定平台重新登录即可。已归属其他本地账号的第三方身份不能直接转移；系统不根据邮箱或昵称合并账号。未绑定的第三方身份直接登录时仍进入待批准状态。绑定 OAuth 不会自动禁用管理员 Token。

自托管的 OAuth 平台配置仍需管理员登记一次应用，但它是后台可选功能，不再阻塞安装和首次使用。

### GitHub 应用

打开 [GitHub → OAuth Apps → New OAuth App](https://github.com/settings/applications/new)，创建 OAuth App：

| 项目 | 示例 |
| --- | --- |
| Application name | `ARGUS` |
| Homepage URL | `https://argus.example.com:9443` |
| Authorization callback URL | `https://argus.example.com:9443/v1/console/auth/callback/github` |

以页面提供的回调地址为准，保留协议、端口和路径。Client ID / Secret 只填入当前 Console 的后台。请求范围为 `read:user`，不需要仓库权限。

### Google 应用

打开 [Google Auth Platform → Clients](https://console.cloud.google.com/auth/clients)，完成应用受众配置，创建 **Web application**。将页面提供的回调 URL 加入 **Authorized redirect URIs**：

```text
https://argus.example.com:9443/v1/console/auth/callback/google
```

使用 Google 接受的 HTTPS 域名；Testing 状态按平台要求加入测试用户。ARGUS 使用 Authorization Code + PKCE 和 `openid profile`。

## 本地恢复

如果已经激活，但 Token 遗失或需要撤销原管理员访问，在服务器本机执行显式恢复：

```sh
sudo /usr/local/libexec/argus-c2/server console-token recover -confirm-recovery -config /etc/argus-c2/server-local.json -out /etc/argus-c2/setup/console-recovery.token
sudo cat /etc/argus-c2/setup/console-recovery.token
```

恢复会立即使旧 Token、浏览器会话和未完成的绑定失效；用新 Token 登录后，旧 Admin 账号被禁用，创建新的本地管理员。它不是无影响的普通 Token 轮换。其他用户和 Fleet 身份保留，新管理员可重新绑定尚未归属其他账号的第三方身份。

schema 104 不能直接运行旧二进制。迁移失败时原始备份仍保留；若已替换数据库但启动验收失败，安装器保留新程序和当前状态并停止服务，打印备份路径供恢复，不会自动回退数据库而丢掉可能已接收的任务。见 [安装和更新说明](server-installation.zh-CN.md)。
