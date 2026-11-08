# Auth0 + GitHub / Google 登录配置

[Console 启动与恢复](console.md) · [实现状态](web-design.md)

Auth0 是可选接入方式。若只需要 Google / GitHub 登录，可以直接按[直连登录说明](console-login.zh-CN.md)配置，无需 Auth0。使用 **Auth0 Universal Login** 时，ARGUS 将登录请求交给 Auth0，用户在 Auth0 页面选择 GitHub 或 Google。

当前局域网 `http://192.168.9.40:5173` 是明确标记的模拟预览；真实登录需要启动独立 HTTPS Console。不要在模拟初始化页面填写真实 Client Secret。

## 准备信息

| 项目 | 用途 |
| --- | --- |
| Console HTTPS 地址，例如 `https://argus.example.com:9443` | 浏览器访问、精确 Origin 和回调地址 |
| 匹配域名的独立浏览器 TLS 证书／私钥 | Console HTTPS；不能复用 Fleet CA 签发的证书 |
| Auth0 Domain，例如 `YOUR-TENANT.auth0.com` | OIDC Issuer 为 `https://YOUR-TENANT.auth0.com/` |
| Auth0 Client ID | 标识 ARGUS Web Application |
| Auth0 Client Secret | 只在真实 Console 的账号设置中填写，保存为服务器私有文件 |

局域网客户端应能把 Console 域名解析到服务器地址。浏览器和 Argus 服务端都需要能访问 Auth0；用户浏览器还需要访问所选的 GitHub／Google 登录页。

## 在 Auth0 配置

1. 创建 **Regular Web Application**，例如命名为 ARGUS。
2. 将 Allowed Callback URLs 设置为下方 ARGUS 回调地址。协议、域名、端口和路径必须与 Console 参数完全一致。
3. 保持标准 OIDC Authorization Code 流程，ID Token 签名算法使用 **RS256**。
4. 在 Authentication → Social 中启用 Google 和 GitHub 连接，并把两条连接分配给 ARGUS Application。
5. 如需自行注册 Google／GitHub OAuth 应用，按照 Auth0 对应连接页面填写提供方凭据。Google／GitHub 的回调指向 **Auth0**，不是 ARGUS。

两个回调的方向不同：

| 登录流程 | 回调 |
| --- | --- |
| Auth0 → ARGUS | `https://argus.example.com:9443/v1/console/auth/callback` |
| Google／GitHub → Auth0 | 使用 Auth0 连接页面给出的 Callback URL，通常为 `https://YOUR-TENANT.auth0.com/login/callback` |

ARGUS 请求 `openid profile`。GitHub／Google 身份通过 Auth0 验证后，ARGUS 使用 Auth0 的 `issuer + subject` 作为身份主键。相同邮箱或名字不会自动合并账户、授予权限。直接 GitHub OAuth App 不能填作 OIDC Issuer。

参考：[Auth0 Application Settings](https://auth0.com/docs/get-started/applications/application-settings) · [Auth0 Social Identity Providers](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers)。

## 登录 ARGUS 后按需绑定

安装完成后，打开 `https://HOST:9443/login`，用安装器生成的管理员 Token 直接进入后台。首次使用不需要 Auth0。在服务器上读取 Token：

```sh
sudo cat /etc/argus-c2/setup/console.token
```

点击顶栏账号名称 → “账号与登录” → “配置第三方登录（可选）”，展开“其他登录服务（Auth0 / OIDC）”，填写凭据并保存。然后点击上方 SSO 绑定按钮，在 Auth0 授权后返回；它绑定到当前本地账号，不创建新的管理员。详见 [Token 与绑定说明](console-login.zh-CN.md)。

以下是从源码手动启动的步骤：

按 [Console 配置](console.md) 构建 UI 与 Go Binary；已有 Schema 102/103 先停服并执行有备份的显式升级。

```sh
bin/server run -config /private/argus/server.json \
  -console-listen 0.0.0.0:9443 \
  -console-origin https://argus.example.com:9443 \
  -console-cert /private/console/browser.pem \
  -console-key /private/console/browser-key.pem
```

另一个终端在服务器本机签发登录 Token：

```sh
bin/server console-token issue -config /private/argus/server.json \
  -out /private/argus/console.token
```

打开真实 Console 的 `/login`，输入 Token 后即可进入后台。随后按上述“账号与登录”流程配置并绑定 Auth0。

之后的新身份会进入“管理 → 用户与权限”的待批准列表。Admin 明确批准后才获得 User 或 Admin 权限。匿名监控入口仍按当前产品要求可访问，但不授予任何管理权限。

ARGUS 退出只撤销本地会话，不会退出 GitHub／Google／Auth0 的单点登录。身份提供方丢失或配置损坏时使用服务器本地恢复命令，步骤见 [Console 恢复](console.md#local-recovery)。
