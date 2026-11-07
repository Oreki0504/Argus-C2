# Google / GitHub 直连登录

Console 首次设置可直接选择 **GitHub、Google，或同时启用两者**，不需要 Auth0。已有 Auth0 / 标准 OIDC 配置仍可使用，在页面的“其他登录服务”中设置。

自托管服务需要服务器所有者在所选平台登记一次 OAuth 应用。平台不会为任意新部署自动提供 Client ID / Secret；ARGUS 不内置共享应用密钥，也不把登录交给项目维护者的中转服务器。普通用户以后只需点击登录按钮。

## 首次绑定

1. 打开安装器打印的 `https://HOST:9443/setup`，输入安装终端显示的初始化码。
2. 选择 GitHub 和／或 Google。页面给出各自的**回调地址**，可以直接复制，并提供创建应用的入口。
3. 将应用的 Client ID、Client Secret 填入对应表单，点击“使用 GitHub / Google 绑定管理员”。页面保存配置并直接跳转到平台登录；验证成功后回到 ARGUS，完成首位 Admin 绑定。

初始化码用于证明你控制这台服务器。若过期，在服务器上签发一个新码，无需重装：

```sh
sudo /usr/local/libexec/argus-c2/server console-bootstrap issue -config /etc/argus-c2/server-local.json -out /etc/argus-c2/setup/bootstrap-new.token
sudo cat /etc/argus-c2/setup/bootstrap-new.token
```

输出文件必须尚不存在。再次签发时更换文件名。签发会使旧码和先前的初始化会话失效。

## GitHub 应用

打开 [GitHub → Settings → Developer settings → OAuth Apps → New OAuth App](https://github.com/settings/applications/new)。创建 **OAuth App**，填写：

| 项目 | 示例 |
| --- | --- |
| Application name | `ARGUS` |
| Homepage URL | `https://argus.example.com:9443` |
| Authorization callback URL | `https://argus.example.com:9443/v1/console/auth/callback/github` |

使用页面实际提供的地址，保留协议、端口和路径。生成 Client Secret，和 Client ID 一起填写到 ARGUS。此流程请求 `read:user` 读取账号资料，不需要仓库权限。

## Google 应用

打开 [Google Auth Platform → Clients](https://console.cloud.google.com/auth/clients)，选择自己的项目，完成应用名称和受众设置，然后创建类型为 **Web application** 的 OAuth Client。

将 ARGUS 页面提供的 Google 回调地址加入 **Authorized redirect URIs**：

```text
https://argus.example.com:9443/v1/console/auth/callback/google
```

填写 Client ID 和 Client Secret。使用 Google 接受的 HTTPS 域名；生产应用的回调不应使用裸公网 IP。若应用处于 Testing 状态，按 Google 的受众设置添加需要登录的测试用户。ARGUS 使用 Authorization Code + PKCE 和 `openid profile`。

## 登录和权限

配置两种方式后，登录页同时显示 Google 和 GitHub 按钮。只配置一种时只显示对应按钮。首次设置中已保存的同平台、同 Issuer、同 Client ID 凭据可以留空 Secret 继续使用；修改 Client ID 后需提供匹配的新 Secret。

两个平台的账号分别识别：Google 使用已验证 ID Token 的 `sub`；GitHub 使用服务器通过 `https://api.github.com/user` 获取的不可变数字 `id`。不会按邮箱或昵称自动合并，也不会将 GitHub 用户名变更视为新账号。用一种方式绑定首位 Admin 后，另一身份首次登录仍会进入待批准状态，可由现有 Admin 在“管理 → 用户权限”中批准并分配角色。

应用凭据只保存在服务器私有文件中，不回传 Secret，也不写入浏览器存储。登录令牌不传给前端。初始化成功后设置页关闭；已有部署更换认证配置需按 [本地恢复流程](console.md#local-recovery)进行，该流程会撤销会话并重新确定管理员，不能当作无影响的普通设置编辑。

旧的单 OIDC 凭据文件无需迁移即可读取。新多平台配置不需要数据库升级，但旧版本程序无法读取这种新配置格式；不要在采用新配置后直接降级程序。
