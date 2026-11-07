# Server 一键安装与自动 HTTPS

[部署总览](deployment.md) · [Console / Auth0](console-auth0.zh-CN.md) · [Agent 一键安装](agent-installation.zh-CN.md)

面向**尚未安装 Argus Server 的 Linux x86_64 / ARM64、systemd 主机**。建议 Ubuntu 24.04。目标机需要 Python 3.10+、OpenSSL、systemd-sysusers；不需要 Go、Node 或源码。Server 与 Agent 服务分开安装，Server 安装包包含已编译的前端和两种架构的 Agent 下载文件。

## 发布安装包

仓库维护者在构建机运行，输出目录必须尚不存在：

```sh
cd web
npm ci --ignore-scripts
cd ..
sh deploy/linux/build-server-bundles.sh /tmp/argus-server-release v0.1.0-preview.5
```

生成：

```text
install-server.py
argus-server-linux-amd64.tar.gz
argus-server-linux-arm64.tar.gz
SHA256SUMS
```

构建需要项目规定的 Go 和 Node 版本。第二个参数是计划发布的版本 tag，构建器将它写入安装脚本，保证脚本与安装包使用同一个版本；省略 tag 时保留本地目录安装及最新稳定 Release 查询能力。可以将目录放在自己的 HTTPS 下载站、GitHub Release，或通过可信渠道复制到目标主机。普通 CI 会生成 `server-bundles` artifact；发布由明确推送版本 tag 或手动运行工作流触发，见下文。目标服务器首次安装不依赖一个已经运行的 Argus Server。

安装脚本与 SHA256SUMS 应从可信来源一起取得。SHA-256 检测损坏和替换，不替代发布者身份认证。仅传输目标架构的 Server 压缩包即可，其中已附带两种架构的 Agent。

## 一条命令启动交互安装

预览版本使用固定 tag 的下载链接。以下是 [v0.1.0-preview.5](https://github.com/Oreki0504/Argus-C2/releases/tag/v0.1.0-preview.5) 发布后的安装入口：在新服务器粘贴命令，即可下载安装脚本、启动交互并自动取得匹配的安装包。下载链接须等待对应 Release 工作流成功完成；仅有 commit 或 tag 不会产生安装包。

curl：

```sh
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.5/install-server.py -o "$f" && sudo python3 "$f" )
```

GNU wget：

```sh
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; wget --https-only --max-redirect=5 -O "$f" https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.5/install-server.py && sudo python3 "$f" )
```

脚本完整下载后才执行，终端标准输入保留给域名/IP 提问。脚本识别架构，从其绑定的 Release 获取 `SHA256SUMS` 和安装包，校验后才运行包内程序。用户不需要填写安装包 URL 或摘要。GitHub 的 HTTPS 资产重定向受支持，不允许降级到 HTTP 或带凭据跳转。

预发布版本不会成为 `latest`。发布首个稳定版本后，可将链接中的 `download/v0.1.0-preview.5` 换成 `latest/download`，取得最新稳定版；测试预览版时应保留固定版本链接。每个 Release 的说明会给出该版本的完整命令。`v0.1.0-preview.1` 在发布检查中失败，保留 tag 供追溯，没有公开安装包。

已有本地安装目录时，也可以继续执行：

```sh
sudo python3 install-server.py
```

安装器自动识别当前架构，然后询问：

1. 第一条提示选择 **中文 / English**，之后的提问和完成指引使用所选语言。可传 `--language zh-CN` 或 `--language en` 跳过语言选择；非交互默认英文。
2. 使用域名还是 IP 地址，并输入具体地址。
3. 公开证书申请需要 ACME 账户邮箱，并明确同意 Let’s Encrypt 条款。

**域名模式**：域名 A/AAAA 必须指向这台主机。通过 Certbot standalone HTTP-01 自动申请 Let’s Encrypt 证书。

**公网 IP 模式**：使用 Certbot `--ip-address` 和 `--required-profile shortlived`，申请有效期约 160 小时的 IP 证书。不能退回一个不支持 IP 的证书 profile。

**私有局域网 IP**：如 `192.168.x.x`，Let’s Encrypt 无法为其签发公开可信证书。安装器会解释原因，并询问是否创建独立 Console 本地 CA。该 CA 与 Fleet CA 完全分开；需要在浏览器和 Agent 主机系统信任库中安装 `/etc/argus-c2/console/ca.pem`。本地证书不走 ACME 自动续期，叶证书有效期 90 天、CA 有效期 365 天，到期前应按手动证书流程更换。

公开签发和后续续期都要求：公网 TCP **80** 能到达此主机，且没有其他进程占用 80 端口。NAT、云安全组和防火墙需由管理员配置。安装器不会停止已有 Nginx/Apache，也不会自动修改防火墙。如果已有 Web 服务，应通过自己的 ACME/DNS-01 流程取得证书，使用 `--tls existing` 导入。

## 无交互参数

域名证书：

```sh
sudo python3 install-server.py \
  --host argus.example.com \
  --tls letsencrypt --email admin@example.com --agree-tos
```

公网 IP：将 `--host` 替换为实际公网 IP，其他参数相同。不能用文档保留 IP 或 `0.0.0.0` 代替实际地址。

局域网：

```sh
sudo python3 install-server.py --host 192.168.9.40 --tls local-ca
```

已有证书：

```sh
sudo python3 install-server.py --host argus.example.com --tls existing \
  --console-cert /private/fullchain.pem --console-key /private/privkey.pem
```

已有证书会复制到 Argus 管理的文件中，必须包含正确 SAN、与私钥匹配且处于有效期内；导入模式下原证书的续期不会自动同步到 Argus，应由原证书管理流程更新复制件并重启服务。

如果安装包放在独立 HTTPS 下载站，可以让安装器下载并校验：

```sh
sudo python3 install-server.py \
  --bundle-url https://downloads.example.com/argus-server-linux-amd64.tar.gz \
  --sha256 ACTUAL_TRUSTED_ARCHIVE_SHA256
```

以上下载地址是部署示例。自定义单个包的 `--bundle-url` 必须显式传入可信 SHA-256，支持最多五次 HTTPS 重定向；本地包使用 `--bundle /path/archive.tar.gz` 并默认读取同目录 `SHA256SUMS`。完整下载及校验通过后才会执行包内程序，解包不接受目录穿越、链接、重复或意外文件。

自托管整个发布目录时，可以改用 `--release-base https://downloads.example.com/argus/v0.1.0`，自动读取同目录清单并选择架构；或用 `--release v0.1.0-preview.5` 选择 GitHub 上已发布的版本。没有本地包、没有绑定版本的源码安装器会查询 GitHub 最新稳定 Release；没有 Release 时明确报错，不会回退到源码构建或未经校验的二进制。

## 发布 GitHub 下载入口

维护者提交代码后，明确创建并推送 `vX.Y.Z` 或 `vX.Y.Z-preview.N` 版本 tag，即触发 **Publish Server release**；也可以在 GitHub Actions 手动运行并输入已经存在的 tag。SSH 仓库写权限即可推送 tag，实际创建 Release 使用工作流的 `GITHUB_TOKEN`，无需本地个人 API Token。流程会校验 tag、构建两种架构安装包、运行 Go 和隔离安装测试，再将安装器、SHA256SUMS、amd64 包和 arm64 包上传到草稿 Release，全部上传成功后才公开。预发布 tag（含 `-`）标记为 prerelease，正式 tag 更新 latest；已有 Release 不覆盖，上传失败留下的草稿需维护者检查。

该流程需要仓库写权限。普通分支 commit/push 和前端 CI 不会自动发布版本，也不会擅自升级现有下载入口；推送版本 tag 表示明确发起发布。下载链接必须等这一发布流程成功完成后才能交给用户执行。

## 安装完成后的配置

安装器会：

- 初始化独立 Fleet CA、Server 证书、CLI 管理员 Token 和 SQLite 状态。
- 创建 `argus-server` 普通用户，安装加固的 systemd 服务并启动。
- 默认监听 `0.0.0.0:8443`（Fleet）和 `0.0.0.0:9443`（Console），IPv6 地址使用 `[::]`；端口可用 `--fleet-port` / `--console-port` 调整。
- 自动发布 `/usr/local/share/argus-c2/agents` 中的两种架构 Agent，并配置实际 Fleet 地址。
- 生成 15 分钟有效的一次性初始化码，保存至 root 专用的 `/etc/argus-c2/setup/bootstrap.token`（0600）。交互终端会显示该码；重定向输出时只打印读取命令，不把凭据写入日志。

安装成功后，打开打印出的 `https://HOST:9443/setup`，输入终端显示的一次性初始化码，也可在服务器本机读取：

```sh
sudo cat /etc/argus-c2/setup/bootstrap.token
```

然后填写 Auth0/OIDC 设置，通过 GitHub/Google 登录并绑定首位管理员。**初始化码只证明你有这台服务器的本地管理权限，不是日常登录密码，也不是 CLI 的 `admin.token`；TLS 私钥不能用来登录 Console。**

**自动 HTTPS 不会替你创建 Auth0 应用**。尚未准备 Auth0 时，可先完成应用配置，再重新签发初始化码；不能仅凭初始化码进入日常管理页。IP 证书能解决 TLS 信任，但 OIDC 提供方是否接受 IP 回调仍需在其应用设置中确认；正式社交登录建议使用域名。

初始化凭据过期后，用新文件重新签发：

```sh
sudo /usr/local/libexec/argus-c2/server console-bootstrap issue \
  -config /etc/argus-c2/server-local.json \
  -out /etc/argus-c2/setup/bootstrap-new.token
sudo cat /etc/argus-c2/setup/bootstrap-new.token
```

`-out` 必须指定尚不存在的新文件；再次签发时换一个文件名。旧码和此前的初始化会话会失效。无需重装或重启服务。

服务使用 `/etc/argus-c2/server.json` 和 systemd `LoadCredential`；`server-local.json` 是 root-only 的运维配置，引用源凭据与同一个状态目录，不应另开第二个 Server 进程。CLI 管理员 Token 位于 `/etc/argus-c2/server/admin.token`，不是 Console 登录凭据。

## 证书自动续期

公开证书使用 Certbot **5.3 或更新版本**。安装器优先使用已有的兼容 Certbot，也可通过 `--certbot /path/to/certbot` 指定。若尚未安装，在 Debian/Ubuntu 上自动安装 `python3-venv`，并在 `/opt/argus-certbot` 中从 PyPI 安装 `certbot>=5.3,<6`；不会替换系统 Python。其他发行版应先按其官方方法安装新版 Certbot。管理员仍需维护 Certbot 工具自身的安全更新。

Argus 使用独立的 `/etc/argus-c2/acme`、`/var/lib/argus-certbot` 和 `/var/lib/argus-certbot/logs`（均为 root 私有目录），不会接管已有 Certbot 证书。日志不依赖 `/var/log` 的组权限，也不修改系统日志目录权限。`argus-console-renew.timer` 每 6 小时运行一次，附加不超过 5 分钟的随机延迟；Certbot 根据到期时间和 ACME Renewal Information 决定是否续签，不会每次强制签发。

成功续期后，部署钩子验证主机名、有效期和密钥匹配，再更新副本并重启 Server，使 systemd 重新加载私钥。重启失败时恢复之前的证书，并尝试恢复服务。每次定时任务结束还会检查证书副本是否同步，避免“签发成功但部署失败”一直拖到下一轮签发才重试。证书未变化时不重启。

**重启会短暂中断连接，清除浏览器会话和未领取的安装链接**；Agent 按现有连接机制重试，用户需重新登录。检查续期状态：

```sh
sudo systemctl list-timers argus-console-renew.timer
sudo journalctl -u argus-console-renew.service -n 50 --no-pager
sudo journalctl -u argus-c2-server.service -n 50 --no-pager
```

参考：[Let’s Encrypt 证书 profiles（IP、160 小时）](https://letsencrypt.org/docs/profiles/)、[Certbot 5.3 IP 支持和续期说明](https://github.com/certbot/certbot/blob/v5.4.0/certbot/CHANGELOG.md)。

## 重复执行和故障恢复

普通安装模式遇到已有 Server 用户、状态、配置、程序或 unit 时仍拒绝覆盖。更新已有服务使用下方显式更新模式；不会通过重新安装来清空身份。

缺包、校验失败、端口占用和输入错误会在应用安装前中止。自动申请证书可能已经创建独立 Certbot 环境、ACME 账户或证书；这些内容保留供诊断及重试，不应为重试随意删除 ACME 账户。若已写入 Server 状态后启动失败，保留该状态并检查日志及配置，按[手动部署](deployment.md)完成恢复；不会自动清理或重新初始化。

旧版 `v0.1.0-preview.2` 在 `/var/log` 允许日志组写入的系统上可能报 `Installation parent must be root-owned and not writable by others: /var/log`。这是安装器路径选择的问题，不应通过 `chmod /var/log` 修复。此时流程尚未执行 Server 初始化，因而还没有 Console 初始化码。改用本页新版命令重试即可复用已安装的 Certbot 和 ACME 准备目录；无需删除这些目录或修改系统日志权限。

隔离测试覆盖可组写的系统日志目录、早期失败重试、真实包初始化和终端凭据显示。CI 还会在一次性 VM 上执行完整安装器、启动真实 systemd 服务，并通过受信任的 HTTPS 验证 `/setup`、初始化码及重新签发流程。ACME 请求由模拟命令验证，不会在测试中申请公开证书或消耗 Let’s Encrypt 配额；真实域名/IP 的外网验证仍需在实际部署时验收。

## 更新 Server 或 Agent

`v0.1.0-preview.4` 起，同一个下载脚本支持显式更新。**更新要求这台主机已完成对应组件的安装**；证书准备阶段失败不算已安装。请先按当前状态选择入口：

| 当前状态 | 应执行的操作 |
| --- | --- |
| 新主机，或上次只准备了 Certbot/ACME 就失败 | 使用上方 Server 安装命令，不加 `--update server`；已有 Certbot/ACME 准备可复用 |
| 标准安装已完成 | 使用下方 `--update server` 或 `--update agent` |
| 已有配置、身份、数据库或服务，但服务账户/必要文件缺失 | 保留原数据，按[手动部署](deployment.md)修复安装后再更新 |

`v0.1.0-preview.5` 修复了缺少 `argus-server` / `argus-agent` 账户时直接抛出 `KeyError: getpwnam()` 的问题。检查发生在下载包和停止服务之前；新版会区分“尚未安装”和“安装不完整”，不自动创建账户、重置身份或转为全新安装。尚未安装 Agent 时应使用 Console 生成的 Agent 安装命令，不能仅删掉 `--update agent`（这个脚本默认安装 Server）。

旧版已安装主机也可下载新版脚本更新，无需重新安装、重新申请证书或重新注册 Agent。在目标主机执行：

```sh
# Server：更新服务端、内嵌前端、CLI 和供新 Agent 下载的二进制
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.5/install-server.py -o "$f" && sudo python3 "$f" --update server )

# Agent：在每台 Agent 主机单独执行，只替换本机 Agent 程序
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.5/install-server.py -o "$f" && sudo python3 "$f" --update agent )
```

已取得安装包目录时可运行 `sudo python3 install-server.py --update server --bundle /path/argus-server-linux-amd64.tar.gz`。同一脚本支持 `--release TAG`、`--release-base URL` 和原有 SHA-256 校验；默认使用下载脚本绑定的版本。更新时不重新询问域名、邮箱或证书，`--host` 等首次安装参数不适用。

更新顺序：先下载并校验包，再停止对应服务、锁定状态、备份旧程序及配置/身份/数据库，在数据库副本上运行新版本的兼容性检查，随后原子替换各程序并恢复服务。原先停止的服务仍保持停止。Server 更新不会启动或更新同机 Agent，也不会远程批量更新其他主机。

运行失败或启动检查失败时，自动恢复旧程序和此前的服务运行状态。**不会自动回退数据库快照**，以免丢掉新接收的结果和审计；当前更新仅允许相同 schema 的兼容版本，数据库迁移仍按[运维文档](operations.md#database-compatibility-and-upgrades)显式执行。配置、证书、Auth0、管理员、Agent 身份和策略均保留，systemd unit/drop-in 及续期计划不改写。Server 重启会让现有浏览器会话失效，需要重新登录。

每次更新在 `/var/lib/argus-c2-updates/server-*` 或 `agent-*` 留下 root 私有备份，包含 `update.json`、旧程序、`state` 和 `configuration`。它包含凭据，应按私有备份保管，并由管理员在验收后管理保留时间。确保磁盘容纳完整状态快照；脚本不会自动删除旧备份。

自动更新支持项目标准路径和专用 systemd 账户；自定义路径、命令、旧 schema 使用手动流程。断电、强制结束进程或恢复失败时，查看 `update.json` 的阶段和原程序位置，保留现有数据库，停止对应服务后按记录恢复程序及权限，再检查启动。不要用旧数据库覆盖现有状态来强行恢复。服务存活检查不等于远端连通验收；Agent 更新后还应在 Console 确认心跳和结果上报。
