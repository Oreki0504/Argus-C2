# Server 一键安装与自动 HTTPS

[部署总览](deployment.md) · [Google / GitHub 登录](console-login.zh-CN.md) · [Agent 一键安装](agent-installation.zh-CN.md)

面向**尚未安装 Argus Server 的 Linux x86_64 / ARM64、systemd 主机**。建议 Ubuntu 24.04。目标机需要 Python 3.10+、OpenSSL、systemd-sysusers；不需要 Go、Node 或源码。Server 与 Agent 服务分开安装，Server 安装包包含已编译的前端和两种架构的 Agent 下载文件。

## 发布安装包

仓库维护者在构建机运行，输出目录必须尚不存在：

```sh
cd web
npm ci --ignore-scripts
cd ..
sh deploy/linux/build-server-bundles.sh /tmp/argus-server-release v0.1.0-preview.12
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

预览版本使用固定 tag 的下载链接。以下是 [v0.1.0-preview.12](https://github.com/Oreki0504/Argus-C2/releases/tag/v0.1.0-preview.12) 发布后的安装入口：在新服务器粘贴命令，即可下载安装脚本、启动交互并自动取得匹配的安装包。下载链接须等待对应 Release 工作流成功完成；仅有 commit 或 tag 不会产生安装包。

curl：

```sh
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py -o "$f" && sudo python3 "$f" )
```

GNU wget：

```sh
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; wget --https-only --max-redirect=5 -O "$f" https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py && sudo python3 "$f" )
```

脚本完整下载后才执行，终端标准输入保留给域名/IP 提问。脚本识别架构，从其绑定的 Release 获取 `SHA256SUMS` 和安装包，校验后才运行包内程序。用户不需要填写安装包 URL 或摘要。GitHub 的 HTTPS 资产重定向受支持，不允许降级到 HTTP 或带凭据跳转。

预发布版本不会成为 `latest`。发布首个稳定版本后，可将链接中的 `download/v0.1.0-preview.12` 换成 `latest/download`，取得最新稳定版；测试预览版时应保留固定版本链接。每个 Release 的说明会给出该版本的完整命令。`v0.1.0-preview.1` 在发布检查中失败，保留 tag 供追溯，没有公开安装包。

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

自托管整个发布目录时，可以改用 `--release-base https://downloads.example.com/argus/v0.1.0`，自动读取同目录清单并选择架构；或用 `--release v0.1.0-preview.12` 选择 GitHub 上已发布的版本。没有本地包、没有绑定版本的源码安装器会查询 GitHub 最新稳定 Release；没有 Release 时明确报错，不会回退到源码构建或未经校验的二进制。

## 发布 GitHub 下载入口

维护者提交代码后，明确创建并推送 `vX.Y.Z` 或 `vX.Y.Z-preview.N` 版本 tag，即触发 **Publish Server release**；也可以在 GitHub Actions 手动运行并输入已经存在的 tag。SSH 仓库写权限即可推送 tag，实际创建 Release 使用工作流的 `GITHUB_TOKEN`，无需本地个人 API Token。流程会校验 tag、构建两种架构安装包、运行 Go 和隔离安装测试，再将安装器、SHA256SUMS、amd64 包和 arm64 包上传到草稿 Release，全部上传成功后才公开。预发布 tag（含 `-`）标记为 prerelease，正式 tag 更新 latest；已有 Release 不覆盖，上传失败留下的草稿需维护者检查。

该流程需要仓库写权限。普通分支 commit/push 和前端 CI 不会自动发布版本，也不会擅自升级现有下载入口；推送版本 tag 表示明确发起发布。下载链接必须等这一发布流程成功完成后才能交给用户执行。

## 安装完成后的配置

安装器会：

- 初始化独立 Fleet CA、Server 证书、CLI 管理员 Token 和 SQLite 状态。
- 创建 `argus-server` 普通用户，安装加固的 systemd 服务并启动。
- 默认监听 `0.0.0.0:8443`（Fleet）和 `0.0.0.0:443`（Console），IPv6 地址使用 `[::]`；端口可用 `--fleet-port` / `--console-port` 调整。
- 自动发布 `/usr/local/share/argus-c2/agents` 中的两种架构 Agent，并配置实际 Fleet 地址。
- 生成可重复登录的随机管理员 Token，保存至 root 专用的 `/etc/argus-c2/setup/console.token`（0600）。交互终端会显示 Token；重定向输出时只打印读取命令。

安装成功后，打开打印出的 `https://HOST/login`，输入管理员 Token 即可进入后台，无需先配置 OAuth。在服务器本机读取：

```sh
sudo cat /etc/argus-c2/setup/console.token
```

Token 可用于后续登录，不会在 15 分钟后过期；退出或重启不会使它失效。不要将它与 CLI 的 `server/admin.token` 混用。需要 Google/GitHub 时，在后台顶栏点击账号进入“账号与登录”，展开可选平台配置并绑定当前账号；见 [Token 登录与 OAuth 绑定](console-login.zh-CN.md)。

旧版未完成初始化的部署，在新版更新结束后会获得新的登录 Token；以更新终端打印的路径为准。手动签发使用 `server console-token issue -config /etc/argus-c2/server-local.json -out NEW_PRIVATE_FILE`，输出文件必须尚不存在。已经激活的部署使用显式 `console-token recover -confirm-recovery` 才能重新建立管理员，该操作撤销旧凭据并在新 Token 登录时禁用原 Admin。

服务使用 `/etc/argus-c2/server.json` 和 systemd `LoadCredential`；`server-local.json` 是 root-only 的运维配置，引用源凭据与同一个状态目录，不应另开第二个 Server 进程。CLI 管理员 Token 位于 `/etc/argus-c2/server/admin.token`，不是 Console 登录凭据。

## 443 与既有 9443 部署

preview.10 起新安装默认 Console 使用 HTTPS 标准端口 443，网址无需写端口。低端口通过 systemd 的 `CAP_NET_BIND_SERVICE` 授予服务，仍以 `argus-server` 普通账户运行；Fleet 继续使用 8443。如果 443 已被其他服务占用，安装器会报端口冲突，可指定 `--console-port 9443`。

**更新和恢复保留既有端口**，不会把已在运行的 9443 自动迁移到 443。迁移会改变 OAuth 的精确回调地址，需要一起调整：

1. 先确认 443 空闲、云平台和主机允许访问；保留当前可用的管理员 Token。
2. 在 Google/GitHub 应用登记新的无 `:9443` 回调地址，路径仍是各自的 `/v1/console/auth/callback/google` 或 `/v1/console/auth/callback/github`。
3. 先备份，再用 `sudoedit /etc/systemd/system/argus-c2-server.service.d/console.conf` 编辑安装器的服务配置。保留完整 `ExecStart` 和 `LoadCredential`，只把 `-console-listen` 改为 `0.0.0.0:443`（IPv6 为 `[::]:443`）、`-console-origin` 改为 `https://实际域名`，其他参数保持原样。在该文件的 `[Service]` 下添加：

   ```ini
   CapabilityBoundingSet=CAP_NET_BIND_SERVICE
   AmbientCapabilities=CAP_NET_BIND_SERVICE
   ```

4. 执行 `sudo systemctl daemon-reload` 和 `sudo systemctl restart argus-c2-server`，打开新地址，用 Token 登录并核对“账号与登录”显示的回调。证书仍覆盖同一域名，不需重新签发。重启会清除旧浏览器会话。

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

若 Certbot 签发失败，查看具体日志文件（`logs` 本身是目录）：

```sh
sudo tail -n 80 /var/lib/argus-certbot/logs/letsencrypt.log
```

`Type: connection` / `Timeout during connect` 表示证书机构无法连接日志中列出的公网验证地址。安装器的端口预检只证明本机端口可以绑定，不能证明公网可达。先确认日志中的 IP 是目标 VM 的公网 IP，再检查云网络、本机防火墙和 NAT；更换为 IP 证书仍需公网 TCP 80。Azure 中若子网和网卡都绑定了 NSG，两处规则都必须允许入站流量，应检查目标网卡的**有效安全规则**及公网 IP 的实际绑定；只新增一条 Allow 规则不能证明整条流量路径可达。

Azure 的普通实例元数据 `publicIpAddress` 返回空值时，不能直接判断 VM 没有公网地址。对于 Standard SKU，按[微软官方说明](https://learn.microsoft.com/en-us/azure/load-balancer/howto-load-balancer-imds?tabs=linux)在 VM 内查询：

```sh
curl -q --noproxy '*' --max-time 5 -H Metadata:true 'http://169.254.169.254/metadata/loadbalancer?api-version=2020-10-01'
```

区分 `publicIpAddresses`、`inboundRules` 和 `outboundRules`；仅出现在出站规则里的地址不能据此作为服务入站地址。经负载均衡器访问时，还需核对入站端口、后端端口及后端健康状态。

排查时应在验证服务仍运行期间，对照本机访问与外部访问结果及服务日志。Certbot 验证失败后会关闭临时监听，结束后直接测 80 端口无法区分“无监听”与“流量被阻断”。日志中的 `:::80` 可能是支持 IPv4 的双栈监听，不能仅凭这一行判定 IPv4 未监听。确认原因前不要反复向生产 ACME 请求证书；网络验证恢复后再执行首次安装命令，不带 `--update server`。

旧版 `v0.1.0-preview.2` 在 `/var/log` 允许日志组写入的系统上可能报 `Installation parent must be root-owned and not writable by others: /var/log`。这是安装器路径选择的问题，不应通过 `chmod /var/log` 修复。此时流程尚未执行 Server 初始化，因而还没有 Console 初始化码。改用本页新版命令重试即可复用已安装的 Certbot 和 ACME 准备目录；无需删除这些目录或修改系统日志权限。

隔离测试覆盖可组写的系统日志目录、早期失败重试、真实包初始化和终端凭据显示。CI 还会在一次性 VM 上执行完整安装器、启动真实 systemd 服务，并通过受信任的 HTTPS 验证 `/setup`、Token 登录及重新签发流程。ACME 请求由模拟命令验证，不会在测试中申请公开证书或消耗 Let’s Encrypt 配额；真实域名/IP 的外网验证仍需在实际部署时验收。

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
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py -o "$f" && sudo python3 "$f" --update server )

# Agent：在每台 Agent 主机单独执行，只替换本机 Agent 程序
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py -o "$f" && sudo python3 "$f" --update agent )
```

已取得安装包目录时可运行 `sudo python3 install-server.py --update server --bundle /path/argus-server-linux-amd64.tar.gz`。同一脚本支持 `--release TAG`、`--release-base URL` 和原有 SHA-256 校验；默认使用下载脚本绑定的版本。更新时不重新询问域名、邮箱或证书，`--host` 等首次安装参数不适用。

更新顺序：先下载并校验包，再停止对应服务、锁定状态、备份旧程序及配置/身份/数据库，在数据库副本上运行新版本的兼容性检查，随后原子替换各程序并恢复服务。原先停止的服务仍保持停止。Server 更新不会启动或更新同机 Agent，也不会远程批量更新其他主机。

相同 schema 的更新失败时，自动恢复旧程序和此前的运行状态。Server schema 102/103 → 104 会在副本上显式迁移并检查，再应用到已停服、锁定的真实状态；迁移前备份保留。若已开始替换 schema 但启动验收失败，保留新程序及当前数据库并停止服务，打印恢复路径；**不会自动回退数据库快照**，以免丢失可能已接收的结果。其他 schema 变更按[运维文档](operations.md#database-compatibility-and-upgrades)处理。配置、证书、Auth0、管理员、Agent 身份和策略均保留，systemd unit/drop-in 及续期计划不改写。Server 重启会让现有浏览器会话失效，需要重新登录。

每次更新在 `/var/lib/argus-c2-updates/server-*` 或 `agent-*` 留下 root 私有备份，包含 `update.json`、旧程序、`state` 和 `configuration`。它包含凭据，应按私有备份保管，并由管理员在验收后管理保留时间。确保磁盘容纳完整状态快照；脚本不会自动删除旧备份。

从 preview.8 起，更新失败还会打印失败阶段、命令名称及退出码，并在该次备份中保存 `failure.json`，包含限长的原始错误输出；恢复旧服务也失败时另存 `recovery-failure.json`。这些文件仅 root 可读，可能包含凭据，排查时先在本机查看，不要原样公开。旧版只有“已回滚”的提示不足以确定失败原因；卸载不是修复更新所必需的步骤。

自动更新支持项目标准路径和专用 systemd 账户；自定义路径、命令及不支持的 schema 使用手动流程。断电、强制结束进程或恢复失败时，查看 `update.json` 的阶段和原程序位置，保留现有数据库，停止对应服务后按记录恢复程序及权限，再检查启动。不要用旧数据库覆盖现有状态来强行恢复。服务存活检查不等于远端连通验收；Agent 更新后还应在 Console 确认心跳和结果上报。

## 卸载 Server 或 Agent

preview.8 起，同一个 `install-server.py` 同时包含安装、更新和卸载。卸载不下载安装包，也不申请证书；支持只安装了一部分的主机及重复执行。先选语言，再显示处理范围并确认。

下载新版脚本并卸载 Server（**默认保留数据**）：

```bash
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py -o "$f" && sudo python3 "$f" --uninstall server )
```

卸载 Agent 时，将末尾的 `server` 改成 `agent`，在 Agent 所在主机执行。已安装新版 Server 的主机也可以离线使用本地维护脚本：

```bash
# 只查看计划，不修改文件或服务
sudo python3 /usr/local/libexec/argus-c2/install-server.py --uninstall server --dry-run

# 停止、禁用并移除程序及服务定义，保留配置、数据库、证书、Token 和账户
sudo python3 /usr/local/libexec/argus-c2/install-server.py --uninstall server

# 删除当前 Server 部署数据和专用账户，以便全新安装
sudo python3 /usr/local/libexec/argus-c2/install-server.py --uninstall server --purge
```

`--purge` 会删除所选组件的标准配置目录、状态数据库、证书、Token 和专用系统账户；Server 还会删除其独立 ACME 账户/证书目录及日志。交互时必须输入 `purge server` 或 `purge agent`。自动化可显式使用 `--yes`；没有终端且未指定 `--yes` 时拒绝卸载。清除 Server 会丢失现有 Fleet 身份，新装后原 Agent 需要重新注册；清除 Agent 后也需要新的注册命令。请先自行备份要保留的数据。

卸载 Server 会先关闭其续期任务，不影响同机 Agent 的程序、配置、账户和服务。卸载 Agent 不修改 Server，也不会自动撤销服务端的注册身份；退役主机时，请在 Console 管理页禁用对应 Agent。

两种模式均保留历史 `/var/lib/argus-c2-updates` 和 `/var/lib/argus-c2-uninstall` 备份、本地维护脚本、Certbot 安装环境及共享父目录。`--purge` 清除的是**当前部署**，并不擦除备份中的历史凭据。验收后由管理员单独管理这些备份；脚本不卸载系统 Python、Certbot 软件包或其他站点的证书。

每次卸载打印 `/var/lib/argus-c2-uninstall/<component>-...` 私有记录目录。`uninstall.json` 记录范围及完成状态，`programs.tar` 保存移除前的程序和服务定义。

### 保留数据卸载后恢复

preview.9 起，重新运行安装器会在域名、邮箱、条款提示**之前**识别保留的部署，交互询问是否恢复。也可以明确执行：

```bash
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.12/install-server.py -o "$f" && sudo python3 "$f" --restore server )
```

Agent 使用 `--restore agent`。本机已保存新版维护脚本时，也可使用 `sudo python3 /usr/local/libexec/argus-c2/install-server.py --restore server`。

恢复读取最近一次成功的保留数据卸载归档，在状态副本上检查旧程序与当前数据库是否兼容，再恢复程序和服务定义并启动原部署。不下载程序、不迁移数据库、不重新申请证书；原域名、端口、管理员账号、Token 和 Agent 注册身份继续使用。Let’s Encrypt 续期任务同时恢复；无需重新填写邮箱或同意证书服务条款。

**恢复的是卸载前的版本。** 恢复成功后，再执行上方 `--update server` 安装新版功能。不能把恢复归档当作数据库降级手段；数据已清除、账户丢失、归档不完整、程序冲突或数据库不兼容时，脚本拒绝自动恢复，并保留现有状态供手动处理。恢复启动失败时在归档目录写入私有 `restore-failure-*.json`。

`Existing Server deployment retained` 指保留了整套部署身份，并不表示“存在证书所以不能安装”。仅有之前证书申请留下的 ACME 目录，不会阻止首次安装。若已安装且仍正常运行，用 `--update server`；如果明确需要全新身份，则先显式 `--purge`，再首次安装。

若卸载中断，请保留已打印的记录，检查 `failure.json` 后重试；脚本不会悄悄改成新安装。历史程序归档只能用于对应主机和兼容数据库；清除数据后，恢复程序不能找回数据库或身份。
