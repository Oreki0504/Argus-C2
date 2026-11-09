# 从 Console 一条命令安装 Agent

[Console 配置](console.md) · [手动部署](deployment.md) · [API](console-api.md)

管理员在 **管理 → Agent → 添加 Agent → 安装命令** 中生成命令，选择 curl 或 wget，复制到一台新 Linux 主机执行。命令会完整下载安装脚本，再通过 root 或 sudo 执行；无需手工填写 Fleet 地址、CA 或注册 Token。默认有效期 15 分钟，可以设置为 1–60 分钟。关闭对话框后，页面不再保留命令。

## 管理服务器准备

先完成真实 Console 的 HTTPS，并使用安装器生成的管理员 Token 登录；OAuth 可选。局域网 HTTP 开发预览只展示交互，生成的是 `.invalid` 域名示例，不能安装 Agent。

在仓库根目录构建安装包，输出目录必须尚不存在：

```sh
sh deploy/linux/build-agent-artifacts.sh /tmp/argus-agent-release
sudo install -d -m 0755 /opt/argus-agent-release
sudo install -m 0644 /tmp/argus-agent-release/agent-linux-* /opt/argus-agent-release/
```

两份安装包使用当前代码构建，支持 Linux x86_64 和 ARM64。构建需要 Go；目标主机无需 Go。允许只发布一种架构，每份文件上限 32 MiB。服务器启动时验证 ELF 架构及静态链接要求，并将二进制冻结在内存中计算 SHA-256；更新文件后需重启服务器才会发布新版本。不要让 Agent 或非管理员写入发布目录及其父目录。

在已有 Console 启动参数上增加两项：

```sh
bin/server run -config /private/argus/server.json \
  -console-listen 0.0.0.0:9443 \
  -console-origin https://argus.example.com:9443 \
  -console-cert /private/console/browser.pem \
  -console-key /private/console/browser-key.pem \
  -console-installer-dir /opt/argus-agent-release \
  -console-fleet-origin https://fleet.example.com:8443
```

`-console-fleet-origin` 必须是目标主机实际能访问、且与 Fleet 证书匹配的 HTTPS 地址，不能使用监听地址 `0.0.0.0`。安装脚本中的 Fleet CA 来自服务器配置的公开 CA 文件，不含 CA 私钥。Console 证书与 Fleet CA 仍然独立。目标主机必须信任 Console 的 HTTPS 证书：私有浏览器 CA 应先通过可信渠道安装到目标机系统信任库，不能使用 `curl -k` / `wget --no-check-certificate`。目标机需要访问 Console 下载端口和 Fleet 连接端口，安装后只需要 Fleet。

若使用 systemd 管理服务器，将相同参数加入服务的 `ExecStart` 配置。未提供安装包配置时，“安装命令”说明缺少配置，“手动注册”继续可用。既有 Fleet JSON 配置格式不变。

## 目标主机上的行为

- 需要 Linux、正在运行的 systemd、systemd-sysusers、runuser、flock、SHA-256 工具，以及 curl 或 GNU wget。建议使用项目部署测试覆盖的 Ubuntu 24.04，其他发行版先验证 unit 支持情况。
- 自动识别 x86_64 / ARM64，下载并校验匹配的 Agent 二进制。
- 写入 `/usr/local/libexec/argus-c2/agent` 和 `/etc/argus-c2/{agent.json,policy.json,ca.pem}`。
- 创建独立 `argus-agent` 用户和 mode-0700 的 `/var/lib/argus-c2-agent`；注册 Token 临时文件为 mode 0600，完成或失败退出时清理。
- 以 `argus-agent` 执行配置检查及注册，然后启用并启动 `argus-c2-agent.service`。服务使用与手动部署一致的加固配置，以普通用户运行。
- 默认本地策略仅允许 `system.info` 和 `system.metrics`；不会开放任意命令执行或远程修改本地策略。

脚本不更改防火墙，不执行 SSH，不自动安装系统软件包。存在 Agent 配置、身份目录、用户或 unit 时会中止，避免覆盖已有安装。两个安装脚本不能并发写同一主机。首次安装后，在 Console 刷新 Agent 列表确认注册及心跳。preview.10 起，启用 Console 的 Server 在 Agent 空闲轮询时自动下发 `system.info`（每小时）与 `system.metrics`（每分钟），不需要手工创建任务，仍受本机策略限制。首批资源指标通常约一分钟出现；上下行速率需要连续两次采样，约两分钟。历史图表逐次积累，不补造安装前数据。

更新到 preview.10 的 Agent 在 `network_interfaces: []` 时自动选择默认路由网卡；显式网卡名单仍优先。Server 更新不会自动升级远端 Agent。带宽上限尚未配置，因此网络速率显示 bit/s，使用率百分比和总流量仍为不可用，不会伪造为 0%。采集任务与结果按现有保留机制存储，每台每天约 1,464 个任务，请按[历史清理流程](operations.md#server-history-retention)维护存储。

## 凭据与故障处理

命令内的 URL 含短期、一次性安装凭据，与 Fleet 注册 Token 不同。不要分享给其他人，也不要将完整 URL 放进日志、工单或版本库；它可能留在粘贴命令的终端历史中。若使用反向代理，屏蔽 `/v1/console/install/` 的凭据路径日志。Console 自身不记录该 URL；审计只记录安装 ID、签发管理员和创建/领取结果。

只有当前 Admin 可通过会话、Origin 和 CSRF 检查创建链接。服务器最多保留 128 条未过期安装链接；重启使链接失效。领取时再次按账号版本、角色、状态和 Console generation 验证权限，因此账号禁用、角色变化、撤销会话或恢复 Console 会阻止尚未领取的链接。普通注销不会撤销已签发的安装链接。

一次成功 GET 即消耗链接，HEAD 和浏览器导航不会消耗。网络中断导致脚本未完整下载时，命令不会执行，需重新生成。脚本中的 Fleet Token 与链接同时过期，只能绑定一台 Agent 的密钥；同一密钥可按照现有注册规则重试。**已下载的脚本不会因之后撤销管理员会话而被远程收回**；其 Token 仍受到期时间和单主机绑定约束。

如果安装已经写入配置但注册失败，脚本不会自动删除主机身份或回滚系统文件。检查错误、DNS、时间和证书，改用“手动注册”生成新 Token，按[手动注册步骤](deployment.md#4-configure-and-enroll-a-node)完成注册。若已注册但服务启动失败，保留已有状态，检查：

```sh
sudo systemctl status argus-c2-agent.service --no-pager
sudo journalctl -u argus-c2-agent.service -n 50 --no-pager
```

不要通过删除 Agent 身份来强行重跑自动安装；已注册主机的更换、升级和禁用沿用现有运维流程。

## 更新已注册的 Agent

使用新版发布脚本的 `--update agent`，在 Agent 主机本地执行，完整命令见 [Server／Agent 更新](server-installation.zh-CN.md#更新-server-或-agent)。它下载并校验当前架构包、停止 Agent、备份身份与待发送结果、检查数据库副本后替换程序，再恢复原服务状态；失败时恢复旧程序。注册证书、节点 ID、策略和现有数据库保留，不需要新的注册 Token。

`v0.1.0-preview.14` 的 Agent 开始上报具体发行版及版本，例如 `Debian 13`、`Ubuntu 24.04`。已有主机需要逐台执行上述更新；新 `system.info` 结果上报后，Overview 和详情页显示发行版、版本与架构。可以等待每小时的自动采集，或在管理页手动下发 `system.info`。更新 Server 只会更新供新主机安装的 Agent 文件，不会替换远端已经运行的 Agent。

## 卸载

在**需要移除的 Agent 主机**执行下列完整命令，可清除当前 Agent 程序、systemd 服务、配置、策略、注册证书、数据库和 `argus-agent` 系统账户：

```sh
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.14/install-server.py -o "$f" && sudo python3 "$f" --uninstall agent --purge )
```

选择语言后，核对清理清单，输入 `purge agent` 确认。想先查看范围，在 `--purge` 后、右括号前加 `--dry-run`；想保留身份供恢复，去掉 `--purge`。只有 wget 时，将下载部分换为 `wget --https-only --max-redirect=5 -O "$f" 同一个下载地址`。

历史更新/卸载备份不会被删除，可能仍含旧身份凭据；维护脚本也保留。完成后在 **管理 → Agents → 对应 Agent → 删除** 撤销服务器注册身份并移除任务和指标历史，审计记录保留。若要保留历史，选择 **禁用**。删除要求输入完整节点 ID 确认，并在最近十分钟内登录；不会远程卸载主机上的软件。重新加入需使用新注册凭据。

同一操作菜单提供 **重命名**，可设置 1–64 个可打印字符。该名称也显示在公开概览，请勿包含私密信息；不会修改主机操作系统的 hostname。

同一个发布脚本支持 `--uninstall agent`，默认保留配置、注册身份、数据库和策略；`--purge` 才清除当前 Agent 数据及专用账户，便于重新安装。完整下载命令、预览和恢复步骤见 [Server／Agent 卸载](server-installation.zh-CN.md#卸载-server-或-agent)。卸载只影响本机 Agent，不修改同机 Server，也不会自动撤销服务器上的注册身份；退役主机时还需在管理页禁用该 Agent。

Server 更新只刷新其托管的安装文件；已部署的 Agent 需要逐台显式更新。更新后在管理页面确认原节点的心跳恢复，避免把重新注册造成的新节点误认为升级成功。

