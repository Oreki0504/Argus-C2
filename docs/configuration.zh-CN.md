# 配置参考

[English](configuration.md) · [文档入口](../README.zh-CN.md) · [采集器](collectors.md) · [部署](deployment.md)

配置由本地文件提供，不通过管理 API 下发。Server 和 Agent 启动时读取一次；修改账号、策略或连接配置后需要重启对应进程。JSON 不支持注释、未知字段、重复字段、`null` 或尾随内容；以下对象字段均应完整提供，空集合使用 `[]`。

配置中的文件和目录路径须为规范绝对路径；不会展开 `~`、环境变量或模板。配置文件本身须为普通、非符号链接文件。私钥、管理员配置、token 应为 0600，状态目录为 0700；生产环境的配置、CA 和策略由本地管理员控制。systemd 凭证文件另有受限 ACL 读取支持。

## Server 配置

```json
{
  "listen": "127.0.0.1:8443",
  "state_dir": "/var/lib/argus-c2-server",
  "certificate": "/etc/argus-c2/server/server.pem",
  "private_key": "/etc/argus-c2/server/server-key.pem",
  "ca": "/etc/argus-c2/server/ca.pem",
  "issuer_key": "/etc/argus-c2/server/ca-key.pem",
  "admins": "/etc/argus-c2/server/admins.json"
}
```

| 字段 | 含义 |
| --- | --- |
| `listen` | `host:port`；只控制监听地址，不改变证书 SAN |
| `state_dir` | 已初始化的状态目录，内含 `argus.db` |
| `certificate` / `private_key` | 匹配的服务端 TLS 证书和私钥 |
| `ca` | 当前单一注册 CA 的证书，也是 TLS 客户端验证信任来源 |
| `issuer_key` | 与注册 CA 匹配的 ECDSA 私钥 |
| `admins` | 具名管理员 token 摘要配置 |

文件整体最多 8 KiB。服务端启动验证证书用途、信任链和有效期。仓库 systemd 单元通过 `LoadCredential` 提供三个秘密文件，实际配置见[部署指南](deployment.md)，不要直接把上面的文件权限放宽给服务用户。

## 管理员配置

格式为 `{"users":[账号记录]}`。账号记录应由下列命令生成，避免误把普通密码的摘要当作 token：

```sh
bin/argus new-user -name observer -role ReadOnly -out /private/observer.token
```

stdout 中的完整对象包含 `name`、`role` 和 `token_sha256`，将它加入 `admins.json` 的 `users` 数组，然后重启服务器。只有 `Admin`、`ReadOnly` 两个角色；至少保留一个可用的 Admin 是运维要求，当前验证器不会替你检查这一点。

账号数为 1–100；账号名为 1–64 个 ASCII 字母、数字、`_` 或 `-`；名称和摘要均不能重复。摘要为 64 位小写 SHA-256 十六进制。整个配置最多 32 KiB。没有密码登录、会话、自动到期或远程用户管理接口。

## Agent 配置

可从 [examples/agent.json](../examples/agent.json) 开始：

```json
{
  "server": "https://fleet.example.com:8443",
  "ca": "/etc/argus-c2/ca.pem",
  "state_dir": "/var/lib/argus-c2-agent",
  "policy": "/etc/argus-c2/policy.json"
}
```

| 字段 | 含义 |
| --- | --- |
| `server` | HTTPS origin；名称/IP 必须与服务端证书匹配 |
| `ca` | 本地可信 CA；没有跳过验证或首次连接自动信任选项 |
| `state_dir` | 注册时初始化，后续运行必须完整保留 |
| `policy` | 本地策略文件，注册时也会校验 |

文件整体最多 8 KiB。状态目录中包括 `agent-key.pem`、`agent.pem`、`probe.db` 和 `probe.lock`；`probe` 只是保留的内部文件名，当前程序统一叫 Agent。

## 本地策略

[examples/policy.json](../examples/policy.json) 是可直接复制的最小策略：

```json
{
  "allowed": ["system.info", "system.metrics"],
  "poll_seconds": 10,
  "timeout_seconds": 10,
  "max_result_bytes": 65536,
  "telemetry": {
    "sample_milliseconds": 1000,
    "disk_paths": ["/"],
    "network_interfaces": []
  },
  "services": [],
  "ssh_profiles": []
}
```

这些是示例值，不是省略字段时的隐式默认值。

| 字段 | 当前允许范围与含义 |
| --- | --- |
| `allowed` | 0–6 个已实现任务名，不可重复；`[]` 拒绝所有采集，但仍执行心跳、续期等循环操作 |
| `poll_seconds` | 5–60 秒；一次循环结束后的正常等待间隔，另加不足一秒抖动 |
| `timeout_seconds` | 1–30 秒；与任务执行预算取较小值，从授权成功且本地 RUNNING 落盘后开始计时 |
| `max_result_bytes` | 1024–65536 字节；完整序列化结果的本地上限 |
| `telemetry.sample_milliseconds` | 100–5000 毫秒；CPU 两次采样之间的等待时间，应小于任务执行预算 |
| `telemetry.disk_paths` | 0–8 个唯一、规范的 Linux 绝对路径，每个最多 256 字节 |
| `telemetry.network_interfaces` | 0–16 个唯一网卡名，每个 1–15 字节；不能含 `/`、`:` 或空格 |
| `services` | 0–16 个服务映射，ID 不可重复 |
| `ssh_profiles` | 0–4 个 SSH profile，ID 不可重复；每个 1–4 个文件 |

策略整体最多 32 KiB。`telemetry` 只供 `system.metrics` 使用，系统不使用 `interval_seconds`，也不周期推送指标。

### 启用其他采集器

以下是完整的本地策略示例。SSH 文件路径与 UID/GID 需符合目标节点实际情况：

```json
{
  "allowed": ["system.info", "system.metrics", "service.status", "network.listeners", "process.list", "ssh.audit"],
  "poll_seconds": 10,
  "timeout_seconds": 10,
  "max_result_bytes": 65536,
  "telemetry": {
    "sample_milliseconds": 1000,
    "disk_paths": ["/"],
    "network_interfaces": []
  },
  "services": [
    {"id": "journal", "unit": "systemd-journald.service"}
  ],
  "ssh_profiles": [
    {
      "id": "host",
      "files": [
        {
          "id": "config",
          "kind": "sshd_config",
          "base_dir": "/etc/ssh",
          "relative_path": "sshd_config",
          "owner_uid": 0,
          "owner_gid": 0,
          "max_bytes": 16384,
          "baseline_sha256": ""
        }
      ]
    }
  ]
}
```

映射 ID 为 1–32 个 ASCII 字母、数字、`_`、`-`，首字符必须是字母或数字。服务 `unit` 必须是明确的 `.service` 名称，最多 128 字节；不接受通配符、`..`、空模板 `name@.service`。Collector 只读取已加载 unit，不会启动它。

SSH 文件 `kind` 只接受 `sshd_config` 或 `authorized_keys`。`base_dir` 必须为规范绝对路径，不能指向 `/proc`、`/sys`、`/dev`、`/run` 及其子目录。`relative_path` 必须在该目录下，不能使用绝对路径、回退路径或通配符；文件名限制为 `sshd_config`、`sshd_config.d/` 下的 `.conf`，或 `authorized_keys` / `authorized_keys2`。

`owner_uid` / `owner_gid` 是预期所有者，必须与文件一致；`max_bytes` 为 1024–65536。`baseline_sha256` 为 `""` 或独立确认的 64 位小写摘要，只做比较，不会自动学习/更新基线。策略允许读取不代表 OS 授权读取；systemd 的主目录隐藏等限制仍然生效。

## 配置检查的边界

```sh
bin/server run -config /absolute/server.json -check
bin/agent run -config /absolute/agent.json -check
```

Server 检查会打开已有数据库并加载账号和凭证，但不绑定端口、不验证远端访问。Agent 检查只读配置和策略，不打开身份状态、不连接服务器、不探测映射资源。两者均不是端到端验收。长期运行中的配置变更不会热加载。

实现依据：[config](../internal/config/config.go)、[policy](../internal/policy/policy.go)、[资源映射](../internal/resources/resources.go)、[管理员认证](../internal/auth/auth.go)。
