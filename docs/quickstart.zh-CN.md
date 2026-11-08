# 本地快速开始

[English](quickstart.md) · [文档入口](../README.zh-CN.md) · [命令参考](cli.md) · [Linux 部署](deployment.md)

本指南在一台 Linux 机器上完成 Server、Agent 和 CLI 的完整闭环。所有数据放在独立临时目录，不安装系统服务。使用同一个 Bash 终端依次执行，运行用户必须为非 root；需要 Go 1.27.3、Python 3，以及空闲的本机 TCP 8443 端口。

使用 Web 后台请按[Server 一键安装](server-installation.zh-CN.md)部署。安装生成的随机管理员 Token 可直接登录，OAuth 在后台按需绑定；详见[登录说明](console-login.zh-CN.md)。本页下面是独立的 CLI 演示，CLI admin.token 不能登录 Web。

正式部署的[更新和卸载](server-installation.zh-CN.md#卸载-server-或-agent)也由同一个安装脚本提供：`--update server|agent`、`--uninstall server|agent`。卸载默认保留数据，用 `--restore server|agent` 可复用原证书和身份恢复；显式 `--purge` 才清除当前部署。

## 1. 构建

先进入仓库根目录：

```bash
mkdir -p bin
for command in server agent argus; do
  CGO_ENABLED=0 go build -trimpath -o "bin/$command" "./cmd/$command"
done
```

## 2. 初始化并启动服务器

`server init` 要求目标目录不存在。它创建 CA、服务端证书、管理员 token、配置和数据库。私钥与 token 不会打印到终端。

```bash
umask 077
export ARGUS_DEMO
ARGUS_DEMO=$(mktemp -d /tmp/argus-demo.XXXXXX)
printf '本次演示目录：%s\n' "$ARGUS_DEMO"

bin/server init -dir "$ARGUS_DEMO/server" \
  -hosts localhost,127.0.0.1 -listen 127.0.0.1:8443
bin/server run -config "$ARGUS_DEMO/server/server.json" -check
bin/server run -config "$ARGUS_DEMO/server/server.json" \
  >"$ARGUS_DEMO/server.log" 2>&1 &
ARGUS_SERVER_PID=$!
ARGUS_AGENT_PID=
trap 'kill "$ARGUS_SERVER_PID" ${ARGUS_AGENT_PID:+"$ARGUS_AGENT_PID"} 2>/dev/null || true' EXIT

argus_demo() {
  bin/argus -server https://localhost:8443 \
    -ca "$ARGUS_DEMO/server/ca.pem" \
    -token-file "$ARGUS_DEMO/server/admin.token" "$@"
}

for attempt in {1..50}; do
  if argus_demo health >/dev/null 2>&1; then break; fi
  sleep 0.1
done
argus_demo health
```

最后应输出 `{"status":"ok"}`。如果失败，查看演示目录中的 `server.log`，不要继续注册。这里的 `-hosts` 是证书允许的主机名/IP，`-listen` 是监听地址；两者用途不同。

## 3. 创建本地策略并注册 Agent

复制的示例只启用 `system.info` 和 `system.metrics`。配置中的路径使用绝对路径；省略必填字段不会自动补默认值。

```bash
cp examples/policy.json "$ARGUS_DEMO/policy.json"
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ["ARGUS_DEMO"])
config = {
    "server": "https://localhost:8443",
    "ca": str(root / "server/ca.pem"),
    "state_dir": str(root / "agent"),
    "policy": str(root / "policy.json")
}
(root / "agent.json").write_text(json.dumps(config, indent=2) + "\n")
PY

bin/agent run -config "$ARGUS_DEMO/agent.json" -check
argus_demo enrollment-token -out "$ARGUS_DEMO/enroll.token" -ttl 300
bin/agent enroll -config "$ARGUS_DEMO/agent.json" \
  -token-file "$ARGUS_DEMO/enroll.token"
rm "$ARGUS_DEMO/enroll.token"

bin/agent run -config "$ARGUS_DEMO/agent.json" \
  >"$ARGUS_DEMO/agent.log" 2>&1 &
ARGUS_AGENT_PID=$!
argus_demo nodes
```

注册 token 与管理员 token 是两种凭证。注册 token 只用于一次节点身份分配；重复请求仅在 token 未过期且使用同一公钥时可恢复。Agent 的 `agent-key.pem` 始终在节点本地生成。

`agent run -check` 只校验配置和策略。真正启动 Agent 才会检查已有证书、状态库及连接；不要将 `-check` 的成功当作注册完成。

## 4. 创建任务并读取结果

本演示只有一个节点，因此可以从列表取出其 ID。实际多节点环境应明确选择目标节点。

```bash
ARGUS_NODE_ID=$(argus_demo nodes | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
ARGUS_TASK_ID=$(argus_demo create -node "$ARGUS_NODE_ID" -type system.info \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
argus_demo wait -task "$ARGUS_TASK_ID" -timeout 1m

ARGUS_METRICS_ID=$(argus_demo create -node "$ARGUS_NODE_ID" -type system.metrics \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
argus_demo wait -task "$ARGUS_METRICS_ID" -timeout 1m
argus_demo audit
```

响应包含 `task`，已收到终态结果时还包含 `result`。先看任务 `status`，再看 `result.payload` 中的数据可用性。`wait` 在 `SUCCEEDED` 时退出 0，在 `FAILED`、`UNKNOWN` 或等待超时时退出非零。

默认 Agent 在每轮工作结束后等待约 10 秒，因此任务不会立即执行。`wait -timeout` 只控制 CLI 等待时间；`create -ttl` 控制首次执行授权的截止时间；`create -execution-timeout 10s` 设置独立采集预算，并受 Agent 本地策略上限约束。

## 5. 停止演示

```bash
kill "$ARGUS_AGENT_PID" "$ARGUS_SERVER_PID"
wait "$ARGUS_AGENT_PID" "$ARGUS_SERVER_PID"
trap - EXIT
printf '状态和日志保留在：%s\n' "$ARGUS_DEMO"
```

数据目录保留，可用同一配置再次启动两个程序。不要再次对已有 Server 目录执行 `init`，也不要删除已注册 Agent 的 `probe.db` 来“重新开始”。若不再需要演示，在进程停止后自行清理该临时目录。

需要服务状态、SSH、进程或端口采集时，继续阅读[配置参考](configuration.zh-CN.md)和[采集器说明](collectors.md)。准备长期运行时，按照[部署指南](deployment.md)改为独立用户和 root 管理的策略文件。
