# 部署与回滚只读计划

本包提供 Python 3.10+ 标准库工具 `scripts/deployment_prepare.py`，规划环境内的组件变更、完整目标与回滚身份，并比较显式提供的观测快照。它不执行项目命令、不访问网络、不连接服务器；没有部署执行器或生产宿主适配器。`executionAvailable` 与 `productionReady` 始终为 `false`。可直接使用工具，无需安装 Skill；`workflow-deploy` 是独立显式安装的第五个可选入口，`--all-packs` 不安装 Skill。

## 配置与命令引用

先安装 Core 和 `deployment` 包，显式采用 `workflow.config.json`，启用环境对应的 `deployment:*` 能力。配置需已同步，工作区需干净，并使用准确的 Git 仓库根目录；未完成的规则升级应先恢复。`extensions.deployment` 必须包含全局非空唯一 `components` 和非空 `environments`。每个环境必须声明 `production` 布尔值、`target`、注册的 `capability`、全局组件的非空唯一子集及 `commands`。名称使用最长 128 字符的可移植标识符：首字符为字母或数字，其后可含字母、数字、`_`、`.`、`-`。

只读 Git 检查显式禁用 `core.fsmonitor`，并在读取工作区状态前拒绝会触发 clean/process 回调的 Git 内容过滤器（含 Git LFS 属性）及 submodule gitlink。规划器还在检查对象前拒绝配置了 partial clone 或 promisor 的仓库，避免缺失对象触发 Git 自动获取。Git helper 同时设置 `GIT_NO_LAZY_FETCH=1` 与 `GIT_TERMINAL_PROMPT=0`；离线保证依赖前置配置拒绝，不假设旧版 Git 支持这些环境开关。当前规划器不支持内容过滤器/LFS、子模块及 partial clone/promisor 工作区；遇到限制时报告阻塞，用户需独立提供适合的完整本地仓库，不能仅凭输入声明认定对象已经齐全，也不执行过滤器、初始化子模块、获取对象或改用命令绕过。

以下是配置片段；根 `commands` 中的实际命令应由项目按已验证入口提供，示例引用不是可执行建议：

```json
{
  "extensions": {
    "deployment": {
      "components": ["web", "worker"],
      "environments": {
        "production": {
          "production": true,
          "target": "primary",
          "capability": "deployment:compose",
          "components": ["web", "worker"],
          "commands": {
            "preflight": "production-preflight",
            "deploy": "production-deploy",
            "health": "production-health",
            "smoke": "production-smoke",
            "rollback": "production-rollback"
          }
        }
      }
    }
  }
}
```

阶段值引用根 `commands` 的现有键，根命令包含 `command` 和仓库内 `cwd`。计划需要 `preflight`、`deploy`、`health`、`smoke`、`rollback` 入口；还可声明 `backup`、`restore`、`migrate`。配置校验允许不完整阶段声明，规划会报告缺失入口。声明和体检均不执行命令，`production: false` 也不启用执行。配置不保存凭据、服务器访问材料或动态快照。

## 目标、基线与条件

目标清单为 JSON，字段恰好为 `kind: "deployment-target"`、`schemaVersion: 1`、`environment`、`target`、`version` 和非空 `components` 数组。`version` 是最长 128 字符的显式版本标签：首字符为字母或数字，其后可含字母、数字、`.`、`_`、`+`、`-`，例如 `v1.2.3+build.7`；不接受 `latest`、`HEAD`、`main`、`master`、`unknown`（不区分大小写）。当前/观测快照使用 `kind: "deployment-snapshot"`，具有相同身份字段，并增加带时区的 `capturedAt`（建议 UTC）与最长 512 字符的非空字符串 `provenance`。环境与目标须匹配选定配置。`provenance` 是提交者声明，不是宿主认证。

例如仅更新 `web` 的目标清单（摘要为格式示例，不代表真实产物）：

```json
{
  "kind": "deployment-target",
  "schemaVersion": 1,
  "environment": "production",
  "target": "primary",
  "version": "release-2026-10-22",
  "components": [{
    "name": "web",
    "sourceSha": "1111111111111111111111111111111111111111",
    "artifact": {"kind": "registry", "ref": "registry.example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "configurationDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "migrationVersion": null
  }]
}
```

每个组件必须记录：

| 字段 | 契约 |
|---|---|
| `name` | 环境声明内的组件名，数组内唯一 |
| `sourceSha` | 完整的 40 或 64 位小写十六进制来源 SHA；各组件独立，不强制等于本仓库 HEAD |
| `artifact` | 下表三种不可变身份之一 |
| `configurationDigest` | `sha256:` 加 64 位十六进制摘要 |
| `migrationVersion` | 可移植标识符或 `null`；不能省略 |

| `artifact.kind` | 其他必需字段 |
|---|---|
| `registry` | `ref`：限定 registry 与 repository，使用 `@sha256:` 加 64 位小写十六进制 digest；不接受可变 tag |
| `local-build` | `imageId`：`sha256:` 加 64 位十六进制；`buildSourceSha` 必须与该组件完整 `sourceSha` 相同 |
| `bundle` | `ref`：最长 256 字符的产物标签，可含字母、数字、`.`、`_`、`/`、`-`，首字符为字母或数字且无 `..` 路径段；`sha256`：64 位小写十六进制内容摘要 |

Registry authority 支持小写 DNS 主机名或 IPv4，可附数字端口 `1–65535`；暂不支持 IPv6 authority。Repository 路径按段验证，每段使用小写字母/数字及受限分隔符，不允许空段（`//`）或 `..` 路径段。引用语法的上游依据见 [Distribution reference 正则定义](https://raw.githubusercontent.com/distribution/reference/main/regexp.go)；本工具仅支持上述子集，不声明完整 OCI/Distribution 引用兼容。

目标可只列出本次变更组件；未变更组件从当前快照按原身份保留，完整期望状态不丢弃它们。当前快照可提交部分组件，但会产生 `rollback-state-incomplete` 阻塞；覆盖选定环境的全部组件才能确定完整回滚状态。缺少基线会生成阻塞草稿，不能用仓库 HEAD、目标值或本机构建结果补造线上状态。回滚目标来自显式当前快照。

可选条件 JSON 使用 `kind: "deployment-conditions"`、`schemaVersion: 1`、相同 `environment`、`target`，并声明：

```json
{
  "kind": "deployment-conditions",
  "schemaVersion": 1,
  "environment": "production",
  "target": "primary",
  "backup": {"required": true, "reference": "evidence/backup.txt", "restoreEvidence": "evidence/restore.txt"},
  "migration": {"mode": "reversible", "evidence": "evidence/migration.txt"}
}
```

`backup.required` 为布尔值，两个材料路径可为 `null`；`migration.mode` 取 `none`、`reversible`、`irreversible`、`unknown`，其材料路径也可为 `null`。所有 JSON 输入与证据文件须在仓库内、为非链接普通文件且不超过 1 MiB。主输入扩展名须为 `.json`；证据为显式 `.json`、`.md` 或 `.txt` 元数据路径，不接受 `.env` 文件、原始备份数据或凭据；工具绑定文件字节的哈希，不搜索凭据、下载材料或证明材料内容真实。备份的有效需求还取决于迁移等条件，不能仅靠 `required: false` 绕过；缺失必需备份、恢复或迁移证据，以及不可逆/未知迁移会阻塞相应部署/回滚建议。条件缺失时不推断“无需备份、无需迁移”。

## 规划与漂移检查

从目标项目根目录执行，全部命令输出 JSON，无需 `--json`：

```sh
python3 scripts/deployment_prepare.py status
python3 scripts/deployment_prepare.py plan --repo . --environment production \
  --target-manifest target.json --current-snapshot current.json \
  --conditions conditions.json --max-snapshot-age 3600 \
  --output .dev-workflow/releases/deployments/plan.json
python3 scripts/deployment_prepare.py check-plan --repo . \
  --plan .dev-workflow/releases/deployments/plan.json
```

只有显式 `--output` 请求写计划文件，未指定时仅输出。输出必须位于仓库内 `.dev-workflow/releases/deployments/`，由 Git 忽略，且整个 `.dev-workflow` 没有已跟踪内容；同名计划不覆盖。`--current-snapshot` 和 `--conditions` 可省略，但相关状态及证据缺口保留为阻塞，不会静默补全。默认快照最大年龄为 3600 秒，可选范围为 1–86400 秒；超前超过 30 秒同样阻塞。年龄仅根据声明的 `capturedAt` 计算，不证明采集来源可信或服务器此刻仍处于该状态。

计划绑定仓库 HEAD、完整已采用配置、环境和命令引用及 `cwd`、所有输入 JSON 和本机证据文件的字节。`check-plan` 检查这些输入是否漂移；检查通过只表示这份本机计划仍与绑定输入一致，不是执行授权，也不证明命令可执行、CI 成功或线上状态。输入变化后重新规划，不手工修改计划绕过检查。部署计划与快照是项目数据，卸载不删除；不要把含敏感信息的运行材料当作共享配置提交。

## 显式快照比较

```sh
python3 scripts/deployment_prepare.py compare --repo . \
  --plan .dev-workflow/releases/deployments/plan.json \
  --observed-snapshot observed.json --direction deploy
# 回滚后提供独立观测快照，比较方向改为 rollback。
```

`--direction` 默认 `deploy`，可选 `rollback`。部署方向比较完整期望状态（含原样保留的组件）；回滚方向比较基线身份。比较只读取用户提供的快照，逐组件检查来源、artifact、配置摘要与迁移版本，报告差异或未知，并单独给出快照新鲜度；过期或过度超前快照返回 `stale-supplied-snapshot`。即使全部匹配，实际执行、在线健康和业务冒烟仍为 `unknown`，不声明生产验证完成。

配置、Skill 安装、计划文件、普通 push 权限或用户编写的授权 JSON 均不提供执行能力。执行部署、迁移、回滚或切流请求在本阶段只能返回执行集成缺口与已有计划；不通过 shell、SSH、Docker、kubectl、云 CLI 或动态 provider 绕过。实际运行仍需项目单独提供受信执行集成及其授权与证据机制，本包未实现该机制。

保存的计划同时绑定快照新鲜度：即使文件字节未变，原基线超过 `maxSnapshotAge` 后，`check-plan`/`compare` 也会要求重新规划。刷新采集材料并重新审阅计划；重新规划仍可能返回 `blocked`，输入一致或快照匹配都不解除执行阻塞。历史回滚清单仍保留，不能把旧计划当成新的现场验证或执行授权。
