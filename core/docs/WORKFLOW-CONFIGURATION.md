# 项目配置与只读体检

Core 提供 `scripts/workflow_config.py` 与 `scripts/workflow_check.py`，仅使用 Python 3.10+ 标准库。不安装 Skill 也能使用；体检不执行项目声明的命令，不 fetch、不连接生产、不改变 Git 状态。

## 创建与采用

先安装 Core，再在目标项目运行：

```sh
python3 scripts/workflow_config.py adopt --repo . --create --dry-run
python3 scripts/workflow_config.py adopt --repo . --create
python3 scripts/workflow_check.py --repo . --json
```

`--create` 仅在配置缺失时从既有能力声明创建骨架，不推断技术栈。已有配置直接 `adopt`，保留其命令、映射和扩展。`workflow.config.json` 是可选的项目共享配置；项目自行决定是否提交。安装器不自动创建、采用或忽略它，也不通过配置授予执行权限。

```json
{
  "schemaVersion": 1,
  "enabledCapabilities": ["cicd:github-actions", "release"],
  "commands": {
    "backend-test": {"command": "go test ./...", "cwd": "backend"}
  },
  "documents": {"tasks": "docs/TASKS.md"},
  "extensions": {
    "release": {
      "strategy": "commit-sha",
      "tagPrefix": "v",
      "components": ["backend", "frontend"]
    }
  }
}
```

示例只是配置格式，不能直接证明项目使用 Go、GitHub Actions 或发布能力。字段契约见 [Schema](workflow-config.schema.json)。不记录凭据、动态生产快照或带敏感参数的命令；不能声明 `gitPolicy` 或通过配置授权。

## 权威来源与同步

| 状态 | 行为 |
|---|---|
| 未采用且无配置 | 兼容读取 manifest 的 `enabledCapabilities` |
| 有效配置已采用 | 项目配置权威；manifest 保存兼容快照、采用标记和 SHA-256 |
| 有配置但未采用 | 体检报需要显式采用；安装可先建立 Core，但不启用配置声明 |
| 无效配置或已采用文件失踪 | 报错，不静默回退；恢复有效文件后再同步/撤回 |
| 配置与快照不同 | 配置声明优先，报告漂移；普通只读检查不修复，strict 失败 |
| 显式撤回 | 将当前有效声明保存回 manifest，保留配置文件并解除读取依赖，manifest 恢复权威；再次采用前重新验证文件 |

```sh
# 项目配置已采用时写配置并同步快照；否则只维护旧 manifest。
python3 scripts/workflow_config.py update --repo . --enable containers:compose --disable release --dry-run
python3 scripts/workflow_config.py update --repo . --enable containers:compose --disable release
# 手工编辑有效配置后显式同步
python3 scripts/workflow_config.py sync --repo .
# 撤回采用关系，保留最新能力声明与配置文件
python3 scripts/workflow_config.py withdraw --repo . --dry-run
python3 scripts/workflow_config.py withdraw --repo .
```

现有 Bash `--enable-capabilities` / `--disable-capabilities` 和 PowerShell 对应参数也遵循采用关系。禁用优先。部分卸载不删除声明，只会导致体检报告专项包/工具缺失；完整卸载保留项目配置和发布记录。重新安装后需重新采用。权限字段由既有机制单独维护。

配置写入通过本机锁、单文件原子替换和输入重检保护；跨配置/manifest 的操作中断可留下可诊断漂移，并非跨文件事务。恢复有效文件后 `sync`；残留 `configuration.lock` 时先确认没有其他进程，保留证据后再处理，不自动抢锁。

## 体检输出与边界

`workflow_check.py --json` 输出安装包、能力配置/工具可用情况、规则已知冲突、命令工作目录/文档路径、当前分支与本机缓存基线差异。`executable` 只表示已知工具文件存在，不证明命令已跑通；纯规则包为 `null`。

退出码：结构/配置错误为 1；普通告警默认 0，`--strict` 时为 1。Git 基线来自本机 refs，远端及生产始终标为 `unknown`。配置 CLI 的 check 返回解析结果；写命令支持 dry-run，失败返回 1。

体检只读取固定规则和显式声明的安全路径，不扫描 `.env`、日志和生产配置。旧脚手架短语与局部权限简写属于已知模式检查；任意文档的语义过期由 AI 按当前证据判断，脚本不伪装为完整语义审查。

## 部署扩展

`extensions.deployment` 声明全局组件及每个环境的 `production`、`target`、`capability`、组件子集与根 `commands` 引用；配置本身不启用能力或授予执行权限。部署计划需安装 `deployment` 包并显式启用对应能力。阶段命令的声明只用于计划及漂移绑定，体检和规划均不执行它们。字段示例、不可变目标/快照、回滚条件与本机证据边界见安装后的 [部署计划](operations/DEPLOYMENT-PLANNING.md)（分发源位于 `packs/deployment/docs/operations/`）。
