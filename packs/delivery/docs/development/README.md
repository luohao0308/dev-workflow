# 开发与交付入口

_状态：待初始化 | 更新：YYYY-MM-DD_

本页把项目真实可执行的开发命令、Git 策略、服务边界和变更影响集中到一个入口。命令必须来自仓库脚本、配置或 CI，不凭经验猜测。

## 仓库与工作区

| 仓库/路径 | 默认集成分支 | 包管理/运行环境 | 所有权 | 备注 |
|---|---|---|---|---|
| <!-- path --> | <!-- branch --> | <!-- runtime/tool --> | <!-- owner --> | <!-- separate repo/worktree --> |

## 命令矩阵

| 目的 | 命令 | 工作目录 | 适用条件 |
|---|---|---|---|
| 安装依赖 | <!-- command --> | <!-- path --> | <!-- lockfile/runtime --> |
| 本地启动 | <!-- command --> | <!-- path --> | <!-- dependencies/ports --> |
| 定向测试 | <!-- command --> | <!-- path --> | <!-- changed area --> |
| 全量测试 | <!-- command --> | <!-- path --> | <!-- high risk/release --> |
| lint/format | <!-- command --> | <!-- path --> |  |
| 类型/静态检查 | <!-- command --> | <!-- path --> |  |
| 构建/打包 | <!-- command --> | <!-- path --> |  |
| 数据迁移 | <!-- command or runbook --> | <!-- path --> | <!-- backup/compatibility --> |
| CI | <!-- workflow/script --> | <!-- path --> | <!-- required gates --> |

## Git 与隔离策略

- Worktree 模式：`required` / `recommended` / `disabled`（只描述隔离偏好，不代表每个任务都要建分支）
- 分支决策：仅为有意进入 Git 的共享交付创建；本机记忆、临时上下文、部署流水和只读任务不建分支。
- 分支命名：
- 提交格式：
- 集成策略：<!-- ff-only/rebase/merge/PR -->
- Git 交付策略：以 `.dev-workflow/manifest.json` 的 `gitPolicy` 为当前机器的执行权限权威；此处记录远端门禁和项目补充说明。
- 本地流程文件：以 `info/exclude` 的实际 `git check-ignore` 结果为准；已跟踪或被项目规则重新放行的路径必须在交付前处理。
- 流程要求：feature/bug/security/跨模块工作关联 Issue；交付默认经过 PR、required CI 和独立 Review。
- 自动允许：<!-- 本地可逆操作；远端操作仅在对应 mode=auto、actor=ai、一次性授权和质量门都通过时执行 -->
- 需要确认：<!-- mode=manual 的 push、PR 创建/更新、远端 PR merge；持久权限策略修改固定需人工确认 -->
- 一次性授权：<!-- repo + remote + remote URL + operation + source ref + target ref + exact SHA + expiry + maxUses；文件放在 .dev-workflow/authorizations/ -->
- 远端强制门：<!-- branch protection / required checks / CODEOWNERS / environment approval -->
- 高权限操作：`privilegedOperationsDefault=deny`；发布、部署、迁移、回滚、流量、仓库设置、凭据和删除按明确目标另行授权。

若 Worktree 模式为 `required` 或 `recommended`，按 [GIT-WORKTREE-WORKFLOW.md](GIT-WORKTREE-WORKFLOW.md) 执行。

AI 执行远端操作前先运行 Core 自带、零第三方依赖的 `python3 scripts/delivery_guard.py check ...`。`actor=user` 时 guard 固定拒绝为 AI 放行；`actor=ai` 时必须提供 `.dev-workflow/authorizations/` 下、权限不宽于 `0600` 的一次性授权 JSON。真正执行前使用 `--consume` 原子记录消耗次数。每类操作都必须提供五分钟内从托管平台读取、并绑定当前仓库/remote/ref/SHA 的 provider 证据；push 证据还要证明非删除、非 force、fast-forward 且目标分支未受保护，merge 证据还要覆盖 PR、CI、独立人工 Review 和分支保护。guard 不读取 Token，也拒绝带凭据、query 或 fragment 的 remote URL。

## 本地服务登记

| 服务 | 启动入口 | 健康/冒烟入口 | 端口策略 | 安全停止方式 |
|---|---|---|---|---|
| <!-- service --> | <!-- command --> | <!-- endpoint/check --> | <!-- fixed/dynamic --> | <!-- PID/workdir verification --> |

## 变更影响矩阵

| 变更类型 | 最低验证 | 需要同步的文档/产物 |
|---|---|---|
| 新增或改变模块边界 | 定向测试 + 静态检查 | `PROJECT-SUMMARY.md`、`architecture/` |
| API/事件/Schema 变化 | 契约测试 + 消费方回归 | `contracts/`、生成物、迁移说明 |
| 数据模型/迁移 | 迁移演练 + 数据断言 | 迁移模板、备份/恢复入口、架构数据说明 |
| 运行时代码/配置/依赖 | 定向测试 + 重启 + 冒烟 | 本页命令、Runbook、配置说明 |
| 部署/基础设施 | 配置校验 + Preflight + 回滚演练 | `operations/`、Runbook、观测入口 |
| 团队可复用的重复性故障经验 | 修复回归测试 | `operations/runbooks/` |
| 纯文档 | 链接、格式、事实来源检查 | 对应索引 |

## 完成定义

- 变更范围清晰且没有夹带无关修改。
- 适用检查通过，或未运行项有原因与替代证据。
- 运行时变更完成任务自有服务重启和冒烟。
- 契约、迁移、架构、任务和长期知识已按影响同步。
- 交付摘要包含文件、命令、结果、风险和后续动作。
- 交付状态和证据包含 `committed → pushed → pr_open → ci_passed → review_approved → merged` 中实际到达的阶段、准确 SHA、PR head/base、CI 和独立 Review。
