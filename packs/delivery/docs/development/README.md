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

- Worktree 模式：`required` / `recommended` / `disabled`（选择一项）
- 分支命名：
- 提交格式：
- 集成策略：<!-- ff-only/rebase/merge/PR -->
- 自动允许：<!-- 本地可逆操作 -->
- 需要确认：<!-- merge/push/生产/发布 -->

若 Worktree 模式为 `required` 或 `recommended`，按 [GIT-WORKTREE-WORKFLOW.md](GIT-WORKTREE-WORKFLOW.md) 执行。

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
| 重复性故障经验 | 修复回归测试 | `project-memory/` |
| 纯文档 | 链接、格式、事实来源检查 | 对应索引 |

## 完成定义

- 变更范围清晰且没有夹带无关修改。
- 适用检查通过，或未运行项有原因与替代证据。
- 运行时变更完成任务自有服务重启和冒烟。
- 契约、迁移、架构、任务和长期知识已按影响同步。
- 交付摘要包含文件、命令、结果、风险和后续动作。
