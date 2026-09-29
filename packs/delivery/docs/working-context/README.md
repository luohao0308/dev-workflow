# 并行任务上下文

本目录只在项目同时存在多个独立任务、工作树或代理时启用。默认单任务项目继续使用本机 `docs/WORKING-CONTEXT.md`；本目录由本机 `info/exclude` 忽略，不作为团队记录源。

## 使用方式

- 每个并行任务建立一个 `<task-id>.md`，从 [TEMPLATE.md](TEMPLATE.md) 复制。
- `TASKS.md` 的进行中任务必须链接对应上下文。
- 根 `WORKING-CONTEXT.md` 只指向当前主任务，不能复制所有并行任务内容。
- 不在多个上下文中重复同一稳定事实；稳定事实进入 `PROJECT-SUMMARY.md`、架构或设计。
- 任务完成后清理本机上下文；本机记忆迁移到 `project-memory/`，团队可复用操作迁移到 `operations/runbooks/`，执行证据留在 CI/部署平台。
