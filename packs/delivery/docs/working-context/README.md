# 并行任务上下文

本目录只在项目同时存在多个独立任务、工作树或代理时启用。默认单任务项目继续使用 `docs/WORKING-CONTEXT.md`。

## 使用方式

- 每个并行任务建立一个 `<task-id>.md`，从 [TEMPLATE.md](TEMPLATE.md) 复制。
- `TASKS.md` 的进行中任务必须链接对应上下文。
- 根 `WORKING-CONTEXT.md` 只指向当前主任务，不能复制所有并行任务内容。
- 不在多个上下文中重复同一稳定事实；稳定事实进入 `PROJECT-SUMMARY.md`、架构或设计。
- 任务完成后将证据迁移到工作日志，将长期经验迁移到 `project-memory/`，再删除或归档上下文。
