# 运维与发布入口

_状态：待初始化 | 权威范围：环境、发布、健康、观测和恢复流程 | 更新：YYYY-MM-DD_

## 环境索引

| 环境 | 用途 | 发布入口 | 健康/冒烟 | 观测入口 | 权限边界 |
|---|---|---|---|---|---|
| local | 本地开发 | <!-- command --> | <!-- check --> | <!-- logs --> | 本地可逆 |
| test/staging | 验证 | <!-- pipeline/runbook --> | <!-- check --> | <!-- dashboard --> | <!-- approval --> |
| production | 生产 | <!-- controlled entry --> | <!-- health --> | <!-- dashboard/alerts --> | 明确授权 |

不要在本文记录密码、Token、私钥、完整环境变量或可直接使用的生产凭据。动态地址、版本、镜像和拓扑必须标注验证时间，并在操作前重新核验。

## 文档入口

- [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)：发布前检查、迁移、切换、验证和回滚。
- [OBSERVABILITY.md](OBSERVABILITY.md)：日志、指标、追踪、健康信号和排障入口。
- `docs/project-memory/`：具体环境和能力的可重复 Runbook。

## 发布原则

- `privilegedOperationsDefault=deny`：创建/推送 tag、创建 Release、发布 package/image、deploy、migration/backfill、rollback、traffic switch、仓库设置、凭据和发布工作流操作不进入普通初始化。
- 每次高权限操作必须按 repo/环境、operation、不可变版本或产物、目标、actor、expiry 单独授权；push、PR 创建/更新或 PR merge 权限不能推导出发布权限。
- 代码托管和部署平台应使用 branch protection、required checks、CODEOWNERS/独立审批和 environment approval 强制门禁；本地 manifest 不能替代远端控制。
- 发布目标使用不可变版本身份（commit、tag、digest 或等价物）。
- 任何数据迁移先确认备份、恢复和兼容顺序。
- 先 Preflight，再构建/部署，再健康检查、业务冒烟和观测。
- 失败时按预先定义的停止条件回滚或前滚，不在生产现场临时发明流程。
- 完成记录包含版本身份、执行人/入口、验证证据和剩余风险。
