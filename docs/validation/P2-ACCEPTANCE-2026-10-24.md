# P2 限定画像验收（2026-10-24）

仅修改 dev-workflow；未安装、升级或部署 luohao-blog。验收画像限定于独立测试仓库的 Linux Docker 单个无状态、只读且无挂载的 `web` 组件，允许中断，要求健康与业务探针，回滚目标固定为 v1 源 SHA。验收报告是历史证据，不授予后续执行权限，`productionReady=false`。

## 代码与审查

P2 新增严格画像与只读评估、分发目录中的可信宿主记录器、示例与操作文档。外部提交的全通过 JSON 保持 `unknown`；仅同进程、由固定 GitHub 客户端与默认 OIDC 验证器直接调用 SDK 所得的阶段观察可进入 `accepted`。审批、恢复、部署、回滚的来源和摘要分别绑定。Reader、writer、探针测试传输及不满足安全条件的画像在消耗授权／写入前被拒绝。复审发现的两处 HIGH 与预览摘要错误均已修复并复审通过。

## 独立环境证据

快照提交 `d9964456953aff43e685e2dbed617fb5da3c22c7`。合成模式运行 [40061917380](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/40061917380)：五组真实 Docker/mTLS 崩溃与恢复全部成功；尽管软件行为通过，合成授权报告明确为 `unknown`，没有伪称真实审批。

真实授权运行 [40062017119](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/40062017119)：受保护环境分别批准恢复 `p15-recovery-approval`、部署 `p14-deploy-approval`、回滚 `p14-rollback-approval` 三笔精确摘要。原故障注入使用合成授权，**不计作真实部署验收**；其后真实审批的恢复使 v1 健康，另一次真实审批将 web v1 部署到 v2，再用第三笔独立真实审批将 web 回滚到经认证的 v1 历史。api 保持原实例。三个阶段分别报告健康与业务探针通过、不同请求摘要、同一工作流 SHA／运行 ID／尝试次数和实际观察摘要。

组合报告 `p2-acceptance.json` 的限定画像结果为 `accepted`，`approval/deployment/health/smoke/rollback/recovery` 六项均 passed；`authorityGranted=false`、`executionAvailable=false`、`productionReady=false`。这说明该次指定测试环境演练完成，不是对任意项目或生产环境的授权或 SLA 保证。

独立完整跨平台运行：[40063777584](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/40063777584)，各平台的最终结果以该运行记录为准。本机 `scripts/check.sh`：708 项单元测试通过，12 项条件跳过；AST、Bash 和安装／卸载／升级集成通过。从真实 v0.12.0 Tag 到 v0.13.0 的临时项目升级及工具事务回退通过，用户数据保留，可信宿主入口未安装到候选项目。

## 保留边界

现有单组件替换先停止／删除旧实例，未提供零停机、流量切换、服务地址连续性、数据库迁移、多组件或多主机高可用。报告没有重新加载为可信执行能力的入口；导入报告只作未验证材料。历史归档保存部署证据，不是应用数据备份。Windows CLI 私有 ACL 和 Windows Docker 生产执行仍未认证。上线某个业务项目前仍须针对该项目、环境和中断约定另做接入验收。
