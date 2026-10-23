# P1-4 健康和业务验收：独立验证记录

验证日期：2026-10-23（北京时间）。范围仅 dev-workflow 和明确合成测试仓库；未操作 luohao-blog，未发布正式版本，也未将 P1-4/P1-5 功能分支合并主分支。

## 实际 GitHub 授权、Docker 部署和回滚

- 运行：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39822997259
- 固定测试源码：`3addbe5cc5c925098edae61fc7e8b4d214ca004c`，独立验证分支 `codex/p14-verification-validation`。该镜像验证 P1-4；工作分支后续 P1-5 集成不据此宣称完成。
- 目标仅 `luohao0308/dev-workflow-p0-target-20261022`，仓库 ID `1428943581`，staging / p1-isolated，非 production。
- web v1 来源 `14bc9e7bd5e94f079a33ae2af719023c7d21fbd0` → v2 `48ba368d095d4bc7fb810db3a490b0191205047b` → v1。api 原实例保留。
- 部署摘要 `bca37ad4b067088b15769676bf2dc11a58971594d596f5ce3d314f58104062df`；环境 `p14-deploy-approval`。用户明确委托登记，部署记录 ID `7259000506`。
- 回滚摘要 `ba50e9541ca5fa20db6bc1f00225a34662e14f081b7d0b2c0f5bb8bdc6600681`；独立环境 `p14-rollback-approval`。用户再次明确委托登记，记录 ID `7259463304`。
- 委托审批如实记录为代理登记，不宣称用户手动点击。实际权限由 GitHub 签名 OIDC、精确受保护审批及一次性 CAS 账本核验。

最终工作流 success，4 个实际运行 job 全部成功，其余矩阵／smoke job 按配置跳过。最终 p14-results 制品中：部署与回滚均为 `executed-verified`；各自健康和业务探针均 passed、HTTP 200、一次通过；共 8 次真实 Docker 写入；恢复完整旧版本映射，api 实例保持不变。reader 写入、未选中组件写入和错误服务端 pin 均被拒绝。`productionReady` 为 false。

## 跨平台与负向验证

修复版 CI：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39763833771 。7 个实际运行 job 全部成功：Linux/macOS × Python 3.10/3.13、Windows/Python 3.10 和 PowerShell 集成，以及两个真实 Docker smoke 场景。

两个 Docker smoke 场景分别验证正常 A→B→A 和业务返回错误后 `executed-unhealthy`、无自动回滚、再用独立测试授权回滚。该 smoke 使用明确的合成授权，不冒充真实 GitHub 授权；真实 GitHub 闭环由上面的独立运行证明。

独立审查发现并修复检查器实例替换／缓存绕过，以及宽松分块响应解析；固定可信类调用、原始实例身份和策略缓存校验，并拒绝不支持的分块响应。Windows／真实审批验证又发现探针后的权限／现场复核耗时被误计入网络超时；修复后网络期限按响应完成时间判断，复核仍受整体期限限制，新增回归覆盖。

旧运行 `39762218151` 实际部署后因上述计时问题验收失败，授权已消费，测试环境清理；未重用旧授权。后续运行 `39765032433` 因等待超过期限退出，未代登记过期审批，随后取消并生成本次新摘要。失败和过期记录不计为通过。

## 保留限制

本记录仅证明上述固定源码、合成无状态只读容器和测试范围。未证明业务项目部署、生产就绪、数据库／备份恢复、切流、零停机或任意网络拓扑。P1-5 的持久化和崩溃恢复不计入本记录的通过结论；后续修复和独立验收见 [P1-5 记录](P1-5-PERSISTENCE-RECOVERY-2026-10-23.md)。
