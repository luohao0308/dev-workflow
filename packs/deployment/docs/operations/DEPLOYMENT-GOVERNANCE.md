# 部署治理专项

适用能力：`deployment:compose`、`deployment:kubernetes-helm`、`deployment:vm-systemd`、`deployment:serverless`、`deployment:generic`。

## 最小检查

- 明确目标环境、所有者、版本/镜像 digest、配置来源、权限和发布窗口；动态值执行前重新核验。
- 发布前执行 preflight，发布后执行健康、业务冒烟、观测和告警检查；liveness 不替代 readiness 或业务验证。
- 数据库/Schema 变更先定义向前兼容窗口、备份、迁移顺序、停止条件和恢复/前滚路径。
- 回滚目标必须是已验证的不可变版本；不可逆迁移、流量切换、凭据和生产操作分别授权。
- 记录执行入口、版本身份、证据和剩余风险，完整流水保存在受控平台而非源码仓库。

详细发布和 Runbook 模板复用 `operations` pack 的 `RELEASE-CHECKLIST.md` 与 `docs/operations/runbooks/`。

## 停止条件

缺少回滚版本、备份/恢复证据、环境审批或健康/业务验证入口时，停止部署，不现场临时发明恢复流程。

## 只读计划入口

安装本包后使用 `scripts/deployment_prepare.py` 生成部署与回滚计划、检查输入漂移，并比较显式提供的目标/观测快照。配置和输入契约见 [部署计划](DEPLOYMENT-PLANNING.md)。CLI 与可选 `workflow-deploy` Skill 均不执行阶段命令、不连接生产，也不提供受信宿主执行适配器。备份/恢复材料仅作为本机证据绑定，快照匹配仅证明所提供身份一致，不能替代实际健康、冒烟、备份可恢复性或生产验收。
