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

安装本包后使用 `scripts/deployment_prepare.py` 生成部署与回滚计划、检查输入漂移，并比较显式提供的目标/观测快照。配置和输入契约见 [部署计划](DEPLOYMENT-PLANNING.md)。离线 CLI 与可选 `workflow-deploy` Skill 不执行阶段命令；CLI 不连接服务器。P1-1/P1-2 提供可信采集/授权 SDK 与独立 GitHub 授权宿主；P1-3 提供固定 Docker API 单组件替换后端。具体信任边界见 [运行时采集与授权](DEPLOYMENT-RUNTIME.md) 和 [部署执行](DEPLOYMENT-EXECUTION.md)。备份/恢复材料仅作为本机证据绑定，快照匹配仅证明所提供身份一致，不能替代实际健康、冒烟、备份可恢复性或生产验收。

## P1 采集与授权边界

仅在实际可用的可信宿主中采集运行基线、构建并审核精确请求；已有明确授权应沿用，不重复索要相同权限。宿主核验与一次性账本消耗仍须执行，不能由对话授权或导出 JSON 替代。首次目标身份是获批的期望声明，未证明目标产物真实或已经运行；执行器须核验预加载镜像、可信规格及完整现场。执行请求额外绑定 `Request.execution_json`，宿主须匹配 `execution_policy_hash`；旧 auth-only permit 即使已 claim 也不能执行。写入身份与只读采集身份分离，证书摘要绑定权限范围，服务端独立限制路由与资源。

回滚须提供同一 collector 保留的较早 observation，并从新鲜完整当前基线重新规划、申请新请求/授权；不能倒用旧部署 permit。保留旧镜像、可信规格与进程内历史，不保留已删除旧容器的日志或实例 ID；JSON 不能恢复历史能力。消耗失败、响应未知或消耗后漂移均停止，按已消耗处理，不自动重试、清理或回滚。中间态不完整时，常规回滚授权也会阻塞，先核对现场；恢复机制留待 P1-5。

离线 CLI 的 `executionAvailable` 为 `false`；实际宿主后端可为 `true`，但 `productionReady` 为 `false`，健康/冒烟为 `unknown`。首个 profile 不覆盖生产部署验收、切流、数据库、备份、readiness 或业务探测，也不保证服务 DNS/Compose 名称连续性。单元测试、合成假授权 smoke 与真实 GitHub 精确审批证据分别记录，不互相替代。
