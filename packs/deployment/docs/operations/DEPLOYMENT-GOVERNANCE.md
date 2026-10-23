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

回滚须提供同一 collector 保留的较早 observation，并从新鲜完整当前基线重新规划、申请新请求/授权；不能倒用旧部署 permit。保留旧镜像与可信规格；可选 P1-5 可将历史写入宿主签名私有存储，可信进程重启后重新核验加载。不保留已删除旧容器的日志或实例 ID；JSON 不能恢复历史能力。消耗失败、响应未知或消耗后漂移均停止，按已消耗处理，不自动重试、清理或回滚。中间态不完整时，常规回滚授权也会阻塞。已启用 P1-5 且具备原始签名日志和网关排空证明时，可按[中断恢复](DEPLOYMENT-RECOVERY.md)核对现场并申请独立恢复授权；不得复用部署或回滚审批。

离线 CLI 的 `executionAvailable` 为 `false`；实际宿主后端可为 `true`，但 `productionReady` 为 `false`，未配置 P1-4 时健康/冒烟为 `unknown`。配置[健康与业务验收](DEPLOYMENT-VERIFICATION.md)后，按固定只读 GET profile 检查健康与业务响应并报告实际结果；失败不会自动回滚。首个 profile 不覆盖生产部署验收、切流、数据库、备份或生产 SLA，也不保证服务 DNS/Compose 名称连续性。单元测试、合成假授权 smoke 与真实 GitHub 精确审批证据分别记录，不互相替代。

## 中断时的运维核对

1. 停止发起新写入，保留原操作 ID、请求／消费摘要、签名日志与网关记录。确认实际宿主、仓库、环境、daemon/project 和组件范围；不要把项目导出的 JSON 当作现场或授权。
2. 用可信 reader 核对完整 inventory 和已知完整 ID／名称的直接查询，同时检查未选中组件。列表缺失不能证明容器已删除；只有认证的直接查询 404 可以证明准确资源不存在。
3. 由可信宿主核对每个写入 generation 的 admission、definitive completion 和排空证明。未知、截断或仍在执行的上游响应不能由容器状态稳定、进程退出或等待超时替代。
4. 核对 Core owner 与签名日志中的完整 pid/token/operation/transaction，以及真实进程存活。不要删除或替换锁文件；活 owner、未知存活状态或未知 recovery.lock 必须保留。目标文件锁与 Core owner 的处理不同，详见恢复指引。
5. 若日志、排空、历史配方和现场均通过可信宿主核验，生成新恢复请求，再走独立审批及一次性消费。若任一证据无法取得，保留阻塞状态，将固定错误码和脱敏摘要交给宿主运维核查，不临时补造历史、修改账本或手工强解锁。

这些核对不需要执行 Docker 写入。`HostCoordinator.inspect` 会关闭旧 generation，属于有持久化影响的宿主操作；不能把它当作完全无副作用的通用诊断命令。安装 pack 或 Skill 本身不提供可信宿主、Docker 权限或审批权。
