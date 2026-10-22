# P1-3 真实部署与回滚执行验证（2026-10-22）

本次在上一轮未提交的 P1-1/P1-2 工作树上增加固定 Docker API 执行后端。未修改 luohao-blog，未提交/推送 dev-workflow、未创建发行版。独立测试使用既有合成仓库，源码镜像位于宿主测试仓库的 `codex/p1-executor-validation`，可信提交为 `1655656778535aaa9156122a49b7f29d59887ef3`；真实执行使用该提交。Windows 用例随后只修正计时起点，最终测试镜像提交为 `2d0bca19411247928ffda135f7b1a5d0e53f5dc7`；生产 Python 源码与真实执行版本完全一致，本地 54 个 Python 文件与最终测试镜像逐文件一致。

## 本次交付

- deployment 可选包增加 `deployment_spec.py` 与 `deployment_execute.py`；宿主 recipe 绑定不可变镜像、有效命令/环境、非 root、只读根、能力移除和固定网络/端口。配方摘要可用于重建，完整实际配置、管理文件和实例状态仍独立参与漂移检测。
- `deployment_authorize.py` 增加执行 intent 绑定、只读 permit 身份字段、进程内签发验证和执行阶段 guard。旧 authorization-only permit、JSON、重建对象及 release 授权不能驱动执行。
- 分发侧 `deployment_host.py` 要求额外 execution_policy_hash，绑定 writer 证书主体和完整执行策略。reader/writer 证书分开，服务端独立限制 GET 与选中组件的四种写入。
- 每次仅替换一个组件：create 停止态目标 → stop 准确旧 ID → remove 旧只读无挂载容器（force=false/v=false）→ start 准确新 ID。每次写入前校验授权、现场预期中间态、未选组件的实例与管理文件内容、仓库/计划；写入后的不确定响应停止且不自动重试。
- 回滚是新鲜当前状态 + 同一 collector 的较早历史 + 新 intent/request/grant，重新创建旧规格；不反用旧部署许可。未选组件保持原实例。
- Core 仅同步能力边界说明；README、离线规划文档、运行/执行契约和 workflow-deploy Skill 同步更新。无新依赖，离线 CLI 默认仍拒绝执行。

## 独立预验证

[最初通过的真实 Docker 预验证](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39746661159) 使用明确标记的 synthetic-test-double 授权，在真实 Linux Docker + mTLS 中完成产品执行器 web A→B→A，共 8 次写入。api 的容器 ID、PID、启动时间不变，历史组件身份恢复。它只证明实际执行与核验，不充当 GitHub 授权证明。

[最终源码矩阵及预验证](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39750323566) 另外验证 reader 写入、writer 修改未选 api 和错误 peer pin 均被拒绝；通过实际执行后复采确认 api 未被改动。该工作流 **6 个实际验证 job 全部成功**：跨平台矩阵 5/5，加真实 Docker 预验证 1 项；四个审批类 job 按本次非真实审批模式跳过，真实审批另由下述独立工作流验证。

## 真实 GitHub 授权及执行

[真实审批工作流](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39748483915) 使用 `p13-observer` 签名 OIDC、独立 `p13-deploy-approval` / `p13-rollback-approval` 受保护环境和外部一次性账本。用户明确授权后委托登记精确审批，不宣称用户手动点击 GitHub。

部署摘要：`80e6240ec150fa9e00119d04e65f1a3d839abda7e71b0a78b149cd8ee471235d`。部署已执行并核验，web 从来源 `fc006bc3d2bc968aec73ee7059e596c01b778a2a` 的 v1 替换为 `4efeab8b9c11c3f4ff366cd4c893b470d19bba12` 的 v2，api 保持原实例。

独立回滚摘要：`4d623690087c6eaed9cba5f274a2dfa321576b724efe2052d821ccfbe349657c`。回滚使用新鲜 v2 基线和同一 collector 保留的 v1 历史。用户明确授权后委托登记独立回滚审批，真实回滚已执行并核验通过。该工作流全部 4 个实际执行/审批 job 成功；两个结果均为 `executed-verified` / `execution=performed`。

最终 `p13-results/summary.json` 确认 realDocker、realMTLS、realGitHubOIDC、productDeploymentExecuted、productRollbackExecuted、preservedApiInstance、restoredHistoricalIdentity 均为 true，productionReady=false。共 8 次写入，两个 create 返回 201，其余 stop/remove/start 均为 204。reader 写入、writer 修改未选组件及错误 peer pin 的拒绝也均通过实际环境验证。

两个独立账本 ref 位于测试宿主 `refs/tags/workflow-deployment-grants/39748483915/<bundle>/<operation>`，均指向可信源码 `1655656778535aaa9156122a49b7f29d59887ef3`；这是授权账本，不是 dev-workflow 发行 Tag。

## 测试与审查

- 本地 `bash scripts/check.sh`：全量 Python 484 项（10 项平台条件跳过）、Bash 集成/语法与全源码 AST 通过。该次全量启动后补充了慢响应头回归，最终源码为 485 项，四组最终 CI 已完整验证，新增边界亦有专项证据。
- 真实回环 TLS 与 deadline 专项 48 项通过，writer TLS/过期发送预算专项 5 项通过；配方与并发审计等最终回归 12 项通过。独立复审所发现的管理文件漂移、并发重放覆盖日志、发送与响应头期限问题已修复并复审通过。
- Windows CI 显式包括 spec、execute、runtime、authorization 和 host 模块，并执行原生 PowerShell 集成；最终 Windows Python **405 项，397 通过、8 项平台条件跳过**，原生 PowerShell 集成通过。四组 Ubuntu/macOS × Python 3.10/3.13 均为 **485 项，475 通过、10 项平台条件跳过**，并通过 Bash 集成和语法/AST 检查。首轮 405 项中唯一失败是慢响应头测试将 Windows 信任库初始化计入了响应预算（2.18 秒）；改为从 guard 发送边界计时，保留 0.15 秒预算与 2 秒断言，执行器代码不变。
- Skill quick_validate 与生命周期测试通过；独立只读审查中三项基于指令的前向推演通过（真实宿主、伪授权 JSON、stop 响应未知）。不把该推演称为另一 Agent 的实际执行或真实 GitHub 证据。

## 当前限制

首次后端仅支持已预加载不可变 Linux 镜像、无持久挂载/设备/数据库迁移、非 root 的受限单容器替换。实际成功为 `executed-verified`，`executionAvailable=true`；`productionReady=false`，健康、业务冒烟和备份仍为 unknown。不保证零停机或 service-DNS/Compose 名称连续性，不 build/pull、切流或执行项目阶段命令。

删除旧容器不保留旧 ID、日志或内存，仅保留可核验镜像/配方及进程内历史。失败中间态可能令普通 collector 无法取得完整基线；此时不自动 cleanup、retry、rollback、退款或从 JSON 续跑，需要后续 P1-5 的现场核对/恢复契约。没有交付 readiness、健康/业务冒烟或生产验收；这些仍属于后续阶段。

细节见 [执行契约](../../packs/deployment/docs/operations/DEPLOYMENT-EXECUTION.md) 和 [复现指南](../../tests/support/P13-EXECUTION-VALIDATION.md)。
