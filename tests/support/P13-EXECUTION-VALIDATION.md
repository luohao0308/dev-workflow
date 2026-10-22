# 独立 P1-3 执行验证指南

本文是验收步骤与证据要求，不是已完成报告。`p1_execution_live.py` 和 `p13-execution-validation.yml` 仅用于独立合成环境，不随 deployment 包安装，不在业务仓库、生产或共享 daemon 运行。P1-1/P1-2 的历史记录不修改，也不能作为 P1-3 执行通过证据。

## 环境与安全边界

独立宿主测试仓库固定可信分发源码；目标测试仓库提供真实 old/new 提交、`fixtures/p1-runtime/Dockerfile` 和不同 `release.txt`。宿主维护 `p1-fixture.json`，字段沿用 `hostRepository`、`hostRepositoryId`、`targetRepository`、`targetRepositoryId`、`reviewerIds`、`oldSha`、`newSha`；不能从候选项目加载策略。目标使用 `staging`、`p1-isolated`、组件 `web`/`api`、无数据库迁移；声明阶段命令不执行。

夹具在 Linux GitHub-hosted runner 上准备并预加载旧/新不可变镜像，再调用产品固定 Docker API 后端执行 web A→B→A，api 实例须始终保留。夹具的构建、临时 CA/证书、网关与最终专属资源清理属于测试设施，不是产品的 build/pull/cleanup 能力；不能将测试脚本当部署命令。reader/writer 使用不同 mTLS 证书，服务端分别限制 GET 与四种写入路由、project/选中组件和准确资源；测试制品不含私钥、原始 Env 或完整规格。

## 先验证真实 Docker，再验证真实授权

1. 在独立测试宿主将模板安装为单独工作流。先用 `real_authority=false`、`full_matrix=false` 执行 Docker smoke。它使用明确的 **`fakeTestApproval`**（当前夹具类名 `TestApproval`，合成测试替身），仅验证真实 Docker/mTLS 与产品部署/回滚路径；不是 GitHub OIDC、受保护审核或 CAS 证明，也不是业务 smoke probe。
2. smoke 稳定后，配置 `p13-observer` 与两个不同的受保护环境 `p13-deploy-approval`、`p13-rollback-approval`。审批人须匹配 `reviewerIds`，禁止管理员绕过；夹具的 `prevent_self_review=false` 仅用于合成验证，不直接作为生产规则。P1-2 的审批环境和旧授权不复用。
3. 用 `real_authority=true` 启动独立真实验收。审核 `p13-deploy-preview` 的实际请求、执行策略、组件、旧实例、目标镜像/规格、范围和到期时间，再以 `dev-workflow approve <bundleHash>` 精确评论批准部署门。任务已有授权不重复询问；这次新精确 bundle 仍须其独立审批。
4. 部署完成并获得新鲜当前 observation 后，夹具生成 `p13-rollback-preview`。审核历史目标、当前基线及新的请求/bundle，以它的新摘要批准回滚门。不能复用部署门的摘要、grant 或 permit。
5. 最终验收再启用 `full_matrix=true`，收集 Linux/macOS × Python 3.10/3.13 四路及 Windows/Python 3.10/PowerShell 第五路结果。平台检查与真实 Docker/OIDC 证据分开报告。

## 必须核对的证据

- smoke 的 `summary.json` 应明确 `realDocker=true`、`realMTLS=true`、`realGitHubOIDC=false` 与 `authority=synthetic-test-double`；报告中明确标识 fakeTestApproval，不升级为 GitHub 授权通过。
- 最终真实运行须有签名 OIDC、两个独立精确审批环境/bundle、不同请求和一次性 CAS 消耗记录，`realGitHubOIDC=true`、`authority=github-oidc-exact-review-cas`。
- 部署和回滚结果均为 `executed-verified`，分别核对 `declaredVersion` 与 `runtimeVersion`、完整组件映射、`runtimeObservation`、新建的实例身份和未变化的 api 实例；`productDeploymentExecuted`、`productRollbackExecuted`、`preservedApiInstance`、`restoredHistoricalIdentity` 应为真。恢复历史映射不等于恢复旧 web 容器 ID 或日志。
- 每次动作固定为 create-stopped→stop-old→remove-old→start-new，两次共八次变更，全部由 writer 身份发出。缺少精确执行绑定、错误策略/证书/路由、auth-only permit（含已 claim）、重复 intent/permit 均须拒绝；单元或负向测试证据另附，不能从成功路径推断。
- SDK 成功对象中的 `observation` 须在 JSON 序列化前取出并留在同一进程；制品/审计只有 `runtimeObservation` 证据副本，不能重建历史能力。原始规格与 Env 不应出现。
- 始终保留 `productionReady=false`，健康、业务冒烟、备份及 readiness 未知；不宣称切流、数据库、生产验收或 DNS/Compose 名称连续性。端口映射实测与 daemon 网络安全边界分别说明。

HTTP 失败、超时、guard 拒绝、漂移或未知立即停止；缺少制品、审批或 fresh observation 不算通过。旧授权不退款、不重放；产品不自动重试、清理或回滚。若留下不完整中间态，先在独立测试环境核对现场，不能用普通回滚授权绕过；P1-5 恢复机制未交付。重新运行是新的请求与审批，不是从 JSON 续跑。

结果制品分别为 `p13-smoke-results`、`p13-deploy-preview`、`p13-rollback-preview`、`p13-results`。最终报告应记录准确源码 SHA、run 链接、审批/账本证据、各路检查结果与缺口；本指南不预填通过结论。产品边界见 [部署执行](../../packs/deployment/docs/operations/DEPLOYMENT-EXECUTION.md)。
