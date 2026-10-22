# 独立 P1 验证环境

`p1_runtime_live.py` 是 Linux GitHub-hosted runner 上的合成测试，不随 deployment 包安装，也不是部署执行器。它只创建本次 run 专属的容器、临时 CA 和客户端证书；结束时删除专属容器。不要在业务仓库或共享 Docker daemon 运行。

在独立公开宿主测试仓库复制本发行版的源码和 `p1-runtime-validation.yml` 到 `.github/workflows/p1-validation.yml`，使用独立公开目标测试仓库。宿主根目录的、由宿主维护者审核的 `p1-fixture.json` 需要这些字段：`hostRepository`、`hostRepositoryId`、`targetRepository`、`targetRepositoryId`、`reviewerIds`、`oldSha`、`newSha`。两个 SHA 必须是目标仓库中真实提交的完整 SHA，禁止从候选项目配置加载宿主策略。

两个目标提交均应有 `fixtures/p1-runtime/Dockerfile` 与 `release.txt`，且后者内容不同。测试 Dockerfile 使用 BusyBox、复制该文件、以非 root 用户运行 `sleep 3600`。目标配置采用 `deployment:compose`，环境 `staging`、target `p1-isolated`、组件 `web` 与 `api`；阶段命令仅作离线声明，SDK 不执行它们。宿主构建并记录真实镜像 ID、平台和来源提交，配置为无数据库迁移。

宿主创建 `p1-observer` 环境，以及两个独立审批环境 `p1-deploy-approval`、`p1-rollback-approval`。后两者要求 `reviewerIds` 指定的用户审批、禁止管理员绕过；本合成单账户验证允许发起者审批，所以 `prevent_self_review=false`。该选择不能直接复制成生产策略。

手动触发工作流。先下载 `p1-deploy-preview` 审核组件、范围和变更，以 `dev-workflow approve <bundleHash>` 的精确评论批准部署授权环境。测试只消费一次授权，不连接产品执行器。随后测试夹具独立切换合成容器，生成新基线与 `p1-rollback-preview`；审核后以其独立摘要批准回滚授权环境。不能重复使用部署审批。

最终 `p1-results` 制品提供预览、消费记录及 `summary.json`。必须确认 `realDocker`、`realMTLS`、`realGitHubOIDC` 与 `deployAndRollbackAuthorization` 为真，同时 `productDeploymentExecuted`、`productRollbackExecuted`、`productionReady` 为假。失败、超时或缺少真实审批不算端到端通过，不自动退款或重放授权；新的运行需要新请求和新审批。

测试中的 HTTP 桥在服务端仅转发固定 Docker GET 路径，包括三个受支持配置文件的只读 archive 路径。TLS 私钥和原始容器配置不进入测试制品。部署/回滚能力的当前限制见 [可信采集与授权](../../packs/deployment/docs/operations/DEPLOYMENT-RUNTIME.md)。
