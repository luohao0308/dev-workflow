# luohao-blog 生产前端接入

## 范围与当前事实

用户已授权使用既有 SSH 线上博客进行生产测试。先限定 frontend，同一当前镜像，保留真实 Config、HostConfig、单网络别名、无挂载和 unless-stopped/json-file 10m×3；后端自动迁移、数据库、Redis、ES、Caddy 及监控保持为受保护对象。

前后端真实健康检查和首页/API GET 已通过。现网 frontend 使用独立 hotfix 镜像与多份发布覆盖，不能用旧本地 Compose 文件覆盖。线上 Memory/MemorySwap/NanoCpus=0、PidsLimit=null。实验 recipe-v3 拒绝这些值，但真实 full-body mapper 可以表示；实际重建还受 sample-only HostConfig policy、生产 namespace/request 守卫及镜像默认值合并规则限制。

## 结果与顺序

1. 实现独立只读 frontend 配置适配与精确同镜像计划。在准确容器、镜像、来源、daemon/project、拓扑及外部快照摘要下保存完整配置，输出脱敏 review；明确不发行执行权限。用当前线上双采样数据验证，测试遗漏/null/空集合、继承和漂移，旧契约不放宽。
2. 接入独立生产登记、精确审批、范围排他和固定 worker。沿用原 Gate/签名见证/CAS，不能改 production=False 或伪装 dw- 项目。先提供可审核生产请求与不可变回退版本，再进入一次性执行。
3. 在真实业务窗口执行同镜像 frontend 替换和独立新审批回滚，核对 Caddy 解析、HTTP 业务响应以及其余十四个容器、卷、网络的保护投影。未知写入立即冻结，不能自动重试或重放。后端迁移和 owner 崩溃接管继续单列。

第一片已完成；当前已补齐第二片的审核工作流和控制器代码，原生生产 writer 接线继续待办。不能将只读计划、内容摘要或普通 SSH 权限当作已准入的生产执行能力。尚未进行生产容器创建、停止、删除、回滚或强杀。证据保持私有，本地旧博客工作目录的既有产品改动不触碰。

## 本轮实现与验证

新增 `deployment_compose_production_frontend_v3_host` 与 `deployment_compose_blog_frontend_preflight_v1_host`：固定只读 SSH 采集同一 frontend、校验独立 daemon/container/image/source pins，完整保留无限资源、重启和日志策略、网络别名及省略字段。私有输出限定外部新建目录，使用目录 FD 防止路径置换。网络静态请求、未知配置、错误镜像类型、暂停/重启/死亡基线均拒绝。镜像 ArgsEscaped 仅显式保留，实际重建仍待 Engine 验证。

新增 `deployment_compose_production_frontend_approval_v1_host`：独立 profile/audience、业务博客仓库及实际 authority ledger ID、运行时与业务源码 SHA 分别绑定，生成一次性 production=true 的精确 deploy 意图。首片明确拒绝 rollback/recovery 工厂和运行时 guard。它是审批 SDK；后续审核工作流代码已补齐，但尚未发布启用，生产 writer 继续待办；RSA/OIDC 测试的平台读写为替身，未在真实账本消费授权。

18 项新增测试和 32 项相关兼容测试在 Python 3.10 / 3.14 各通过，共每版 50 项。独立复审 CLEAR。真实 SSH 入口重验线上前端，生成同一 body digest，记录其余 14 个容器 ID；仅清单不等于它们完整配置/生命周期已获保护证明。Caddy upstream 为 frontend:3000，尚未执行切换。

只读调用：`python3 scripts/deployment_compose_blog_frontend_preflight_v1_host.py --pins /absolute/private/pins.json --output /absolute/private/new-directory`。路径须绝对且不含符号链接；输出目录必须新建且在源码树外。pins 精确字段为 hostId、daemonId、project、service、containerId、containerName、imageId、sourceSha。示例不提供任何执行开关。

后续是审核工作流发布启用、宿主登记/范围排他、跨项目且不要求 Health 的保护清单 guard，以及保留旧实例至新实例验证成功的操作顺序。不能沿用实验链先删除旧实例再验证 readiness 的顺序开展本次生产测试。

## 生产审核工作流与控制器

`production-frontend-review.yml` 固定 main 和 compose-review 环境，调用独立 production review contract，按已登记的 DW_PROD_FRONTEND_POLICY_HASH 重新生成精确请求。业务博客源码 SHA 和运行时工作流 SHA 分别绑定。公开摘要列出 production=true、准确宿主/daemon、当前容器、同镜像、其他容器 ID、有效期和执行缺口；不上传私有 create body。

控制器 `GitHubProductionFrontendReviewV1.request_prepared_review` 先核原私有计划、main 发布 SHA、受保护环境、分支政策和注册策略，然后只派发一次。固定 gh API 命令从 stdin 接收冻结的公开 payload，不按可替换路径重读文件。匹配唯一且准确的审核运行后，验证公开产物并在内存解密 OIDC；返回真实 approval/grant 给后续 worker，不自行消费账本。原实验派发/消费入口在新控制器上显式拒绝。未知派发结果不重试，已知 artifact 下载失败明确报错。

真实 CMS/RSA 回环以及 run/配置/回调漂移、错误 artifact、复制/线程/fork、跨请求混用、旧入口、重复派发及加密输出置换的回归通过。新增 18 项及相关 18 项，共 36 项在 Python 3.10 / 3.14 各通过；独立复审 CLEAR。GitHub/JWKS 为明确替身，未运行真实审批。

2026-11-10 的 GitHub 只读检查确认：main 尚无本工作流，compose-review 仅允许 feat/compose-validation-20261028，DW_PROD_FRONTEND_POLICY_HASH 尚未配置。审核环境的唯一 reviewer 为 84822776，prevent_self_review=true，禁止管理员绕过。main/分支政策/策略登记尚未满足，控制器应在 POST 前拒绝；本轮未修改这些远端设置。先完成宿主排他、保护对象 guard、保留旧实例的切换及失败恢复路径，再对具体的发布/配置步骤和精确业务请求进行实际审批。

本片不放开旧 production=False 守卫，不提供 rollback/recovery，不证明生产 writer 或部署/回滚链路已可用。证据见 [审核接线记录](../validation/BLOG-PRODUCTION-REVIEW-WIRING-2026-11-10.json)。

## 部署锁、全宿主保护与保留旧容器的切换（2026-11-11）

`deployment_compose_production_scope_v1_host` 在已登记的宿主私有目录中为每个 Compose 项目固定一份持久日志。执行器核对目录与日志 inode，取得 `flock` 后先同步写入启动记录。原执行线程完成终态核验后登记证明摘要，再释放锁。强杀会释放进程锁，未结束的记录仍会阻止新执行器。该机制覆盖使用同一登记的执行器，依赖可信的本地持久存储。

`ProductionFrontendProtectionV1` 复用原生 Docker 端点及双采样，要求原容器一直保留，新增项仅限创建回执登记的候选 ID。其他容器的配置摘要和生命周期记录、镜像库存、网络与卷配置、宿主网络投影必须一致。健康日志会滚动，因此比较不依赖健康日志。执行器仍需独立核对原容器与候选的阶段状态以及 Caddy 入口。

`prepare_retained_frontend_cutover` 生成同镜像切换计划。候选先以停止状态创建，随后停止原容器、保留改名后的原实例、为候选更名并启动。切换和恢复都拒绝把受保护容器 ID 当作候选。恢复计划按已确认的切换步数和候选运行状态生成，需要把实际候选 ID、现场状态和操作绑定进独立审批。现有审批仍只绑定重建计划，实际 worker 还需接入这些检查并绑定新切换摘要。

本地 Docker Desktop Engine 24.0.6 使用博客镜像内的诊断进程，在独立内部网络上完成三组演练。正常切换返回 200，故障候选返回 503，第三组在候选启动前停止切换。三组都保留并恢复原容器，探针均确认 `frontend` 只解析到预期实例，恢复后返回 200。每笔演练写入前均检查范围锁，事后核对本地资源清理。生产 Engine 29、实际 Nuxt/Caddy 路径和审批执行链仍需验收。

Python 3.10、3.14 与隔离 Linux Python 3.13 各通过 31 项定向测试，包含真实子进程竞争和强杀、范围日志故障、保护投影漂移与切换计划。独立复审通过。可在具备本地博客镜像的 Docker Desktop 上用 `python3 tests/support/compose_retained_frontend_local_fixture.py` 重跑三组演练。[演练记录](../validation/BLOG-RETAINED-FRONTEND-CUTOVER-2026-11-11.json)
