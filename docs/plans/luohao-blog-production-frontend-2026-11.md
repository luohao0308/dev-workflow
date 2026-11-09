# luohao-blog 生产前端接入

## 范围与当前事实

用户已授权使用既有 SSH 线上博客进行生产测试。先限定 frontend，同一当前镜像，保留真实 Config、HostConfig、单网络别名、无挂载和 unless-stopped/json-file 10m×3；后端自动迁移、数据库、Redis、ES、Caddy 及监控保持为受保护对象。

前后端真实健康检查和首页/API GET 已通过。现网 frontend 使用独立 hotfix 镜像与多份发布覆盖，不能用旧本地 Compose 文件覆盖。线上 Memory/MemorySwap/NanoCpus=0、PidsLimit=null。实验 recipe-v3 拒绝这些值，但真实 full-body mapper 可以表示；实际重建还受 sample-only HostConfig policy、生产 namespace/request 守卫及镜像默认值合并规则限制。

## 结果与顺序

1. 实现独立只读 frontend 配置适配与精确同镜像计划。在准确容器、镜像、来源、daemon/project、拓扑及外部快照摘要下保存完整配置，输出脱敏 review；明确不发行执行权限。用当前线上双采样数据验证，测试遗漏/null/空集合、继承和漂移，旧契约不放宽。
2. 接入独立生产登记、精确审批、范围排他和固定 worker。沿用原 Gate/签名见证/CAS，不能改 production=False 或伪装 dw- 项目。先提供可审核生产请求与不可变回退版本，再进入一次性执行。
3. 在真实业务窗口执行同镜像 frontend 替换和独立新审批回滚，核对 Caddy 解析、HTTP 业务响应以及其余十四个容器、卷、网络的保护投影。未知写入立即冻结，不能自动重试或重放。后端迁移和 owner 崩溃接管继续单列。

第一片为当前实施范围。不能将只读计划、内容摘要或普通 SSH 权限当作已准入的生产执行能力。尚未进行生产容器创建、停止、删除、回滚或强杀。证据保持私有，本地旧博客工作目录的既有产品改动不触碰。

## 本轮实现与验证

新增 `deployment_compose_production_frontend_v3_host` 与 `deployment_compose_blog_frontend_preflight_v1_host`：固定只读 SSH 采集同一 frontend、校验独立 daemon/container/image/source pins，完整保留无限资源、重启和日志策略、网络别名及省略字段。私有输出限定外部新建目录，使用目录 FD 防止路径置换。网络静态请求、未知配置、错误镜像类型、暂停/重启/死亡基线均拒绝。镜像 ArgsEscaped 仅显式保留，实际重建仍待 Engine 验证。

新增 `deployment_compose_production_frontend_approval_v1_host`：独立 profile/audience、业务博客仓库及实际 authority ledger ID、运行时与业务源码 SHA 分别绑定，生成一次性 production=true 的精确 deploy 意图。首片明确拒绝 rollback/recovery 工厂和运行时 guard。它是审批 SDK，尚无可用 production 审核工作流或生产 writer；RSA/OIDC 测试的平台读写为替身，未在真实账本消费授权。

18 项新增测试和 32 项相关兼容测试在 Python 3.10 / 3.14 各通过，共每版 50 项。独立复审 CLEAR。真实 SSH 入口重验线上前端，生成同一 body digest，记录其余 14 个容器 ID；仅清单不等于它们完整配置/生命周期已获保护证明。Caddy upstream 为 frontend:3000，尚未执行切换。

只读调用：`python3 scripts/deployment_compose_blog_frontend_preflight_v1_host.py --pins /absolute/private/pins.json --output /absolute/private/new-directory`。路径须绝对且不含符号链接；输出目录必须新建且在源码树外。pins 精确字段为 hostId、daemonId、project、service、containerId、containerName、imageId、sourceSha。示例不提供任何执行开关。

后续是独立审核工作流、宿主登记/范围排他、跨项目且不要求 Health 的保护清单 guard，以及保留旧实例至新实例验证成功的操作顺序。不能沿用实验链先删除旧实例再验证 readiness 的顺序开展本次生产测试。
