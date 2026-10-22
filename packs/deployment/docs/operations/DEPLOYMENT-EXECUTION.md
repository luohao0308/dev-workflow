# 固定 Docker API 部署与回滚（P1-3）

首个实际执行后端是 `deployment_execute.py` 的 `docker-container-replace-v1`，每次仅替换一个选中组件，保留环境内其余组件的完整映射与实例。它由固定可信源码宿主嵌入，不是项目命令执行器。离线 CLI 仍返回 `executionAvailable: false` 并拒绝执行；只有实际配置的可信宿主能调用 SDK，实际后端结果可为 `executionAvailable: true`。`productionReady` 始终为 `false`，健康/业务冒烟为 `unknown`。

## 支持范围与可信规格

镜像须已预加载于固定 Linux Docker daemon，以不可变 image ID 和可信来源 catalog 绑定；registry artifact 还须匹配实测 RepoDigests。后端不 build、pull 或发布镜像。`ContainerSpec.from_image()` 从实测镜像构建受信 recipe，宿主私下保留 image/spec catalog；候选项目不能提供宿主代码、插件或任意 create 参数。

规格要求数字非 root 用户、只读根文件系统、`CapDrop=ALL`、`no-new-privileges`、无自动重启、无 bind/volume/tmpfs、设备、特权或宿主命名空间共享。拒绝镜像隐含 volumes、healthcheck 等不支持的继承项。网络限受支持的既有模式；不创建网络。端口仅允许显式静态 IPv4/非零固定端口，启动后核对实际映射；端口占用仍可能使启动失败。daemon 版本、主机防火墙和网络暴露安全不在此 profile 的保证内，API v1.45 不代表 daemon 的具体网络安全行为。

`RuntimePolicy.specifications_json` 可选；为 `None` 时维持原 observed-v2 采集行为，但不能用于此执行后端。启用后，snapshot 的 `configurationDigest` 是版本化完整可信 recipe 摘要，实测配置须匹配它。Docker 生成的 hostname、端点/IP 和管理文件不进入可重建 recipe 摘要；原始完整配置投影、网络、管理文件摘要及实例身份仍进入独立 `state_hash`，现场漂移不会因 recipe 摘要相等而消失。

完整 `ContainerSpec.to_dict()`、Config/HostConfig 与私密 Env 仅供宿主内部使用，不能导出到请求、审计或制品。请求仅绑定规格摘要等标量身份；哈希不加密，应限制证据访问。

## 宿主、TLS 与精确授权

宿主加载完整可信分发，遵守 [采集与授权契约](DEPLOYMENT-RUNTIME.md)。显式注入 reader 的 CA/证书/私钥、`RuntimePolicy`、collector，以及另一独立 writer 身份。`ExecutionPolicy(runtime_policy, writer_certificate_sha256, stop_timeout=10, execution_deadline=180)` 的身份绑定 profile、完整采集策略、writer DER 证书 SHA-256 与时间预算。`DockerMutationClient` 核验自身证书摘要、服务端 CA/主机名及服务端 DER pin，TLS 连接验证后、紧邻写入前执行 guard。

服务端必须按 reader/writer 证书身份分别限制路由、project、选中组件与准确容器资源：reader 只允许固定 GET；writer 仅允许下表四种变更及受限 create 内容。客户端限制与证书 pin 不能替代服务端授权；原始 daemon 的客户端证书通常不是细粒度权限边界。writer 不能获得 exec、build、pull、volume、network、其他组件或任意容器的写入权。stop 请求超时应大于 stop 等待预算，并处于整体 deadline 内；不确定响应不得重试。

受信宿主在同一进程中按顺序使用：

1. 从 collector 取得新鲜完整 observation，按它的 snapshot 生成并检查计划。
2. 调用 `DockerExecutor(policy, client, collector).prepare(root, plan, operation, observation=observation, rollback_target=history)`；部署省略 history，回滚传入同一 collector 签发的较早完整证明。prepare 校验恰好一个选中组件、镜像、规格与完整现场，返回仅该执行器认可的 `ExecutionIntent`。
3. 将同一 `execution_intent=intent` 传给 `build_request()` 与 `authorize()`。可选 `Request.execution_json` 冻结 profile、policyHash、intentId、specHash、component、imageId、beforeContainerId、唯一 resourceName 和固定 actions；`DeploymentHostPolicy.execution_policy_hash` 必须匹配 `ExecutionPolicy.identity_hash()`。未绑定执行的旧 auth-only 请求/permit，即使已 claim，也不能执行。
4. GitHub 宿主核验签名 OIDC、精确 bundle 的受保护环境审批和一次性 CAS 账本，再返回 permit。沿用用户已有明确授权，不重复询问；新精确 scope/bundle 需要新的审批，不能复用 P1-2 或部署时的旧审批。
5. 调用 `executor.execute(root, permit, intent)`。生命周期锁内先持久化私有审计，再一次 claim；每次写入前经 `guard_for_execution(runtime_check=...)` 核对授权、预期中间态、daemon、完整 inventory、未选中实例与项目/计划。跨系统检查不是原子事务。

本地 `deployment_execute.py status/execute` 不加载 policy、证书、宿主 shell、插件或环境凭据；`execute` 默认拒绝。缺可信执行 profile 时保留计划并报告缺口，不能回退到 Docker CLI、SSH、Compose、kubectl、云 CLI 或项目声明命令。

## 固定替换顺序

| 顺序 | Docker API v1.45 | 核验与限制 |
|---|---|---|
| 1 | `POST /containers/create?name=dwf-<intentId>` | 创建停止态新容器，期望 201；核验准确新 ID、规格、执行 labels 与唯一名称 |
| 2 | `POST /containers/<oldId>/stop?t=N` | 只停止准确旧 ID，期望 204 |
| 3 | `DELETE /containers/<oldId>?force=false&v=false` | 只删除已停止旧容器，期望 204；规格只读且无 volumes，不删除持久卷 |
| 4 | `POST /containers/<newId>/start` | 只启动准确新 ID，期望 204；复采完整环境并核对实际端口映射 |

表中路径均带 `/v1.45` 前缀。304 不视为本次成功完成转换。唯一资源名用于定位和核对，不是幂等令牌。先创建停止态容器可在停止旧实例前核验配置，但不保证后续启动成功，也不提供零停机、readiness 或流量切换。唯一名称不保留原容器名、Compose 名称或 service-DNS 连续性；Compose labels 仅用于成员选择，不提供 endpoint alias。

删除旧容器后，其实例 ID、元数据和容器日志不作为可恢复对象保留；`v=false` 也不保留这些内容。回滚保留的是旧镜像、可信规格/catalog 以及 collector 进程内历史 observation，重新创建等价规格的新实例。

## 成功结果与回滚能力

成功结果 `status: executed-verified` 表示新鲜采集的完整组件映射等于请求 after，未选中实例保持不变。分别记录业务声明 `declaredVersion` 与实际 `runtimeVersion`；后端比较完整组件映射，原规划器 `compare` 仍严格比较全局 version alias，行为不变。runtime 核验不代表业务可用、健康、冒烟、备份或生产就绪。

SDK 成功返回的 `observation` 是同一 collector 签发的进程内宿主 capability。调用者须在 JSON 序列化前取出并保留它：

```python
result = executor.execute(root, permit, intent)
observation = result.pop('observation', None)
# result 可导出；observation 留在同一可信进程内供新请求使用。
```

磁盘审计只含 `runtimeObservation` JSON 证据，不含 capability。不能以导出 JSON、重建 dataclass、另一 collector 或重启进程恢复 observation、intent 或 permit。

真正回滚从新鲜完整当前 observation 重新规划，以同一 collector 保留的较早 observation 为历史目标，重新 prepare、新建精确请求并取得新 grant。旧历史可超过新鲜期，当前基线不可以；不反转旧 permit，不重启被删除的旧容器。旧镜像/规格仍须可用并通过实测核验。

## 失败与未交付边界

HTTP 错误、超时、漂移、guard 失败或结果未知立即停止。结果区分 `failed`、`unknown`、`executed-unverified`，审计记录 lastAction、尝试状态、唯一资源名及已知 ID；已发生写入不宣称未执行。写入尝试或不确定结果要求核对现场，不自动 retry、cleanup、rollback、退款、恢复或重放。

创建后双实例、旧容器停止或删除后新容器未运行等中间态，会使普通 collector 返回不完整。此时不能用普通新授权“直接回滚”；须先核对并协调现场至可证明的完整状态，中断恢复契约留待 P1-5。当前没有 JSON 恢复或进程重启续跑机制。

本 profile 不交付生产部署验收、切流、数据库、备份/恢复、迁移、健康/业务 smoke probes 或 readiness。合成 Docker smoke 中的假授权不是 GitHub 证明；真实 OIDC、两道独立精确审批门与实际部署/回滚须另有独立环境证据。本文描述接口和限制，不声明测试已完成。
