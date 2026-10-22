# 可信运行时采集与部署授权（P1-1/P1-3）

本阶段提供 `deployment_runtime.py` 采集 SDK、`deployment_authorize.py` 授权 SDK，以及分发目录中的 `scripts/deployment_host.py` GitHub Actions 授权宿主。P1-3 另提供 `deployment_spec.py` 可信规格和 `deployment_execute.py` 固定 Docker API 单组件替换后端，见 [部署执行](DEPLOYMENT-EXECUTION.md)。采集/授权本身不写 Docker，也不运行项目声明命令；本地 CLI 与授权结果的 `executionAvailable` 为 `false`，实际宿主执行后端可为 `true`。`productionReady` 为 `false`，健康、冒烟、备份保持 `unknown`；仅实际成功执行后才能报告对应部署/回滚已核验。离线计划与显式快照比较仍按 [部署计划](DEPLOYMENT-PLANNING.md) 工作，不因 SDK 存在而联网。

## 可信源码宿主

宿主从固定、已核验版本的完整分发源码加载 SDK，以 `python3 -I /固定可信路径/宿主入口.py` 启动；导入路径只指向该可信分发中的 `scripts`、`packs/deployment/scripts`、`packs/release/scripts`、`core/scripts`，不可由候选项目、当前目录、`PYTHONPATH` 或项目配置选择。`-I` 隔离导入环境，不替代可信源码与策略核验。候选仓库只是被检查的数据，不能成为宿主实现或插件来源。

GitHub 授权宿主复用完整可信分发的 release 基础模块；这是分发侧依赖。安装后的 deployment 包不依赖目标项目安装 release 包。宿主直接注入策略、TLS 材料和可信 catalog，测试 transport/verifier 注入也仅属于可信嵌入，不是本地扩展接口。执行时还须注入可信规格和独立 writer TLS 身份，并由服务端限制允许的写入路由及资源；客户端证书摘要绑定执行策略，不能把只读证书权限或客户端路由检查当成服务端授权。

本地 `deployment_runtime.py status/collect` 不接受 policy、证书路径或项目 adapter loader；`collect` 拒绝采集。`deployment_authorize.py status` 报告仅宿主授权模式，`authorize/execute` 默认拒绝。配置、安装、普通 push 权限和授权 JSON 均不能解除拒绝；缺少可信宿主时报告缺口，不回退到项目命令、SSH、Docker、kubectl 或云 CLI。

## P1-1：运行基线

`RuntimePolicy` 固定 HTTPS origin、服务端 DER 证书 SHA-256 pin、daemon ID、仓库 `owner/name`、环境、目标、production、Compose project、完整组件集合和可信 catalog。默认 observation 最大年龄 3600 秒、采集期限 30 秒；策略身份哈希绑定全部字段。

`DockerTLSClient` 使用显式 CA、客户端证书和私钥，校验主机名与服务端证书链，在发送 GET 前验证 peer pin。每轮读取 `/v1.45/info` 并校验 daemon ID；客户端只允许固定 `/v1.45` info、容器列表/inspect、镜像 inspect，以及固定 `/etc/hosts`、`/etc/hostname`、`/etc/resolv.conf` 的只读 archive GET 路由，不使用重定向、代理或环境凭据发现。部署方还必须为 reader 配置服务端强制 GET 路由白名单的 mTLS 网关/授权层；执行 writer 是另一独立身份，具体路由与范围见执行文档。客户端证书直接访问原始 Docker daemon 并不天然只读，客户端路由限制不能代替服务端权限约束。

Compose project/service labels 仅用于选择成员，不证明来源、版本或产物身份。每组件必须恰好一个 running、未 paused/restarting/dead 的容器；实际容器 `.Image` 必须等于镜像 inspect 的不可变 `Id`。可信 catalog 由宿主维护，schema v1 的每项绑定 component、imageId、repository、完整 sourceSha、语义版本、os、architecture、artifact 和 migration。实际平台必须匹配；local-build 的 imageId/buildSourceSha 必须匹配 catalog，registry 引用必须精确出现在实际 RepoDigests。来源 SHA 是可信 catalog 对实测镜像的绑定，不从 labels 或目标清单补造。缺失 catalog、未知来源或迁移不能借用目标值。

首个完整 profile 仅支持 Linux 容器（SDK 可跨平台连接远端 Linux Docker）、不可变镜像、`ReadonlyRootfs=true`、无 bind/volume/tmpfs 等挂载及其他镜像外配置依赖、无特权/设备/宿主 PID/IPC/网络/UTS 共享、无数据库、无需迁移的工作负载；catalog 必须显式声明 `migration.mode=none`。未知迁移或不支持的文件系统产生 `complete=false`，无可用 snapshot/授权；数据库、备份、恢复和迁移能力未由此交付。

这里的 complete 指受支持的 Docker 实例、声明配置和管理文件已完整采集，不验证应用内存缓存、远端配置服务或外部系统的数据。需要这些证据的工作负载不能仅凭本 profile 授权；宿主须另外补齐可信证据，当前无相应采集适配器。

在期限内进行两轮完整读取，包含两次 daemon 校验，结果必须相等。这证明两次读取稳定，不是跨 Docker API 的原子快照，不能排除读取之间变化后恢复。配置摘要为版本化 canonical 投影：`schemaVersion=2`、`kind=docker-container-configuration`、inspect 的 `Config`、`HostConfig`、`Path`、`Args`、实际网络连接和三个 Docker 管理文件的内容摘要。管理文件通过固定路径的只读 archive 获取，仅接受有大小上限的普通文件；不解压到宿主文件系统，也不把路径存在当作内容证明。未配置规格目录时保留此 observed-v2 行为。P1-3 的 `RuntimePolicy.specifications_json` 为可选 canonical 可信规格目录，并参与策略身份：启用后每个实测组件/镜像须匹配 `ContainerSpec`，snapshot 的 `configurationDigest` 使用受信 recipe 摘要。Docker 生成的 hostname、网络端点等不进入可重建 recipe 摘要；完整 observed-v2 原始配置投影仍独立进入 `state_hash`，不因 recipe 稳定而忽略实例或现场漂移。缺规格、配置不匹配或缺必要字段则采集不完整，无 snapshot/授权能力。

Env 等私密值参与哈希但不导出；完整规格目录和 `ContainerSpec.to_dict()` 含私密配置，仅供可信宿主内部使用，不写请求或审计。摘要不加密，仍需限制访问。输出不含原始 Env/Config/HostConfig、凭据、原始 API 响应或异常。

| 身份 | 含义 |
|---|---|
| `policy_hash` | 固定采集范围与可信策略 |
| `state_hash` | 全组件映射、完整原始配置投影、实例 container/image ID、启动时间、PID 等状态，重启或实测配置/网络变化也触发漂移 |
| `evidence_hash` | 本次 payload（含采集时间和 nonce）的身份 |
| snapshot `version` | `runtime-` 加完整组件映射哈希；全环境运行身份，非业务 release alias，不直接包含 PID/启动时间。observed-v2 配置变化可改变它；规格 profile 的生成配置变化由独立 `state_hash` 捕获 |

各组件语义版本另列于 observation，不拿目标业务标签冒充当前全局 runtime version。`RuntimeObservation.snapshot()` 仅对 complete 返回 schema-v1 快照。collector 在自身内存中保留签发对象；`validate` 验证对象身份、范围与新鲜度，`recheck` 重新采集并拒绝 state_hash 漂移，不更新已审核基线。`to_dict()` 导出 JSON 仅为证据副本，重建对象、文件或另一 collector 均不能恢复证明。

## P1-2：精确授权

`build_request` 先重新检查 prepared plan、仓库准确根目录、HEAD、配置、命令引用/cwd 和输入字节，再要求同一 collector 签发的新鲜完整 observation，覆盖配置环境的全部组件。计划基线的 runtime version、完整映射及输入 snapshot 必须与该 observation 一致。before/after 保留全部组件，未选择组件身份不变；当前 profile 拒绝需要备份或迁移的请求。

首次 after/目标清单是审核通过的期望声明，不是目标产物已验证或已运行证明。P1-3 执行器在 prepare 时核验预加载镜像与可信 recipe，执行后再采集全组件映射；授权成功本身仍不是 dispatch 或运行成功。回滚另需显式 `rollback_target`：同一 collector 在内存中保留、范围一致的完整历史 observation，签发顺序必须严格早于当前 observation 且不是同一个对象；历史目标可过新鲜期，当前基线必须新鲜。按当前基线重新规划，目标选中组件匹配该历史证明，不能简单反转旧 deploy permit，也不接受任意历史 JSON。

Request 固定 operation（`deployment-deploy` / `deployment-rollback`）、仓库路径/slug/ID、HEAD、配置哈希、环境/target/production、组件、完整 before/after、条件与证据、plan/observation/state/runtime policy 哈希、有效期和 `max_uses=1`。有效期不超过一小时；Grant/Receipt 必须为部署类型且匹配请求摘要、次数和期限。可选 `Request.execution_json` 绑定固定 profile、执行策略、intent、选中组件、镜像/规格摘要、旧实例、唯一资源名及固定操作顺序。`build_request(..., execution_intent=intent)` 与 `authorize(..., execution_intent=intent)` 必须使用同一执行器签发的对象；JSON 不提供签发权。`DeploymentHostPolicy.execution_policy_hash` 必须精确匹配执行策略哈希，未配置的 auth-only 宿主不能签发执行绑定。域为 `dev-workflow-deployment-authorization-v1`，GitHub audience 为 `dev-workflow-deployment-host`，grant namespace 为 `github-deployment`，独立账本 namespace 为 `workflow-deployment-grants`；release 请求、审批和凭据不能跨域使用。

`DeploymentHostPolicy.environment` 是签名 OIDC 调用者环境，`approval_environment` 是受保护人工审核环境；两者可相同，也可分开以便只读 observer 持续运行并保留历史。部署环境/target/production、runtime policy hash、允许组件另行固定。宿主核验 OIDC 签名/issuer/audience/subject、仓库身份、workflow ref/SHA、run ID、首次 attempt、调用者环境与 actor；运行须为进行中的 workflow_dispatch。受保护审核环境、reviewer ID、自审规则和禁止管理员绕过规则必须匹配，审批评论精确为 `dev-workflow approve <bundle_hash>`。bundle 摘要绑定全部宿主策略上下文、请求集合和到期时间，不能只审目标业务版本或另一环境的审批。沿用用户已有明确授权，不重复索要相同权限；对话授权不替代这些宿主核验。

`authorize` 在消耗前和返回 permit 前重核项目/计划、现场 observation 与宿主权限；完成远端权限查询后，紧邻账本 CAS 再执行运行状态和项目 guard。dispatch claim 的最后一次现场读取后再检查项目/计划。跨 Git、Docker 和 GitHub 的检查仍不构成原子事务，固定执行器在每次写入前核对预期中间态、完整项目 inventory 和未选中实例；这些检查仍不是分布式事务，唯一资源名也不是可重试的幂等令牌。宿主在目标项目之外的可信账本，以只允许不存在时创建 ref 的 CAS 语义记录一次消耗；重复、响应丢失或结果未知均按次数已消耗处理，停止，不退款、不自动重试/恢复。消耗后漂移也不恢复次数。最终 guard 再验证实时授权和账本；进程内 `DeploymentPermit.claim_for_dispatch()` 仅允许一次 claim，固定执行器在生命周期锁内调用它。执行绑定 permit claim 后，`guard_for_execution(runtime_check=...)` 在每次写入前验证授权、预期中间态和项目/计划；旧 auth-only permit 即使已 claim 也被拒绝。任何不确定调度须先核对现场和账本，再另行构建新请求，不能从旧文件自动续跑。普通 collector 不接受创建后双实例、旧实例停止或缺失等中间态；在现场恢复为完整受支持状态前，不能通过普通回滚授权绕过阻塞，后续恢复契约留待 P1-5。

本机审计保存于 Git 忽略且无已跟踪内容的 `.dev-workflow/releases/deployments/`，POSIX 文件权限为 `0600`；Windows 的 `chmod` 不提供同等 ACL 隔离，嵌入宿主须提供受控目录权限。首个 GitHub 授权宿主仍运行于 Linux。JSON、Receipt 导出和 `authorizationConsumed=true` 只说明审计/消耗结果，不是可加载的执行 capability，也不是部署成功证明。

## 验收边界

mock/单元测试只能证明相应 SDK 分支。真实 Docker + 服务端 GET-only mTLS 网关、GitHub OIDC/受保护审批及账本的端到端验收须另附独立环境证据；本文不声明这些真实验收已完成。授权成功仍不是部署执行证据。实际执行结果与进程内 observation 的使用见执行文档；健康/冒烟及生产就绪结论不由该后端提供。历史 P1-1/P1-2 验证记录保持原义，P1-3 独立验证指引见分发仓库 `tests/support/P13-EXECUTION-VALIDATION.md`，不据此声明验收已完成。
