# P1-5 持久化和中断恢复：独立验证记录

日期：2026-10-23（北京时间）。仅修改 dev-workflow，使用独立合成测试仓库；未操作 luohao-blog，未创建功能 PR、合并这些功能或发布正式版本。

## 交付范围

- deployment 可选包：签名持久化历史、独立历史 capability、签名操作日志、精确写入 admission／完成证明、受限恢复状态表和独立恢复请求／grant／receipt。
- 固定分发宿主：mTLS／本机 Unix Docker 网关，以及独立 GitHub 恢复授权适配器。候选项目不能加载插件、任意执行器或环境凭据。
- Core：仅增加可选 `LifecycleLock.expected_owner`，在恢复 guard 内删除旧锁前重新比较完整 owner；不改变未启用此参数时的默认接口。
- workflow-deploy Skill：说明可选健康验收、持久化历史和独立恢复授权路径，缺少宿主时继续离线规划。

P1-4 已另有实际部署、健康／业务验收和独立回滚证据，见 [P1-4 记录](P1-4-DEPLOYMENT-VERIFICATION-2026-10-23.md)。

## 实际 Docker 崩溃恢复

测试源码镜像：`8653c3cb9b023040e515b8b2df892a3f3dfca758`，独立验证仓库分支 `codex/p15-recovery-validation`。本地 27 个产品／Core／宿主 Python 文件和 45 个 Python 测试文件与该镜像逐字节一致。

完整验证运行：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39831567356 。两个实际 Docker smoke job 已成功：

1. 真实子进程在 create 的上游完整响应之后、观察者持久化响应之前硬退出；父网关继续运行，新观察者证明排空，删除准确停止态候选，恢复原完整 v1 映射。
2. 真实子进程在删除原实例后同样硬退出；恢复依次清理准确候选、按保留的旧配方重建、启动并检查 v1。

使用真实 mTLS 和本机 Unix Docker API，遗留 Core owner 属于真实已退出子进程，未以测试 liveness oracle 代替此项证明。两种 smoke 的原部署和恢复均使用明确的合成授权，不宣称是真实 GitHub 审批。未选中 api 的原实例保持不变，v1 健康与业务响应通过。

## 实际 GitHub 恢复授权

运行：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39831924284 。观察任务和恢复审批任务均成功；未启用的矩阵任务按配置跳过。

- 目标：`luohao0308/dev-workflow-p0-target-20261022`，数值仓库 ID `1428943581`，staging / p1-isolated，非 production，仅 web。
- 原始测试部署使用合成授权，子进程按计划在原 v1 删除后崩溃；本次单独验证真实 GitHub 恢复授权。
- 用户明确委托登记精确审批，环境 `p15-recovery-approval`，摘要 `6be04487e984073520afb4865553434af4c78ef22c8cfbd1cef195e693fbe038`，部署审批记录 ID `7260303678`。如实记为委托登记，不宣称用户亲自点击。
- 恢复请求独立 audience 为 `dev-workflow-deployment-recovery-host`，使用 `workflow-recovery-grants` 一次性账本；不复用 P1-4 的部署或回滚审批。
- 准确动作：删除停止态候选 `5b9e969425a395e5f9c85a7988bda214c9edc521d8723a52e681015d4183f2c4`；创建并启动固定恢复资源 `dev-workflow-recover-74c1be9835da8a26314c38c94aa8674f00819cd8caa05ef70b8a76635c387e62`。

最终制品 `p15-recovery-results`：`recovered-runtime-verified`，health/smoke 均 passed、HTTP 200、一次通过；旧完整版本映射恢复，api 原实例保留，真实旧进程锁已回收；相同恢复请求重放被拒绝，`productionReady=false`。

## 审查和回归修复

架构审查结论 CLEAR；代码审查发现最终 guard 后请求头生成仍可能等待文件锁，已将全部 header／文件系统准备移到最后 guard 之前。回归先复现“过期后仍有一次写入”，修复后零写入、failed/not-performed；独立复审 APPROVE。

真实 Docker 首次启动会补全准确容器的三个管理文件路径，并在 `OomKillDisable=false/null` 等价默认值之间规范化。原始过严校验误判漂移；修复只接受这些明确变化，其余 HostConfig、配置、实例身份、可信规格和完整未选中状态仍校验。真实环境的 false→null 情况、错误路径、配置修改及已启动实例路径变化均有回归覆盖。

另外验证截断上游响应、未知／进行中 admission、重复写入、错误证书／body/path、签名篡改、错误密钥、目录／mutex 身份替换、历史副本伪造、catalog／配方移除、Core owner 替换及独立授权域拒绝。上游结果未知时，即使现场稳定或进程已死也不能自动排空。

本地部署相关单元测试 332 项通过，1 项 Windows 专用测试在 macOS 跳过；新增的两项最终修复回归单独通过。Bash 安装／升级集成通过；13 个产品和宿主文件通过 Python 3.10 语法检查，包内无字节码缓存。Skill quick_validate 通过；独立三案推演正确要求新的回滚授权、拒绝未知上游恢复、拒绝把历史 JSON 当当前基线。

Windows 首轮的 4 个竞争测试只接受“替换成功后网关拒绝”，未涵盖 Windows 系统拒绝替换打开句柄的安全结果。修正后的断言同时要求实际系统拒绝、原签名存储保持有效、原操作的证明可验证；若替换成功，则仍须拒绝发放 capability。没有通过跳过这四项测试来掩盖问题。

Windows 专项运行 https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39834380582 已成功：44 项中 39 项通过、5 项平台限定测试跳过，四个跨平台竞争场景均实际执行并通过。最终完整矩阵使用测试修正后的 `fc9e93f2d2a57e606ea993aec814212240078ccb`，产品 Python 与真实恢复运行的 `8653c3c` 完全一致：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39834813660 。最终运行 success，7 个实际运行 job 全部成功：Linux/macOS × Python 3.10/3.13、Windows 全量 Python 与 PowerShell 集成，以及两组真实 Docker 崩溃恢复。未启用的真实审批 job 按该矩阵配置跳过；真实审批由独立运行 39831924284 证明。Windows Python 共 544 项：525 项通过、19 项平台／依赖条件限定跳过；随后 PowerShell 集成明确输出通过。

## 保留限制

首版是单宿主、共享本地私有文件系统和固定 Linux Docker 无状态只读单组件规格，不是多宿主 HA、Windows 容器部署、数据库／备份恢复、生产验收或切流系统。Windows ACL 须由宿主部署；HMAC 不防持钥管理员回滚整个可信存储。

中断操作须保留原 coordinator 策略；未知上游完成、未知锁／外来资源、缺旧配方或不支持中断状态均阻塞。恢复在“候选已清理、旧实例尚未创建”的空选中状态再次崩溃，目前仍不自动恢复。未启用可选策略时不自动开启这些能力，也不为旧 P1-3 中断现场补造签名日志。无生产就绪声明。
