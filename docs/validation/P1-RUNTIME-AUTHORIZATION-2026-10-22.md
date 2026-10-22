# P1-1 / P1-2 验证记录（2026-10-22）

本次实现真实运行状态采集和部署/回滚专用授权。dev-workflow 工作分支为 `codex/p1-runtime-authorization`，基于 v0.10.0 的 `f8558e76cc98d2c43e5091dced6b8a04e42c9a44`；源码改动尚未提交、推送或发布。未操作 luohao-blog。

## 交付内容

- deployment 可选包新增 `deployment_runtime.py` 与 `deployment_authorize.py`。Linux Docker 现场采集校验 mTLS、证书 pin、daemon、实际镜像/平台及宿主可信制品目录；配置摘要包含三个 Docker 管理文件和实际网络，不把目标清单当成现场证明。
- 完整支持范围为只读根文件系统、无额外挂载、无特权/设备/宿主 PID/IPC/网络/UTS 共享、明确无迁移的 Linux 容器。未知来源、配置或迁移阻断授权。两轮采集检查稳定性，返回的 JSON 不能恢复进程内签发证明。
- 部署与回滚有独立 Request/Grant/Receipt、域、OIDC audience 和 `workflow-deployment-grants` 账本。请求绑定完整前后状态、组件范围、仓库/配置、环境、目标和有效期；一次消费、CAS 前后实时检查，未知结果不自动退款或重试。
- 回滚需要同一 collector 严格较早签发的历史对象和新鲜当前基线。签发序号避免 Windows 低分辨率时钟把两次合法采集误判为同一时刻。
- 分发侧 `scripts/deployment_host.py` 提供固定可信源码的 GitHub Actions 授权宿主；安装 deployment 包无需安装 release 包。Core 仅更新能力边界说明，继续复用通用生命周期锁。workflow-deploy Skill 保留离线语义并说明可信宿主路由。

## 本机验证

- 全量 Python：428 项，418 通过、10 项按既有平台条件跳过。
- 最终运行时/授权/宿主专项：121 项全部通过，包含本机真实回环 mTLS、跨域拒绝、过期、状态漂移、一次性消费、回滚历史及并发 claim。
- Bash 集成、Bash 语法、全源码 Python AST、Skill 校验通过。
- 独立复审发现的配置采集、CAS 时序、历史先后和隔离 profile 问题已修复；补充复审通过。Skill 三项独立行为推演通过。

## 独立真实环境

[端到端工作流 39733263750](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39733263750) 全部 4 个 job 成功。可信测试宿主源码提交为 `710b61c040e8e789b7d66bd24fb102193056661b`；目标为独立合成仓库 `luohao0308/dev-workflow-p0-target-20261022`，环境 `staging`、target `p1-isolated`，production=false。

1. 根据两个真实提交构建合成镜像：v1 为 `fc006bc3d2bc968aec73ee7059e596c01b778a2a`，v2 为 `4efeab8b9c11c3f4ff366cd4c893b470d19bba12`。初始 web/api 均为 v1。
2. 通过服务端 GET-only mTLS 桥采集真实 Docker 状态；共 408 次 GET，校验客户端证书和服务端 pin，错误 pin、重建 observation 均被拒绝。
3. 部署请求仅选择 web v1→v2，api 不变。用户审核精确摘要后明确委托登记 `p1-deploy-approval` 审批，实际通过 GitHub OIDC、审批 API 与账本 CAS 消费一次；重复 claim/消费被拒绝。
4. 测试夹具单独切换合成 web 容器。产品 SDK 没有执行部署。实测新基线保留 api 的旧来源 SHA、web 的新来源 SHA，并拒绝继续使用旧基线。
5. 基于新鲜当前状态和同一 collector 保留的旧历史构建独立回滚请求。用户再次明确委托登记 `p1-rollback-approval` 的精确摘要，回滚授权独立消费一次；没有产品回滚执行。

两次审核均为用户明确授权后的**委托登记**，不宣称用户亲自在 GitHub 点击。真实测试制品 `p1-results` 包含 `summary.json`、两个预览和两个消费结果。两个消费结果均为 `status=consumed-verified`、`useNumber=1`、`execution=not-performed`。

| 操作 | 精确审核 bundle 摘要 |
|---|---|
| deployment-deploy | `854ae09d91351809a6806e456914e202ee7034ee32baddcd838b3c5f309b6594` |
| deployment-rollback | `63159828fbd4d27e12d73e0de5daa6bd37e9da8c89688a6b401519e142ec2b74` |

两个独立账本 ref 均位于测试宿主的 `refs/tags/workflow-deployment-grants/39733263750/<bundle>/<operation>`，指向上述可信宿主提交。它们是授权账本记录，不是 dev-workflow 发行 Tag。

早期真实验证因两个审批同时等待、workflow 状态为 waiting 被拒绝，未消费授权；测试工作流改成生成回滚预览后才启动回滚审批，没有放宽宿主必须 in_progress 的检查。后续使用新请求、新摘要及新审批完成验证，未复用旧审批。

## 跨平台 CI

[最终源码镜像 CI 39733219033](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39733219033) 对上述可信宿主提交运行完整矩阵：Ubuntu/macOS × Python 3.10/3.13，以及 Windows Python 3.10 + 原生 PowerShell。**五组全部通过（5/5）**，包含 Windows Python 工具测试和原生 PowerShell 集成。Windows Python 共 348 项，340 通过、8 项按既有平台条件跳过。可执行 Python 源码与该 CI 镜像逐文件一致；验证记录和边界说明在验收后补充。

## 当前边界

`executionAvailable=false`、`productionReady=false`。没有交付真实部署/回滚执行器、健康/业务冒烟、数据库迁移、备份恢复、流量切换、持久化历史恢复或不确定执行后的自动续跑。目标清单仍是审核过的期望声明；实际产物与调度由后续 P1-3 执行器核验。

当前配置摘要包含实测 Docker 管理文件与网络身份；这些生成值变化会改变运行身份，不能把它当成可直接用于重建容器的完整配置或业务版本。两轮采集不是跨 Docker/Git/GitHub 的原子事务。历史证明仅在本次可信宿主进程内保留；重启后不能加载 JSON 续用。

首个授权宿主为 Linux Actions。SDK 的 Windows 兼容测试不代表原生 Windows 容器已支持；Windows 审计目录的 ACL 也须由宿主管理。复现步骤见 [独立测试说明](../../tests/support/P1-RUNTIME-VALIDATION.md)，接口及限制见 [运行时与授权](../../packs/deployment/docs/operations/DEPLOYMENT-RUNTIME.md)。
