# 发布执行集成契约（S5 基础）

此版本提供 Python 3.10+ 标准库执行基础，供受信宿主在同一进程内注入授权服务与远端 provider。**未交付生产适配器**：分发 CLI 与 `workflow-release` 仅准备，不能执行真实发布。此基础不构成生产发布就绪声明，也不执行包/镜像发布、部署、迁移或线上验证。原有 `release_prepare.py` 保持只读及兼容。

## 分发 CLI

在安装 release 包的项目中运行：

```sh
python3 scripts/release_execute.py status
python3 scripts/release_execute.py plan --repo . --preparation .dev-workflow/releases/prepared.json
python3 scripts/release_execute.py plan --repo . --preparation .dev-workflow/releases/prepared.json --remote origin --release-spec .dev-workflow/releases/release-spec.json --output .dev-workflow/releases/execution.json
```

`status` 输出 JSON，`executionAvailable` 为 `false`。`plan` 默认只打印 JSON；`--output` 才保存到仓库 `.dev-workflow/releases/` 下的新文件，不覆盖已有文件；写入前要求准确输出路径被 Git 忽略，且整个 `.dev-workflow/` 没有已跟踪文件。准备记录、Release 内容、notes 和其他本机输出只在用户明确要求时写入。`--release-spec` 是待发布内容，不是授权文件。

`plan` 重新检查准备记录、HEAD、目标提交、配置及本地 tag，并固定 remote 名称和 URL。它不连接远端，不证明远端 tag/Release 状态或凭据可用。`execute` 固定拒绝，在任何仓库读取、网络访问或变更前退出；提供路径、JSON、环境变量、TTY 确认或已有普通 push 权限都不能放行。不得加载项目提供的 provider 路径或临时自制执行适配器绕过该边界，也不得改用直接 Git/托管平台命令完成被阻止的发布。

准备记录重验沿用离线检查限制：禁用 fsmonitor、交互凭据提示与按需对象获取，并拒绝 partial-clone/promisor 配置键（包括 false 值）、submodule/gitlink 和启用内容 filter 属性的工作树。执行基础的 Git helper 同样禁用这些隐式行为，并保留空 hooks 目录；受信宿主显式授权后的远端 provider 传输仍由宿主负责。

## Release 内容与计划

`--release-spec` 必须是仅含以下字段的 JSON 对象；它把 Release 内容固定到准确仓库身份，不可用任意 endpoint 或仓库代替：

```json
{
  "endpoint": "https://api.github.com",
  "repository": "OWNER/REPO",
  "repositoryId": 123,
  "name": "Release 1.2.0",
  "body": "已核实的发布说明",
  "draft": true,
  "prerelease": false
}
```

`repositoryId` 为正整数，`name` 为非空字符串，`body` 为字符串，`draft` 与 `prerelease` 为布尔值。remote 仅支持规范的 GitHub HTTPS、SSH 或 scp 形式，fetch/push 必须是同一个 URL；spec 仓库名称必须匹配 remote。provider 还须验证远端仓库 ID。不会生成 notes，也不隐式改变 latest（provider 使用 `make_latest=false`）。

执行计划为 `schemaVersion: 1`、`kind: release-execution-plan`，包含 `repository`、`preparation`、`remote`（`name`/`url`/`repository` 或 null）、`tagObjectSha`（目标准确 commit）、`release`（spec 或 null）及 `requiresTrustedHost: true`。它保存意图，不证明远端状态或授权。

## 三个独立操作

| 操作 | 可变更对象 | 边界 |
| --- | --- | --- |
| `local-tag-create` | 本地 `refs/tags/<tag>` | 只创建不存在的 lightweight tag；同一 raw object 为 no-op |
| `remote-tag-push` | 指定远端的准确 tag ref | 不包含分支 push、强推、移动或删除 tag |
| `remote-release-create` | 指定仓库中准确内容的 Release | 独立于 tag push；不自动授予或执行 tag push |

`none`、`commit-sha`、`semver-tag` 保持可选策略；普通 push 不要求 tag。没有准备出的 tag 时，不凭空选择 SemVer 或创建 tag。现有准备入口允许同名 annotated tag 指向同一提交；执行基础要求 raw object 等于目标 commit，拒绝 annotated tag，即使它 peel 后是同一提交。不同对象的同名 ref 是冲突，永不移动或删除。

## 宿主权威与 provider 边界

宿主负责认证人工同意，并在项目数据之外维护权威授权账本。每次变更前，宿主必须验证并原子消耗准确操作的授权，绑定仓库身份、准备意图、HEAD/目标 SHA、配置、tag raw object、remote 名称与 URL、Release 内容摘要、有效期和最大使用次数。消耗必须先于变更；失败尝试不退还次数。过期、耗尽、漂移、缺失或无法验证时拒绝。

本地 `.dev-workflow/` 计划和审计记录只保存意图及观察结果，不是授权源，不续期、不补发、不重置消耗次数。`approvedBy: user` 等用户 JSON 声明、环境变量或命令行开关不能替代受信宿主入口。这个 SDK 是进程内集成接口，不是任意同进程 Python 代码的安全沙箱。

宿主入口为 `build_plan(root, preparation, *, remote=None, release=None)` 和 `execute(root, plan, operation, *, approval=None, tag_provider=None, release_provider=None)`。`approval.validate(request)` 返回带 `grant_id`、`request_hash`、`expires_at`、`max_uses` 的 Grant；`approval.consume(grant, request)` 原子消耗并返回含 `grant_id`、`request_hash`、`use_number`、`consumed_at` 的 Receipt。request 为冻结对象，绑定上述执行身份与计划摘要，`.digest()` 生成授权所需摘要。缺少受信宿主时保持拒绝，不用本机文件实现替代。

所有远端 Git 与 Release 访问由宿主注入 provider；provider 必须绑定预期 remote/repository 身份、准确对象和 Release payload，并负责传输真实性。tag provider 实现 `inspect(request)` 与 `push(request)`；Release provider 实现 `inspect(request)` 与 `create(request)`。检查必须返回实际观察，不把请求内容原样回显成证据；Release 创建前后还核对远端 tag。分发不内置生产 provider、凭据发现或模块/文件加载入口。SDK 在 provider 检查前及变更方法调用前重验 Grant；provider 若在内部排队、等待或重试，仍须在实际发出请求时通过宿主账本再次核对授权范围和有效期。SDK 无法消除方法调用后或 HTTP 在途期间的时序竞争，这属于未来生产适配器必须验证的边界。生产集成仍需宿主实现与独立验证，不能把测试 bare remote 或假平台当成生产适配器。

## 失败、恢复与证据

每个操作独立记录状态；本地 tag、远端 tag 和远端 Release 的成功不能互相推导。宿主调用执行即请求生成 `.dev-workflow/releases/execution-<UUID>.json` 审计记录；在消耗授权前，准确审计目标必须被 Git 忽略，且整个 `.dev-workflow/` 内不能有已跟踪文件。记录含 `createdAt`、`observedAt` 和明确的 `releasePayloadHash`；消耗后增加 `consumedAt`、`useNumber`。`phase` 区分 `pre-dispatch`、`dispatch`、`verification`，已存在的同对象可记为 `verified`；`failureCode` 使用有界分类，不写入原始 provider 异常或凭据。变更后必须通过 provider/本地读取确认准确身份。遇到响应丢失或超时，先只读核对实际对象；同对象已存在可报告 no-op，不再创建。核对无法完成时保持不确定，不盲目重试；需要新的变更尝试时重新取得有效授权，旧失败次数不退还。

准备意图、目标、配置、remote URL 或 Release 内容变化会使原计划/授权失效。消耗授权后、分发变更前检查到漂移时，正常异常路径将审计记为 `failed`，已消耗的次数仍然保留。恢复时重新读取当前状态并核对绑定，不从本地审计记录恢复权限。记录状态为 `created_verified`、`already_present_verified`、`failed`、`outcome_unknown` 或 `conflict`，不能把未核实结果提升为成功。当前基础没有 tag/Release 删除或回退能力；不要删除资源模拟回滚。

硬崩溃可能遗留 `pending` 审计与 `.dev-workflow/lifecycle.lock/owner.json` 中的 release owner。`pending` 不证明操作未发生，应按结果未知处理；宿主或操作员须先确认所属进程已终止，再人工恢复锁并只读核对实际对象。当前没有自动 release 恢复命令，不自动删除仍存活或身份不明的 owner/lock，也不凭旧记录重新发起变更。

CI、产物/镜像、部署和线上验证保持各自 `unknown`，除非另有独立、有效证据；此执行基础不提升这些状态。部分完成应逐操作报告真实结果、缺口和后续所需授权，不能把 Release 已创建表述为已部署或生产成功。

## provider 实现依据

本地不存在才创建使用 Git 的原子 ref 语义，见 [git-update-ref](https://git-scm.com/docs/git-update-ref.html)。远端必须区分 raw tag object 与 peeled commit，见 [git-ls-remote](https://git-scm.com/docs/git-ls-remote)；tag 推送只使用准确对象和准确目标 ref，见 [git-push](https://git-scm.com/docs/git-push)。宿主也负责所用 Git 程序和传输配置的可信性。

GitHub provider 必须完整核对 Release 身份和内容；按 tag 查询不覆盖 draft，不能据此断言不存在；创建接口没有可依赖的通用幂等键，超时后须先核对。已有 tag 时 `target_commitish` 不能证明实际 tag 目标，须独立读取 Git ref。依据见 [GitHub Releases REST API](https://docs.github.com/en/rest/releases/releases)。这些约束描述未来生产 provider 的职责，不表示本包已实现 GitHub HTTP 适配器。
