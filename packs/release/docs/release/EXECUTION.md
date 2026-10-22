# 发布执行集成契约

发布模块提供 Python 3.10+ 执行 SDK、真实 GitHub.com Tag / Release provider（`release_github.py`）及受信 GitHub Actions 授权宿主（`release_host.py`）。**项目本地 CLI 仍仅准备**；真实执行必须接入下述独立可信宿主，不能把项目文件当作授权源。原有 `release_prepare.py` 保持只读及兼容。此模块不执行包/镜像发布、部署、迁移或线上验证；实际端到端验收须有独立测试仓库的执行证据。

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

所有远端 Git 与 Release 访问由宿主注入 provider；provider 必须绑定预期 remote/repository 身份、准确对象和 Release payload，并负责传输真实性。tag provider 实现 `inspect(request)` 与 `push(request)`；Release provider 实现 `inspect(request)` 与 `create(request)`。检查必须返回实际观察，不把请求内容原样回显成证据；Release 创建前后还核对远端 tag。已提供的 GitHub provider 仅接受宿主注入的凭据和最终 mutation guard，不读取项目凭据、代理环境配置或任意模块/文件；不跟随 HTTP 重定向。SDK 在 provider 检查前及变更方法调用前重验 Grant，provider 在实际发出变更请求前调用宿主 guard，再核对权限和账本。变更不自动重试。SDK 和 REST API 无法消除 HTTP 在途期间的远端竞争，也没有以 expected tag OID 原子创建 Release 的接口；因此创建前后均须核实 raw tag 和内容，无法核实时保持 `outcome_unknown` 或冲突。单元测试、bare remote 或假平台不代替独立真实仓库验收。

## GitHub Actions 可信宿主接入

宿主必须使用单独维护、固定准确 commit 的可信代码和工作流；待发布 checkout 只作为数据读取，不能运行其中的安装器、Python 模块、构建脚本或工作流。`release_host.py` 及其 imports、宿主 runner 和策略均来自可信 checkout。这个隔离和凭据管理由宿主运维负责，Python 进程内 SDK 不提供沙箱。

宿主策略 `HostPolicy` 固定以下身份，不能从候选项目的 JSON、环境变量或任意 CLI 开关提升权限：

- 宿主 `host_repository` / `host_repository_id`、准确 `workflow_ref` / `workflow_sha`、当前 `run_id` 和环境名称；仅接收 `workflow_dispatch` 且 `run_attempt=1`。
- 目标 `target_repository` / `target_repository_id`，以及项目之外的 `ledger_repository` / `ledger_repository_id` / `ledger_sha`。账本与目标必须是不同仓库；账本 SHA 必须是账本已有的固定对象。
- 允许的个人 reviewer ID、`prevent_self_review` 和准确操作集合的 `expires_at`。bundle 最长一小时，实际授权还受短期 OIDC 到期限制。

凭据由可信宿主的受保护环境提供，不写入候选 checkout、计划、日志或审计文件。需要分别具备：目标仓库的 Contents 读写（创建 refs / Release，并完整观察草稿）；宿主仓库的 Actions、环境、审批记录与 OIDC subject 设置读取权限；独立账本仓库的 Contents 读写。具体 token 类型及权限由所选宿主配置，但读取不到完整身份、权限或审批数据时须拒绝；公共只读 token 不足以证明没有同名草稿。工作流只授予请求 GitHub OIDC 所需的 `id-token: write`，不因安装 release 包自动创建凭据或修改仓库设置。

### 最小宿主配置与 runner

分发仓库提供 `scripts/release_host_runner.py`，仅从可信分发 checkout 运行，不作为目标项目的本地执行入口安装。工作流示例见 [host-workflow.example.yml](host-workflow.example.yml)；它是待审核模板，不会自动启用为目标项目的工作流。宿主需保留完整分发目录结构供 runner 导入可信 Core 和 release 模块，固定第三方 action SHA，并保护宿主默认分支和执行环境。候选项目必须在隔离路径，不能与可信分发目录相互嵌套。

宿主维护的 `host-policy.json` 最小示例（名称、ID、reviewer 和发布内容必须替换为实际已核实值）：

```json
{
  "hostRepository": "OWNER/release-host",
  "hostRepositoryId": 1001,
  "workflowRef": "OWNER/release-host/.github/workflows/release.yml@refs/heads/main",
  "environment": "release-validation",
  "reviewerIds": [1002],
  "preventSelfReview": false,
  "targetRepository": "OWNER/release-test",
  "targetRepositoryId": 1003,
  "candidatePath": "/tmp/dev-workflow-target",
  "operations": ["local-tag-create", "remote-tag-push", "remote-release-create"],
  "release": {
    "name": "Release validation",
    "body": "Isolated test repository release; no deployment.",
    "draft": true,
    "prerelease": true
  }
}
```

此例为单用户隔离验收，显式允许本人审批；多人宿主通常保留默认 `preventSelfReview: true`。`workflowRef` 必须匹配实际文件名和触发 ref。此 runner 以宿主仓库自身作为独立账本，目标仓库必须不同；宿主 checkout 的 HEAD 固定 workflow SHA 和账本对象 SHA，再用签名 OIDC 及运行 API 核实，不从候选项目接收这些权威身份。

工作流 preview 阶段只接收准确目标 SHA 和显式版本；Release name/body/draft/prerelease 由已审核的宿主策略提供，不从候选项目执行代码生成。preview 保存完整计划、55 分钟 expiry、操作集合和 bundle hash 供用户审核。protected execute 阶段下载同一运行的 preview，重新检查新鲜候选 checkout，核对完整 bundle 后才请求授权与执行。命令形式如下，必须由该可信工作流运行：

```sh
python3 -I trusted/scripts/release_host_runner.py prepare --policy trusted/host-policy.json --repo /tmp/dev-workflow-target --record preview.json --version 1.2.3
python3 -I trusted/scripts/release_host_runner.py execute --policy trusted/host-policy.json --repo /tmp/dev-workflow-target --record preview.json --output results.json
```

示例中 preview 的 `TARGET_READ_TOKEN` 仅用于克隆私有目标项目，公开仓库可按实际权限配置。protected execute 的 `RELEASE_TOKEN` 来自受保护环境，当前 runner 使用同一凭据读取宿主运行、环境、审批和 OIDC subject 设置，并写宿主账本及目标 tag / Release；须将权限限制到这两个已核实仓库及上述必要 API。`ACTIONS_ID_TOKEN_REQUEST_*` 只由 GitHub 运行时提供，用于取短期签名身份，不能在本机填造替代。执行输出保存逐操作结果；成功后额外只读重验已存在对象，核对没有再次消耗授权。任何步骤失败都不会自动重试变更。

### 审核与执行顺序

1. 在不执行候选代码的条件下生成准备和执行计划；固定操作集合、仓库 / remote / HEAD / 目标 SHA / raw tag 身份及 Release 全部内容，并计算 `bundle_digest(requests, expires_at, policy.bundle_context())`。审核材料须展示这些准确值及 expiry，不能只展示版本号或摘要。
2. 进入受保护环境前将审核材料和 bundle hash 展示给用户。环境必须要求策略中的个人 reviewer，`can_admins_bypass=false`，不得用管理员绕过。默认 `prevent_self_review=true`；单用户宿主可在可信策略中显式设为 `false`，环境设置须准确一致，仍须取得该 reviewer 账户下的真实 GitHub 环境审批记录。
3. reviewer 的真实 GitHub 环境审批记录必须包含准确评论 `dev-workflow approve <bundle hash>`。聊天中的一般任务指令、项目 approval JSON 或普通工作流 dispatch 不等于已经存在审批记录。用户也可在看过准确 run、bundle hash、仓库、版本和操作集合后，明确授权代理通过已验证的 GitHub 账户登记该次审批；代理只可登记该准确范围，并保留直接用户授权证据，将审批方法记为 delegated，不能声称用户亲自在 GitHub 页面点击或经过独立人工复核。仅持有环境 token、执行权限或此前的泛化授权不能自行代批。
4. 宿主验证 GitHub OIDC 的 RS256 签名和固定 issuer / audience，再匹配仓库 ID、workflow SHA / ref、run ID、attempt、actor、环境及时间；通过 GitHub API 重读工作流、环境保护和准确审批。首个宿主限 GitHub-hosted Linux，使用固定 `/usr/bin/openssl` 验签；这不宣称 Windows 上的 Actions 宿主已经验收。
   Subject 还须通过认证后的宿主仓库设置核验：读取 `/repos/{owner}/{repo}/actions/oidc/customization/sub`，仅接受实际使用默认 subject 的配置，自定义模板拒绝。immutable 默认模式的前缀由已核实的仓库名称、API 返回的 owner ID 和策略仓库 ID 构造为 `repo:OWNER@OWNER-ID/REPO@REPO-ID`，再准确匹配 `:environment:ENVIRONMENT`；不能从 JWT 自报的前缀放宽比较。legacy 名称格式只在 API 确认实际 legacy 默认配置时接受。GitHub 对 2026-07-15 后新建的仓库启用 immutable 默认 subject，旧仓库及迁移情形以实时配置为准，见 [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims)。读取配置失败、ID 不同、未知模式或 subject 不一致均拒绝，不尝试降级。
5. 每个操作先在独立账本创建 `refs/tags/workflow-grants/<run ID>/<bundle hash>/<operation>`，只创建不存在的 ref，再分发变更。每个操作 `max_uses=1`；已有标记、丢失响应或无法确认登记均拒绝继续，失败或未知结果不退还次数。provider 在实际变更前再次核验授权和账本。
6. 逐操作读取真实远端对象、记录结果。需要再次尝试时先只读查清结果，再取得新运行、新审核与有效授权；不能通过 workflow rerun、删除账本标记或修改候选文件恢复使用次数。

审批账本的不可覆盖创建保证并发消费失败关闭；可信宿主管理员仍须保护账本，限制可删除标记或修改宿主代码、策略、凭据的人。此模型不防御已控制可信宿主的管理员。没有真实 reviewer 审批或实际网络执行证据时，报告待审批 / 未验收，不声称真实发布闭环已通过。

### GitHub provider 的当前范围

- `remote-tag-push` 使用 REST GitRefs 创建准确 lightweight tag；虽沿用 SDK 操作名称，但不运行 `git push`，不推送分支、不上传对象。目标 commit 必须已存在于目标仓库，分支交付需要独立授权和流程。
- 不创建 annotated tag，不移动或删除既有 tag。已有 lightweight ref 必须与准确 raw object 一致；annotated tag 即使 peel 到同一 commit 也阻断当前执行器。
- Release 检查分页读取草稿和已发布记录，再按 ID 读取准确对象；同 tag 多条记录、内容不同或分页无法证明完整时拒绝。不把 `target_commitish` 回显当作 tag 目标证据。
- 创建 Release 固定 `make_latest=false` 和 `generate_release_notes=false`，不生成或改写用户批准的 notes。draft / prerelease 取自准确批准的 spec。
- GitHub Release API 在 tag 缺失时可能补建 tag。为保持三种授权的边界，真实创建 Release 前还要求目标仓库存在已启用的 tag ruleset：同一规则集禁止 update/deletion、没有 bypass actor、没有排除项，且覆盖准确 tag 或 `~ALL`。provider 只读核验，不自动创建规则或提升权限；凭据必须能读取完整 ruleset 与 bypass 元数据，字段缺失时拒绝。当前保守实现只接受仓库级规则，不推导复杂模式或组织继承规则。宿主管理员仍须保护这些规则；不声称能防御有权删除规则的管理员。
- 网络请求有超时和响应体上限；没有自动变更重试。`outcome_unknown` 表示结果未核实，不能自动升级成成功或删除资源模拟回滚。

## 失败、恢复与证据

每个操作独立记录状态；本地 tag、远端 tag 和远端 Release 的成功不能互相推导。宿主调用执行即请求生成 `.dev-workflow/releases/execution-<UUID>.json` 审计记录；在消耗授权前，准确审计目标必须被 Git 忽略，且整个 `.dev-workflow/` 内不能有已跟踪文件。记录含 `createdAt`、`observedAt` 和明确的 `releasePayloadHash`；消耗后增加 `consumedAt`、`useNumber`。`phase` 区分 `pre-dispatch`、`dispatch`、`verification`，已存在的同对象可记为 `verified`；`failureCode` 使用有界分类，不写入原始 provider 异常或凭据。变更后必须通过 provider/本地读取确认准确身份。遇到响应丢失或超时，先只读核对实际对象；同对象已存在可报告 no-op，不再创建。核对无法完成时保持不确定，不盲目重试；需要新的变更尝试时重新取得有效授权，旧失败次数不退还。

准备意图、目标、配置、remote URL 或 Release 内容变化会使原计划/授权失效。消耗授权后、分发变更前检查到漂移时，正常异常路径将审计记为 `failed`，已消耗的次数仍然保留。恢复时重新读取当前状态并核对绑定，不从本地审计记录恢复权限。记录状态为 `created_verified`、`already_present_verified`、`failed`、`outcome_unknown` 或 `conflict`，不能把未核实结果提升为成功。当前基础没有 tag/Release 删除或回退能力；不要删除资源模拟回滚。

硬崩溃可能遗留 `pending` 审计与 `.dev-workflow/lifecycle.lock/owner.json` 中的 release owner。`pending` 不证明操作未发生，应按结果未知处理；宿主或操作员须先确认所属进程已终止，再人工恢复锁并只读核对实际对象。当前没有自动 release 恢复命令，不自动删除仍存活或身份不明的 owner/lock，也不凭旧记录重新发起变更。

CI、产物/镜像、部署和线上验证保持各自 `unknown`，除非另有独立、有效证据；此执行基础不提升这些状态。部分完成应逐操作报告真实结果、缺口和后续所需授权，不能把 Release 已创建表述为已部署或生产成功。

## provider 实现依据

本地不存在才创建使用 Git 的原子 ref 语义，见 [git-update-ref](https://git-scm.com/docs/git-update-ref.html)。远端必须区分 raw tag object 与 peeled commit，见 [git-ls-remote](https://git-scm.com/docs/git-ls-remote)；tag 推送只使用准确对象和准确目标 ref，见 [git-push](https://git-scm.com/docs/git-push)。宿主也负责所用 Git 程序和传输配置的可信性。

GitHub provider 必须完整核对 Release 身份和内容；按 tag 查询不覆盖 draft，不能据此断言不存在；创建接口没有可依赖的通用幂等键，超时后须先核对。已有 tag 时 `target_commitish` 不能证明实际 tag 目标，须独立读取 Git ref。依据见 [GitHub Releases REST API](https://docs.github.com/en/rest/releases/releases)。本包 GitHub HTTP 适配器按这些边界实现；仅支持 GitHub.com 固定 API，不支持任意 endpoint 或 GitHub Enterprise Server。
