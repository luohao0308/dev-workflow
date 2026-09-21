# dev-workflow

`dev-workflow` 是一套可放在 GitHub 分发、安装到任意代码仓库或多仓库工作区的通用 AI 协作开发流程。Core 不依赖 Skill、Plugin、常驻 CLI、特定模型、前后端框架或业务领域；可选 `feature-catalog` 自动化只使用 Python 3 标准库。

安装完成后，AI 日常只需自动读取目标项目中的 `AGENTS.md`；其他 Markdown 文件由 `AGENTS.md` 按任务引导读取。

## 给 AI：自动接入当前项目

当用户把本仓库链接交给 AI，并要求“接入当前项目”时，AI 应先完整阅读本 README，再按以下契约执行，不需要用户逐条转述安装命令：

1. 把当前工作目录视为目标项目；只读确认仓库边界、现有 `AGENTS.md`、`docs/`、用户改动和受保护路径。
2. 用户指定版本时使用对应 tag；未指定时使用最新稳定 Release，没有 Release 时使用最新的非预发布 SemVer tag。只有用户明确要求测试开发版时才使用 `main`。
3. 将分发仓库克隆到目标项目之外的临时目录，判断当前系统后选择 PowerShell 或 Bash 安装器。
4. 先执行 dry-run，确认不会覆盖已有文件；再根据项目适用性选择流程包。用户要求完整流程时安装全部流程包。
5. 安装后读取目标项目中的 `AGENTS.md` 和 `docs/WORKFLOW-ADOPTION.md`，完成只读项目画像、既有文档映射和项目专属规则初始化。
6. 将已验证事实写入目标项目，保持 Unknown 明确，不复制来源项目的技术栈、业务规则、凭据或敏感信息。
7. 同步 `WORKFLOW-ADOPTION.md` 与 `.dev-workflow/manifest.json` 的接入状态，最后运行严格审计；只有审计退出码为 `0` 才标记接入完成。
8. 除非用户明确要求，不自动 commit、push、发布或删除临时目录之外的项目内容。

用户推荐提示词：

```text
按照仓库 README，将 dev-workflow 最新稳定版接入当前项目。
先执行 dry-run，保留并映射已有 AGENTS.md 和 docs，不覆盖现有内容；
完成项目画像和接入审计，直到 onboarding 为 ready 且严格审计通过。
```

裸链接本身可能表示阅读、评审或安装；“接入当前项目”用于明确授权目标。首次接入完成后，后续正常对话直接沿用目标项目中的 `AGENTS.md`，不再需要重复运行安装器。

## 分发仓库结构

```text
dev-workflow/
├── core/                  # 每个项目都适用的协作与知识治理核心
├── packs/                 # 按项目选择安装的流程包
│   ├── architecture/
│   ├── design/
│   ├── delivery/
│   ├── contracts/
│   ├── operations/
│   └── feature-catalog/   # 功能清单 Schema、模板、说明和标准库工具
├── VERSION                # 分发仓库版本
├── scripts/               # 安装、卸载和接入审计工具，不进入目标项目
│   ├── install.ps1
│   ├── install.sh
│   ├── uninstall.ps1
│   ├── uninstall.sh
│   ├── audit.ps1
│   └── audit.sh
└── tests/                 # 单元测试与 PowerShell/Bash 端到端脚本测试
    ├── test_feature_catalog.py
    ├── integration.ps1
    └── integration.sh
```

`core/` 和每个 `packs/<name>/` 都是目标项目根目录的 overlay：目录中的相对路径就是安装后的相对路径。

## Core：默认安装

Core 提供：

- `AGENTS.md`：自动协作规则、首次项目扫描、规则分层、任务推进、安全和完成标准；
- 大型计划拆分确认门：在跨模块或高风险计划实施前，先列出 `2-6` 个切片并等待用户确认；
- `docs/README.md`：文档导航与权威边界；
- `docs/TASKS.md`：唯一任务状态源；
- `docs/WORKING-CONTEXT.md`：当前主任务短期记忆；
- `docs/WORKFLOW-ADOPTION.md`：首次接入状态、既有文档映射和审计记录；
- `docs/PROJECT-SUMMARY.md`：仓库拓扑、模块、命令、契约、交付和风险画像；
- `docs/project-memory/README.md`：长期、已验证经验库。

### 默认开发闭环

Core 采用轻量的默认路径：

```text
目标与完成标准 -> 风险分类 -> 测试或 Eval 先行 -> 小型垂直切片 -> 验证与证据
```

SDD/ATDD 和 TDD/EDD 是这条路径中的对应做法，不是每次都必须单独完成的阶段。Contract、
Property、E2E、对抗性验证、回滚演练和人工确认按风险触发；低风险局部改动保持短路径。
每条验收标准都应映射到 test、Eval 或其他可执行检查，完成声明必须带有新鲜证据。

安装器还会在目标项目生成 `.dev-workflow/manifest.json`，记录流程版本、已安装流程包、逐文件来源、安装动作、原始哈希、接入状态和当前机器的交付执行权限。它是本地安装、升级、安全卸载和 AI 权限判断的元数据，不是团队共享配置。

如果目标目录位于 Git 仓库，安装器还会通过 `git rev-parse --git-path` 定位该仓库（包括 worktree）的本地 `info/exclude`，维护一个 `dev-workflow managed` 排除区块。`.dev-workflow/` 和安装器实际创建的文件会加入其中；项目原有文件、被保留的文件和只追加核心区块的 `AGENTS.md` 不会被整文件忽略。嵌套目标路径会按 Git ignore 字面量规则转义，写入后再用 Git 验证最终忽略结果。安装器不会修改项目 `.gitignore`。非 Git 目录会跳过这一步并给出告警。已经被 Git 跟踪的文件，或被更高优先级 `.gitignore` 规则重新放行的文件，不会因为新增 exclude 而停止上传；安装器只告警，不会自动执行 `git rm --cached` 或改写 `.gitignore`。

## 可选流程包

| 包 | 安装内容 | 适用场景 |
|---|---|---|
| `architecture` | 系统架构、模块边界、ADR 模板 | 多模块、Monorepo、多仓库、长期维护项目 |
| `design` | 根 `DESIGN.md`、设计索引与完整设计模板 | 新功能、产品/UI、复杂技术方案 |
| `delivery` | 开发命令、Worktree、测试、计划、并行上下文、工作日志，以及大型计划拆分确认门 | 需要可重复的开发、验证和 Git 交付流程 |
| `contracts` | API/事件/Schema 契约、变更和迁移模板 | 对外接口、事件、数据库或文件格式项目 |
| `operations` | 发布、Preflight、观测、回滚和 Runbook 模板 | 有测试、预发布或生产环境的项目 |
| `feature-catalog` | 功能层级/状态/成熟度 Schema、初始化模板、生成/查询/校验工具 | 功能较多、需要 AI 排查、成熟度治理或发布证据追踪的项目 |

多数流程包只包含普通 Markdown 文件。Core 自带零第三方依赖的 `scripts/delivery_guard.py`，`feature-catalog` 另带一个 Python 3 脚本；它们都不会安装解释器、依赖包、后台进程或常驻服务。不启用 `feature-catalog` 时，其余行为保持不变。

Delivery 的本地 Agent 临时分支可以使用 `codex/*`，但这类分支禁止 push 到远端，也不能作为线上 PR 的 source branch。线上交付必须切换到项目约定的 `feat/*`、`fix/*`、`docs/*`、`chore/*` 等合规命名。

## 安装

### Windows PowerShell

只安装 Core：

```powershell
.\scripts\install.ps1 -TargetPath "D:\Projects\another-project" -DryRun
.\scripts\install.ps1 -TargetPath "D:\Projects\another-project"
```

安装选定流程包：

```powershell
.\scripts\install.ps1 `
  -TargetPath "D:\Projects\another-project" `
  -Packs architecture,design,delivery,feature-catalog
```

安装全部流程包：

```powershell
.\scripts\install.ps1 -TargetPath "D:\Projects\another-project" -AllPacks
```

交互安装只确认 push、PR 创建/更新和远端 PR merge 的审批模式与执行角色。默认均为 `manual + user`；自动执行必须显式使用 `auto + ai`：

```powershell
.\scripts\install.ps1 `
  -TargetPath "D:\Projects\another-project" `
  -PushMode auto -PushActor ai `
  -PullRequestMode manual -PullRequestActor user `
  -MergeMode manual -MergeActor ai
```

### Linux、macOS 或 WSL Bash

```bash
# 只安装 Core
bash ./scripts/install.sh --target /path/to/project --dry-run
bash ./scripts/install.sh --target /path/to/project

# 安装选定流程包
bash ./scripts/install.sh \
  --target /path/to/project \
  --packs architecture,design,delivery,feature-catalog

# 安装全部流程包
bash ./scripts/install.sh --target /path/to/project --all-packs
```

交互安装只确认 push、PR 创建/更新和远端 PR merge 的审批模式与执行角色。默认均为 `manual + user`；自动执行必须显式使用 `auto + ai`：

```bash
bash ./scripts/install.sh \
  --target /path/to/project \
  --push-mode auto --push-actor ai \
  --pull-request-mode manual --pull-request-actor user \
  --merge-mode manual --merge-actor ai
```

首次安装在交互式终端中会询问三类远端操作的 mode/actor；如果 stdin 不是终端，安装器会停止并提示重新在交互式终端运行，不会静默假装完成确认。CI 或其他非交互环境必须显式使用 `--non-interactive`、PowerShell 的 `-NonInteractiveInstall`，或设置 `DEV_WORKFLOW_NON_INTERACTIVE=1`；它们只能采用安全默认值、保留既有策略或执行无参数的安全迁移，不能通过参数创建或修改持久权限。PR、CI、独立 Review 默认强制；force push、直接 push 保护分支和高权限操作默认拒绝，这些安全边界不作为普通初始化问题。

### 功能清单初始化与使用

只有选择了 `feature-catalog` 流程包的项目才需要这些命令。安装完成后，在目标项目根目录运行：

```bash
# 首次创建活动清单；文件已经存在时会拒绝覆盖
python3 scripts/feature_catalog.py --init

# 只读校验 JSON 结构、层级、成熟度规则、证据和仓库内路径
python3 scripts/feature_catalog.py --validate

# 校验后写入/更新面向人的 docs/FEATURE-MATRIX.md
python3 scripts/feature_catalog.py --generate

# 只读校验清单，并确认生成矩阵没有漂移；适合 CI 和接入审计
python3 scripts/feature_catalog.py --check

# 只读返回匹配功能及其必要祖先；适合 AI 按当前任务加载最小上下文
python3 scripts/feature_catalog.py --query "login release evidence"
```

这些命令主要服务 AI 协作和 CI 门禁，但人也可以直接使用。`--init` 和 `--generate` 会写项目文件，其余命令只读；查询还支持项目自定义的 `--platform` 标签，以及 `--status`、`--maturity`、`--limit` 和 `--json`。初始化后必须用当前项目事实替换模板示例，不能把模板状态当成产品完成情况。

项目维护的活动清单 `docs/development/ai/feature-catalog.json` 和生成矩阵 `docs/FEATURE-MATRIX.md` 不属于安装器的文件清单；它们是项目数据，不会在重装或卸载流程包时被覆盖或删除。完整字段、成熟度门和 CI 接入方式见安装后的 `docs/development/ai/FEATURE-CATALOG.md`。

### 接入审计

审计检查安装结构、流程包文件、核心标记、manifest、初始化状态和本地 Git exclude；安装了 `feature-catalog` 时还会只读运行目录校验与矩阵漂移检查。受管排除区块缺失、重复、标记倒序、最终 Git ignore 未生效，或包含 dev-workflow 内容的文件已经被 Git 跟踪时都会告警，strict 模式会失败。审计不会修改项目代码，也不会读取凭据。

```powershell
.\scripts\audit.ps1 -TargetPath "D:\Projects\another-project"
```

```bash
bash ./scripts/audit.sh --target /path/to/project
```

审计退出码：`0` 表示结构正常且接入状态为 `ready`，`1` 表示安装损坏或缺少必要文件，`2` 表示安装存在但接入状态仍为 `pending` 或 `blocked`。可选的 `-Strict` / `--strict` 会把占位内容、版本落后等告警也视为退出码 `1`。

安装了 `feature-catalog` 时，审计会调用目标项目自己的 `scripts/feature_catalog.py --check`。接入状态为 `pending` 或 `blocked` 时，活动清单缺失、矩阵缺失或检查失败记为告警；状态为 `ready` 时记为错误并返回 `1`。因此项目可以先完成画像和清单初始化，再把 onboarding 切换为 `ready`。

### Bash 版本兼容

`scripts/install.sh`、`scripts/audit.sh` 和 `scripts/uninstall.sh` 支持 macOS 自带的 Bash 3.2。脚本在 `set -u` 下对空流程包、空文件清单和空错误列表使用兼容展开，不要求安装新版 Bash。读取已有 manifest 的安全策略时需要 `python3`、`jq` 或 Node 中至少一个结构化 JSON 解析器；全部缺失时 fail-closed，不使用文本匹配降级。完整 Bash 端到端回归入口为：

```bash
bash tests/integration.sh
```

## 卸载

卸载器必须从 `dev-workflow` 分发仓库运行。schema 2/3/4 安装要求分发仓库 `VERSION` 与目标项目 manifest 的 `workflowVersion` 一致，应先检出对应版本 tag；schema 1 旧安装可由当前卸载器保守处理。然后执行 dry-run 查看删除、编辑和保留清单：

### Windows PowerShell

```powershell
# 预览完整卸载
.\scripts\uninstall.ps1 -TargetPath "D:\Projects\another-project" -DryRun

# 完整卸载 Core 和全部流程包
.\scripts\uninstall.ps1 -TargetPath "D:\Projects\another-project"

# 只卸载指定流程包，保留 Core 和其他流程包
.\scripts\uninstall.ps1 `
  -TargetPath "D:\Projects\another-project" `
  -Packs delivery,operations
```

### Linux、macOS 或 WSL Bash

```bash
# 预览完整卸载
bash ./scripts/uninstall.sh --target /path/to/project --dry-run

# 完整卸载 Core 和全部流程包
bash ./scripts/uninstall.sh --target /path/to/project

# 只卸载指定流程包
bash ./scripts/uninstall.sh \
  --target /path/to/project \
  --packs delivery,operations
```

卸载规则：

- `AGENTS.md` 只移除带稳定标记的 AI-WORKFLOW 核心区块；安装后新增的项目专属规则会保留。
- 只有 manifest 标记为安装器创建、且当前哈希仍等于安装时哈希的文件才会自动删除。
- 安装前已存在、安装后被修改或旧版来源不明的文件始终保留，并在输出中标记为 `[keep]`。
- `feature-catalog` 的活动清单和生成矩阵是项目数据，不进入 manifest 文件所有权；部分或完整卸载都会保留它们。
- 部分卸载会更新 manifest 中的流程包和文件清单；完整卸载最后删除 manifest，并且只清理已经为空的目录。
- `schemaVersion: 1` 的旧安装会先保守迁移：核心标记可移除，普通文件标记为 `legacy`，不会因无法证明所有权而被删除。

交给 AI 卸载时可使用：

```text
按照仓库 README 卸载当前项目中的 dev-workflow。
先读取 .dev-workflow/manifest.json 的 workflowVersion，并使用对应版本 tag 的卸载器；
先执行 dry-run 并汇报删除、编辑、保留和冲突项；确认范围后再执行正式卸载。
不得删除已修改、安装前已存在或无法证明归属的项目文件。
```

## 安装行为

- 目标目录必须已经存在，并且不能位于 `dev-workflow` 分发仓库内部。
- 已有普通文件不会覆盖。
- 已有 `AGENTS.md` 会保留原内容，只追加带稳定标记的通用核心区块。
- 已经存在通用核心标记时保持不变，重复安装具有幂等性。
- `-DryRun` / `--dry-run` 只输出将创建、追加或跳过的文件，不写入目标项目。
- 首次安装会创建 `.dev-workflow/manifest.json`；重复安装会保留安装时间，合并已安装流程包并更新版本信息。
- manifest 的 `gitPolicy` 分别记录 push、PR 创建/更新和远端 PR merge 的 `manual|auto` 模式与 `user|ai` 执行角色；缺失时按 `manual + user`。`auto` 只允许与 `ai` 组合，本地 `git merge` 不属于远端 merge 权限。
- `pullRequestRequired`、`ciRequired`、`independentReviewRequired` 默认为 `true`；`forcePushAllowed`、`directProtectedBranchPushAllowed` 固定为 `false`，`privilegedOperationsDefault` 固定为 `deny`。
- 修改持久权限策略本身始终需要人工确认，不能由现有权限推导，并记录 `policyChangedAt` / `policyChangedBy`。一次性授权必须绑定 `repo + remote + remote URL + operation + source ref + target ref + exact SHA + expiry + maxUses`，不改变 manifest，也不授权其他目标或后续操作。
- Core 安装的远端操作 guard 必须在 AI 执行 push、PR 创建/更新和远端 PR merge 前运行：`python3 scripts/delivery_guard.py check`。`actor=user` 时 guard 拒绝 AI 执行；`actor=ai` 即使处于 `auto + ai` 也需要有效的一次性授权，`auto` 只免除该授权范围内的再次交互。最终 preflight 使用 `--consume` 记录授权次数；每类操作都需要绑定当前仓库/remote/ref/SHA 的新鲜 provider 证据，merge 还需 PR/CI/独立 Review/分支保护证据。
- `deleteAllowed` 固定为 `false`，安装初始化不展示或授予删除权限；具体删除必须针对明确目标另行授权。
- manifest schema 4 会记录三类 Git 交付执行权限、固定质量门和高权限操作默认拒绝策略，以及安装器实际创建、追加、保留或从旧版迁移的文件；卸载器据此判断文件所有权。
- 安装器只维护 Git 解析出的 `info/exclude` 中带 `# BEGIN dev-workflow managed excludes` / `# END dev-workflow managed excludes` 标记的本地区块；更新前会验证标记完整且顺序正确，重复安装幂等，部分卸载按剩余文件重建，完整卸载只移除该区块并保留用户自己的 exclude 内容。
- 安装、审计和卸载都会验证 manifest 中的每个路径确实属于其声明的 Core 或流程包；未知路径会停止处理，不会据此删除项目文件。
- 自动删除还要求 `created` 文件的安装哈希等于同版本分发文件哈希；卸载器版本不匹配时会停止，避免用新版模板推断旧版所有权。
- 目标项目已有非 dev-workflow 管理的 `.dev-workflow/manifest.json` 时安装会停止，不覆盖未知元数据。
- 安装脚本和 `core/`、`packs/` 分发目录不会复制到目标项目。
- `feature-catalog` 的 Schema、模板、说明和工具由 manifest 管理；活动清单和生成矩阵由项目管理，不记录为安装器拥有的文件。
- `audit` 不会自动把项目标记为已接入；必须先完成 `WORKFLOW-ADOPTION.md` 中的项目画像和文档映射，再同步更新文档状态、manifest 的 `onboarding.status` 与 `lastAuditAt`。
- 自动升级不会静默改写已有规则；升级先比较 GitHub 版本差异，再用 dry-run 查看安装计划，审核合并后运行审计。

## 目标项目结构

只安装 Core 时：

```text
.
├── .dev-workflow/
│   └── manifest.json
├── AGENTS.md
└── docs/
    ├── README.md
    ├── TASKS.md
    ├── WORKING-CONTEXT.md
    ├── WORKFLOW-ADOPTION.md
    ├── PROJECT-SUMMARY.md
    └── project-memory/
        └── README.md
```

安装全部流程包后，会在同一 `docs/` 下增加 `architecture/`、`design/`、`development/`、`testing/`、`plans/`、`working-context/`、`contracts/`、`operations/`、`工作日志/` 和 Runbook 模板；设计包还会增加根 `DESIGN.md`。`feature-catalog` 包还会增加：

```text
.
├── scripts/
│   └── feature_catalog.py
└── docs/
    ├── FEATURE-MATRIX.md                         # --generate 后创建的项目数据
    └── development/ai/
        ├── FEATURE-CATALOG.md
        ├── feature-catalog.schema.json
        ├── feature-catalog.template.json
        └── feature-catalog.json                  # --init 后创建的项目数据
```

## 首次使用

安装模板只是建立规则和文档骨架。第一次在目标项目对话时，AI 应先读取 `WORKFLOW-ADOPTION.md`，完成只读项目画像和既有文档映射：

```text
读取 AGENTS.md，对当前项目做一次只读项目画像扫描。
识别仓库拓扑、模块、命令、测试/CI、契约、迁移、受保护路径和发布边界；
将已验证事实填入 PROJECT-SUMMARY.md、项目专属规则和已安装流程包；不覆盖已有文档，冲突和 Unknown 要明确记录。
```

完成项目画像后，先在 `pending` 状态运行审计并处理结构错误和告警，再同步将 `WORKFLOW-ADOPTION.md` 与 manifest 标记为 `ready`，记录审计时间，最后重跑审计确认退出码为 `0`。此后正常对话即可自动沿用这套开发风格，不需要每次调用 Skill 或运行 CLI。安装和审计脚本只在首次接入或升级时使用。

交付治理分三层：流程要求决定何时需要 Issue、PR、CI 和独立 Review；执行权限决定谁可以 push、创建/更新 PR 和合并远端 PR；质量门禁决定准确 head SHA 是否允许进入目标分支。feature、bug、安全和跨模块工作应关联 Issue，小型低风险改动不强制。远端 PR merge 必须 fail-closed 验证 PR、head/base、required CI、独立 Review 和分支保护；实现者不得作为唯一审批者，AI review 不计作独立批准。

tag/Release、package/image publish、deploy、migration/backfill、rollback、traffic switch、仓库设置、凭据和发布工作流操作不进入普通初始化，默认拒绝并按具体目标逐次授权。push、PR 或 merge 权限均不蕴含这些权限。

如果选择了 `feature-catalog`，在切换到 `ready` 前还要运行 `--init`，用项目事实维护活动清单，再运行 `--generate` 和 `--check`。后续对话无需重复安装；AI 按任务查询清单，维护者在功能、证据或成熟度变化时更新清单并重新生成矩阵。

## 版本与升级

分发仓库的版本写在 `VERSION`。dev-workflow 安装内容按策略只用于本机，不应提交到 Git；安装器以本地 `info/exclude` 排除 `.dev-workflow/` 和其创建的文件，其他电脑或新 clone 必须重新安装并完成接入。`info/exclude` 无法阻止已跟踪的宿主文件或其新增区块被提交；strict audit 遇到这种情况必须失败，并要求人工处理 Git 索引、项目规则或安装冲突后再交付。manifest 只约束当前机器，团队级强制门必须由远端 branch protection、required checks、CODEOWNERS/独立审批和 environment approval 提供。

升级时先比较 GitHub 新旧 tag 或 release 的变更，再从新版分发仓库运行安装器的 dry-run。安装器只创建缺失文件，不覆盖目标项目已经存在的 Core 文件、流程包文档或受管控 `AGENTS.md` 区块；因此新版新增的 Core 规则必须由人工或 AI 对比后合并到项目现有权威文件，不能把“manifest 已升级”理解为规则正文已经同步。确认合并后运行正式安装以创建缺失文件并更新 manifest，最后运行 audit。

从旧版新增 `feature-catalog` 时，把它加入 `-Packs` / `--packs` 即可安装通用资产；随后在目标项目运行 `--init`、填写项目事实、`--generate` 和 `--check`。schema 1/2/3 manifest 会升级到 schema 4；schema 1 中无法证明由旧安装器创建的普通文件，以及升级时模板内容已变化的旧 `created` 文件，会记录为 `legacy`。若旧 manifest 不是由 `dev-workflow` 管理，安装器会停止并要求先处理冲突。

## 不包含的内容

- 当前来源项目的技术栈、业务模块、端口、服务器或账号信息；
- Claude、Gemini、Cursor、Copilot 等工具专属适配文件；
- `.omx/`、`.omc/`、本机运行状态或模型专属审计格式；
- 生产凭据、环境变量、Cookie、Token、私钥或完整签名 URL；
- 对目标项目代码、架构和命令的猜测。

客户端需要支持读取仓库中的 `AGENTS.md`，或允许在自身项目规则入口中指向它。对于不支持仓库规则自动加载的工具，需要由该工具自身配置入口，但不复制整套规则。

## 许可证

`dev-workflow` 使用 [MIT License](LICENSE)。可以自由使用、修改和分发，但必须保留版权与许可声明；软件按现状提供，不附带担保。
