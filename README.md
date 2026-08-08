# dev-workflow

`dev-workflow` 是一套可放在 GitHub 分发、安装到任意代码仓库或多仓库工作区的通用 AI 协作开发流程。它不依赖 Skill、Plugin、常驻 CLI、特定模型、前后端框架或业务领域。

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
├── packs/                 # 按项目选择安装的普通 Markdown 流程包
│   ├── architecture/
│   ├── design/
│   ├── delivery/
│   ├── contracts/
│   └── operations/
├── VERSION                # 分发仓库版本
├── scripts/               # 安装、卸载和接入审计工具，不进入目标项目
│   ├── install.ps1
│   ├── install.sh
│   ├── uninstall.ps1
│   ├── uninstall.sh
│   ├── audit.ps1
│   └── audit.sh
└── tests/                 # PowerShell/Bash 端到端脚本测试
    ├── integration.ps1
    └── integration.sh
```

`core/` 和每个 `packs/<name>/` 都是目标项目根目录的 overlay：目录中的相对路径就是安装后的相对路径。

## Core：默认安装

Core 提供：

- `AGENTS.md`：自动协作规则、首次项目扫描、规则分层、任务推进、安全和完成标准；
- `docs/README.md`：文档导航与权威边界；
- `docs/TASKS.md`：唯一任务状态源；
- `docs/WORKING-CONTEXT.md`：当前主任务短期记忆；
- `docs/WORKFLOW-ADOPTION.md`：首次接入状态、既有文档映射和审计记录；
- `docs/PROJECT-SUMMARY.md`：仓库拓扑、模块、命令、契约、交付和风险画像；
- `docs/project-memory/README.md`：长期、已验证经验库。

安装器还会在目标项目生成 `.dev-workflow/manifest.json`，记录流程版本、已安装流程包、逐文件来源、安装动作、原始哈希和接入状态。它是安装、升级与安全卸载的元数据，不是日常运行时依赖。

## 可选流程包

| 包 | 安装内容 | 适用场景 |
|---|---|---|
| `architecture` | 系统架构、模块边界、ADR 模板 | 多模块、Monorepo、多仓库、长期维护项目 |
| `design` | 根 `DESIGN.md`、设计索引与完整设计模板 | 新功能、产品/UI、复杂技术方案 |
| `delivery` | 开发命令、Worktree、测试、计划、并行上下文、工作日志 | 需要可重复的开发、验证和 Git 交付流程 |
| `contracts` | API/事件/Schema 契约、变更和迁移模板 | 对外接口、事件、数据库或文件格式项目 |
| `operations` | 发布、Preflight、观测、回滚和 Runbook 模板 | 有测试、预发布或生产环境的项目 |

流程包只包含普通 Markdown 文件，不会安装新的运行时或后台进程。

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
  -Packs architecture,design,delivery
```

安装全部流程包：

```powershell
.\scripts\install.ps1 -TargetPath "D:\Projects\another-project" -AllPacks
```

### Linux、macOS 或 WSL Bash

```bash
# 只安装 Core
bash ./scripts/install.sh --target /path/to/project --dry-run
bash ./scripts/install.sh --target /path/to/project

# 安装选定流程包
bash ./scripts/install.sh \
  --target /path/to/project \
  --packs architecture,design,delivery

# 安装全部流程包
bash ./scripts/install.sh --target /path/to/project --all-packs
```

### 接入审计

审计只检查安装结构、流程包文件、核心标记、manifest 和初始化状态；它不会修改项目代码，也不会读取凭据。

```powershell
.\scripts\audit.ps1 -TargetPath "D:\Projects\another-project"
```

```bash
bash ./scripts/audit.sh --target /path/to/project
```

审计退出码：`0` 表示结构正常且接入状态为 `ready`，`1` 表示安装损坏或缺少必要文件，`2` 表示安装存在但接入状态仍为 `pending` 或 `blocked`。可选的 `-Strict` / `--strict` 会把占位内容、版本落后等告警也视为退出码 `1`。

## 卸载

卸载器必须从 `dev-workflow` 分发仓库运行。schema 2 安装要求分发仓库 `VERSION` 与目标项目 manifest 的 `workflowVersion` 一致，应先检出对应版本 tag；schema 1 旧安装可由当前卸载器保守处理。然后执行 dry-run 查看删除、编辑和保留清单：

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
- manifest schema 2 会记录安装器实际创建、追加、保留或从旧版迁移的文件；卸载器据此判断文件所有权。
- 安装、审计和卸载都会验证 manifest 中的每个路径确实属于其声明的 Core 或流程包；未知路径会停止处理，不会据此删除项目文件。
- 自动删除还要求 `created` 文件的安装哈希等于同版本分发文件哈希；卸载器版本不匹配时会停止，避免用新版模板推断旧版所有权。
- 目标项目已有非 dev-workflow 管理的 `.dev-workflow/manifest.json` 时安装会停止，不覆盖未知元数据。
- 安装脚本和 `core/`、`packs/` 分发目录不会复制到目标项目。
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

安装全部流程包后，会在同一 `docs/` 下增加 `architecture/`、`design/`、`development/`、`testing/`、`plans/`、`working-context/`、`contracts/`、`operations/`、`工作日志/` 和 Runbook 模板；设计包还会增加根 `DESIGN.md`。

## 首次使用

安装模板只是建立规则和文档骨架。第一次在目标项目对话时，AI 应先读取 `WORKFLOW-ADOPTION.md`，完成只读项目画像和既有文档映射：

```text
读取 AGENTS.md，对当前项目做一次只读项目画像扫描。
识别仓库拓扑、模块、命令、测试/CI、契约、迁移、受保护路径和发布边界；
将已验证事实填入 PROJECT-SUMMARY.md、项目专属规则和已安装流程包；不覆盖已有文档，冲突和 Unknown 要明确记录。
```

完成项目画像后，先在 `pending` 状态运行审计并处理结构错误和告警，再同步将 `WORKFLOW-ADOPTION.md` 与 manifest 标记为 `ready`，记录审计时间，最后重跑审计确认退出码为 `0`。此后正常对话即可自动沿用这套开发风格，不需要每次调用 Skill 或运行 CLI。安装和审计脚本只在首次接入或升级时使用。

## 版本与升级

分发仓库的版本写在 `VERSION`。目标项目的 manifest 应随项目文档一起提交到 Git，这样其他电脑克隆项目后无需重新安装即可获得同一套规则。

升级时先比较 GitHub 新旧 tag 或 release 的变更，再从新版分发仓库运行安装器的 dry-run。项目已经存在的规则和文档需要人工或由 AI 审核合并；确认后运行正式安装以创建缺失文件并更新 manifest，最后运行 audit。schema 1 manifest 会在升级时保守迁移到 schema 2；无法证明由旧安装器创建的普通文件，以及新版中模板内容已变化的旧 `created` 文件，会记录为 `legacy`。若旧 manifest 不是由 `dev-workflow` 管理，安装器会停止并要求先处理冲突。

## 不包含的内容

- 当前来源项目的技术栈、业务模块、端口、服务器或账号信息；
- Claude、Gemini、Cursor、Copilot 等工具专属适配文件；
- `.omx/`、`.omc/`、本机运行状态或模型专属审计格式；
- 生产凭据、环境变量、Cookie、Token、私钥或完整签名 URL；
- 对目标项目代码、架构和命令的猜测。

客户端需要支持读取仓库中的 `AGENTS.md`，或允许在自身项目规则入口中指向它。对于不支持仓库规则自动加载的工具，需要由该工具自身配置入口，但不复制整套规则。

## 许可证

`dev-workflow` 使用 [MIT License](LICENSE)。可以自由使用、修改和分发，但必须保留版权与许可声明；软件按现状提供，不附带担保。
