# dev-workflow

`dev-workflow` 是一套可放在 GitHub 分发、安装到任意代码仓库或多仓库工作区的通用 AI 协作开发流程。它不依赖 Skill、Plugin、常驻 CLI、特定模型、前后端框架或业务领域。

安装完成后，AI 日常只需自动读取目标项目中的 `AGENTS.md`；其他 Markdown 文件由 `AGENTS.md` 按任务引导读取。

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
└── scripts/               # 安装和接入审计工具，不进入目标项目
    ├── install.ps1
    ├── install.sh
    ├── audit.ps1
    └── audit.sh
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

安装器还会在目标项目生成 `.dev-workflow/manifest.json`，记录流程版本、已安装流程包和接入状态。它是安装元数据，不是日常运行时依赖。

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

## 安装行为

- 目标目录必须已经存在，并且不能位于 `dev-workflow` 分发仓库内部。
- 已有普通文件不会覆盖。
- 已有 `AGENTS.md` 会保留原内容，只追加带稳定标记的通用核心区块。
- 已经存在通用核心标记时保持不变，重复安装具有幂等性。
- `-DryRun` / `--dry-run` 只输出将创建、追加或跳过的文件，不写入目标项目。
- 首次安装会创建 `.dev-workflow/manifest.json`；重复安装会保留安装时间，合并已安装流程包并更新版本信息。
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

升级时先比较 GitHub 新旧 tag 或 release 的变更，再从新版分发仓库运行安装器的 dry-run。项目已经存在的规则和文档需要人工或由 AI 审核合并；确认后运行正式安装以创建缺失文件并更新 manifest，最后运行 audit。若旧 manifest 不是由 `dev-workflow` 管理，安装器会停止并要求先处理冲突。

## 不包含的内容

- 当前来源项目的技术栈、业务模块、端口、服务器或账号信息；
- Claude、Gemini、Cursor、Copilot 等工具专属适配文件；
- `.omx/`、`.omc/`、本机运行状态或模型专属审计格式；
- 生产凭据、环境变量、Cookie、Token、私钥或完整签名 URL；
- 对目标项目代码、架构和命令的猜测。

客户端需要支持读取仓库中的 `AGENTS.md`，或允许在自身项目规则入口中指向它。对于不支持仓库规则自动加载的工具，需要由该工具自身配置入口，但不复制整套规则。

## 许可证

`dev-workflow` 使用 [MIT License](LICENSE)。可以自由使用、修改和分发，但必须保留版权与许可声明；软件按现状提供，不附带担保。
