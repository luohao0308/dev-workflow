# docs/ 目录索引

> 这是与具体技术栈无关的文档导航模板。项目应根据实际启用的流程包补充领域文档，但不要改变任务状态、短期上下文、稳定摘要和长期记忆的职责边界。

## AI 读取规则

1. 每次任务先读根目录 `AGENTS.md` 和 [TASKS.md](TASKS.md)。
2. 如果 [WORKING-CONTEXT.md](WORKING-CONTEXT.md) 处于 active 状态且未过期，再读取它；并行任务按 `working-context/` 的规则读取对应文件。
3. 根据任务打开一个领域入口；禁止无差别加载整个 `docs/`。
4. 自动生成文档、完整 Runbook 和历史工作日志按标题或关键词检索，不整份预载。
5. 按内容类型区分权威来源：当前任务上下文 → `WORKING-CONTEXT.md`；任务状态 → `TASKS.md`；稳定事实 → `PROJECT-SUMMARY.md` 与 `architecture/`；当前设计 → `design/`；计划 → `plans/`；契约 → `contracts/`；可重复操作 → `project-memory/` 与 `operations/`；历史证据 → `工作日志/`。
6. 线上动态值、外部服务状态和环境信息必须重新验证，不能直接复用历史记录。
7. 被 Git 忽略的敏感配置和本机运行资料不属于知识库，不读取、不索引、不提交。

## 核心文件

| 文件 | 用途 | 何时读 |
|---|---|---|
| [TASKS.md](TASKS.md) | 任务状态、待办、进行中、阻塞和技术债 | 开始任何任务前 |
| [WORKING-CONTEXT.md](WORKING-CONTEXT.md) | 当前主任务的短期上下文、决策、阻塞、下一步和验证摘要 | active 且未过期时 |
| [WORKFLOW-ADOPTION.md](WORKFLOW-ADOPTION.md) | 首次接入状态、既有文档映射和审计记录 | 状态为 `pending` 或需要核验流程接入时 |
| [PROJECT-SUMMARY.md](PROJECT-SUMMARY.md) | 稳定项目事实、拓扑、命令、模块、边界和路径速查 | 需要项目概览或路径定位时 |
| [project-memory/](project-memory/) | 长期、可复用且已经验证的操作知识 | 排障、部署或复用经验时 |

## 可选流程包目录

| 目录 | 所属包 | 用途 |
|---|---|---|
| `architecture/` | architecture | 系统、仓库、模块、数据流和架构决策 |
| `design/` 与根 `DESIGN.md` | design | 当前设计、非目标、取舍、实现约束和验收 |
| `plans/` | delivery | 多步骤变更的范围、阶段、风险和完成标准 |
| `development/`、`testing/`、`working-context/` | delivery | 开发命令、Git 隔离、验证矩阵和并行上下文 |
| `contracts/` | contracts | API、事件、Schema、CLI 等机器契约 |
| `operations/` | operations | 发布、Preflight、观测、健康检查和回滚 |
| `工作日志/` | delivery | 历史过程、验证证据和交付记录 |

未安装某个流程包时，不假定其目录或模板存在；应按项目现有文档和规则继续，并在项目扩展区说明替代入口。

## 文档维护规则

- 新增目录或领域文档时，先在本索引登记用途和读取时机。
- 稳定事实只保留一个权威来源，其他文档使用链接引用。
- 任务状态、短期上下文、长期经验、设计、契约和历史证据不能混写。
- 文档内容与代码或运行中接口冲突时，保留冲突说明并重新验证事实。
- 模板完成后删除占位示例，保留状态、权威范围和更新时间。
- 首次接入完成后将 `WORKFLOW-ADOPTION.md` 标记为 `ready`，并保留最近一次审计的简短证据。
- `.dev-workflow/manifest.json` 只记录安装元数据和接入状态，不记录凭据、绝对本机路径或线上动态秘密。
