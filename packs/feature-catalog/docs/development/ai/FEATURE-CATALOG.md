# Feature Catalog 流程包

这个可选流程包为项目提供一份机器可读的全量能力清单，把功能层级、实现状态、
生产成熟度、验收标准、代码/规格/测试路径、验证证据和已知缺口连接起来。

## 文件职责

安装后由项目维护：

- `docs/development/ai/feature-catalog.json`：项目功能清单的唯一权威数据源。
- `docs/FEATURE-MATRIX.md`：由工具生成的人类阅读视图，不手工维护。

流程包提供：

- `docs/development/ai/feature-catalog.schema.json`：字段和枚举契约。
- `docs/development/ai/feature-catalog.template.json`：初始化脚手架，不是产品事实。
- `scripts/feature_catalog.py`：零第三方依赖的校验、查询和生成工具。

功能层级固定为：

```text
domain → capability → feature
```

`implementation_status` 描述实现进度：`not_started`、`in_progress`、`implemented`、`verified`。
`maturity` 描述生产成熟度：`prototype`、`beta`、`production_candidate`、
`production_ready`、`production_proven`。实现完成不能自动推导生产就绪。
`platforms` 使用项目自定义的小写 kebab-case 标签，例如 `backend`、`web`、`cli` 或
`ios-app`，分发包不预设技术栈。计划中的 feature 可以暂时没有测试路径和证据，但仍需
明确验收标准；升级到 `verified` 后必须有测试路径和通过证据。

## 初始化与日常命令

初始化只在活动清单不存在时创建，绝不覆盖项目数据：

```bash
python3 scripts/feature_catalog.py --init
```

维护或 CI 使用：

```bash
python3 scripts/feature_catalog.py --validate
python3 scripts/feature_catalog.py --generate
python3 scripts/feature_catalog.py --check
python3 scripts/feature_catalog.py --query "release evidence"
```

`--check` 同时验证清单语义和矩阵漂移。查询结果优先返回匹配功能及其必要祖先，
不会把整个目录倾倒给 AI。路径必须是仓库内相对路径，证据引用必须可追溯到项目文件。

## 生产成熟度门

- `verified` 的 feature 至少要有一条 `passed` 证据。
- `production_candidate` 的 feature 至少要有一条 `passed` 证据。
- `production_ready` 需要通过的 unit、integration、e2e、release 证据。
- `production_proven` 在上述证据之外还需要通过的 live 真实环境证据。
- `blocked`、`partial` 或缺失日期/命令/引用的证据不能支撑成熟度升级。

项目可以扩展本地 CI 或 brief 工具调用 `--query`，但不应把本项目的业务功能、任务
ID 或路径写回 dev-workflow 分发仓库。

## 升级与卸载边界

活动 `feature-catalog.json` 和生成的 `FEATURE-MATRIX.md` 不属于安装器管理文件，
升级不会覆盖它们，卸载也应保留它们。流程包中的 Schema、模板、说明和工具遵循
manifest 所有权与哈希规则；项目修改过的流程文件由卸载器保留。
