# dev-workflow 功能清单流程包提取计划

_状态：completed_
_批准：用户已确认采用可选 `feature-catalog` 流程包_
_基线：v0.2.1 + Bash 3.2 兼容修复_
_完成：2026-08-17_

## 目标

把 Harness 中已经验证的功能清单能力提炼为通用、可选、零第三方依赖的
`feature-catalog` 流程包，同时保持项目真实功能数据和生成人类矩阵属于目标项目。

## 边界

- 流程包提供通用 Schema、初始化模板、字段/成熟度契约、Python 标准库工具和接入说明。
- 目标项目保存自己的 `feature-catalog.json`、`FEATURE-MATRIX.md`、代码/规格/测试路径和证据。
- 不把 Harness 的业务功能、路径、任务 ID、brief 路由或项目数量断言复制进分发仓库。
- 不升级 `.dev-workflow/manifest.json` 的 schema；版本从 `0.2.1` 提升到 `0.3.0`。

## 实施切片

### S1：通用契约与模板

- 新增 `packs/feature-catalog/` 的通用 Schema、模板和使用说明。
- 泛化实现状态、生产成熟度、证据和路径安全规则。
- 验收：模板不含 Harness 专属事实，正负 fixture 规则明确。

### S2：工具与单元测试

- 提取并泛化 `feature_catalog.py`，支持 `--init`、`--validate`、`--generate`、`--check`、`--query`。
- 支持 `--root`/路径注入，活动目录缺失时不隐式创建，`--init` 不覆盖已有项目数据。
- 新增 distribution 级标准库测试，覆盖结构、层级、证据、成熟度、路径、查询、Markdown 转义、幂等和漂移。
- 验收：`python3 -m unittest tests.test_feature_catalog -v` 全绿。

### S3：安装、审计、升级和卸载集成

- 保持 Core-only 行为不变；`feature-catalog` 作为可选 pack，`--all-packs` 包含它。
- Bash/PowerShell audit 在已安装该 pack 时检查活动目录和矩阵；pending 产生告警，ready 对无效目录/漂移失败。
- 集成测试证明 dry-run、安装、重装、升级、部分卸载和被修改项目数据保留。
- 验收：Bash 集成全绿；PowerShell 在可用环境全绿；manifest 继续 schema 2。

### S4：导航、发行和回灌

- 更新 README、Core 条件规则、docs 导航、WORKFLOW-ADOPTION 和版本号 `0.3.0`。
- 在临时 Core-only/all-packs 目标项目中完成安装、初始化、生成、审计和卸载回归。
- 回灌 Harness：保持现有项目清单数据不变，仅记录迁移边界和验证证据。
- 验收：`git diff --check`、Bash 语法检查、文档/脚本测试通过；不执行 tag、push 或 release。

## 回退点

- 每个切片独立提交前可通过恢复新增 pack 文件或不发布 `0.3.0` 回退。
- 不修改目标项目数据；卸载器按 manifest 所有权规则保留项目活动清单和生成矩阵。

## 完成证据

- Schema 和模板通过 `python3 -m json.tool`；Python 工具与测试通过 `py_compile`。
- `python3 -m unittest tests.test_feature_catalog -v`：13 passed。
- `LC_ALL=C LANG=C bash tests/integration.sh`：通过 Core-only、all-packs、重装、审计、漂移、部分/完整卸载回归。
- Bash 安装、审计、卸载和集成脚本通过 `bash -n`；`git diff --check` 通过。
- Harness 仅新增 FCAT-002 提取留痕；既有活动清单、矩阵、定制工具和 Docs CI 保持不变，项目文档门禁通过。
- 当前环境没有 `pwsh`，PowerShell 对称实现与测试未在本机执行；未执行 commit、tag、push 或 release。
