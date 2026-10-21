# 流程升级、回退与文档归属

仅在升级任务中读取本指南。升级工具位于新版本 dev-workflow 分发目录的 `scripts/upgrade.py`，不复制到目标项目；可选 `workflow-upgrade` Skill 负责组织审阅，直接运行脚本同样有效。要求 Python 3.10+；非平凡文本三方合并还要求 Git。工具不下载版本、不修改 Git 索引、不执行发布。

## 先计划，再应用

首次使用需准备 manifest 所记 `workflowVersion` 的完整原始分发目录；工具会核对版本和已安装文件哈希。不能用当前项目文件伪造旧基线。schema 1–4 的安装需先通过兼容的安装器迁移到 schema 5；无法证明的旧 Core 区块不会自动合并。

```sh
python3 /new-dev-workflow/scripts/upgrade.py plan --target /project --baseline /old-dev-workflow --output /tmp/upgrade-plan.json
python3 /new-dev-workflow/scripts/upgrade.py apply --target /project --plan /tmp/upgrade-plan.json
```

计划文件必须是项目和新旧分发目录之外的新文件。审阅其中每个路径的动作、原因、冲突，以及相关旧版/当前/新版正文。计划只读取状态；apply 在锁内重新计算并核对整份计划，输入变化需重新生成。任何冲突都会拒绝整份应用，不留下部分合并正文。没有强制跳过基线或冲突的参数。

- 工具只升级已安装的流程包；新增包继续通过显式安装选择。
- 未改动文件更新到新版；可安全合并的文本保留项目修改；二进制冲突、基线缺失、上游删除和本地删除需人工处理。
- `AGENTS.md` 只替换完整且唯一的受管 Core 区块，区块外项目规则保留。区块版本和哈希单独记录；未知旧区块拒绝自动合并。
- 已修改的 `delivery_guard.py` 拒绝自动合并。项目配置、能力启用、接入状态与执行权限不因升级改变。
- 原有 preserved/legacy 文件保留；来源删除仍需显式处理，不自动清除项目资料。

成功后返回 transaction 标识，并在 `.dev-workflow/upgrades/<ID>/` 保存日志和新分发的原始基线快照。后续 plan 可省略 `--baseline`，使用 manifest 指向的快照；它记录分发原文，不是合并后的项目正文。快照不完整或哈希不匹配时停止，改用完整的对应版本分发目录。升级后另行安装了包时，旧快照可能缺少该包，应显式提供完整基线。

## 回退与中断恢复

```sh
python3 /new-dev-workflow/scripts/upgrade.py check --target /project --json
python3 /new-dev-workflow/scripts/upgrade.py rollback --target /project --transaction ID
```

日志在首次产品文件写入前保存原始内容、拟写入内容、哈希与权限；manifest 最后写入。跨文件更新不是文件系统原子事务：异常或进程退出可能留下部分写入，日志状态会阻止后续安装、卸载、配置或升级操作。检查对应事务，使用同一引擎和明确的 ID 回退，不盲目删除日志或锁后重跑。

回退逐路径检查文件仍符合事务记录，恢复前再次检查；后续用户修改或权限改变会阻止覆盖。此时保留日志与用户修改，报告冲突并人工决定下一步。回退可能已恢复部分其他路径，不能把失败当成全部完成。已完成回退可重复执行。

安装、卸载、配置和升级共用本机生命周期锁。仅在明确回退对应事务且能证明原进程已退出时回收该事务的残留锁；活进程、未知来源锁不会自动清除。恢复过程另有互斥保护；若恢复进程退出留下 `recovery.lock`，工具会保守停止，需先核实没有活动恢复进程后人工处理。旧版脚本不支持此协议，操作期间不要并行使用旧工具。日志及快照含项目内容，应按本机资料管理；卸载保留这些记录，Git 本机排除规则继续保护它们。

## 将模板移交项目维护

```sh
python3 /new-dev-workflow/scripts/upgrade.py transfer --target /project --paths docs/PROJECT-SUMMARY.md --dry-run
python3 /new-dev-workflow/scripts/upgrade.py transfer --target /project --paths docs/PROJECT-SUMMARY.md
```

只对明确点名并已审阅的路径执行。允许根 `DESIGN.md`、项目摘要和已安装的架构、设计、契约、开发、运维 Markdown 文档；本机记录、任务上下文、Core 规则、脚本与 `docs/development/ai/` 不可转移。转移将归属改为 preserved，并从该文件的本机受管排除项中移除；不暂存、不提交，也不授予对外共享权限。后续升级、重复安装和卸载保留这些文档，即使文件暂时缺失也不重建。归属转移本身也有可回退事务。

## 元数据和审计

manifest 保持 schema 5，新增可选 `upgradeState`：`schemaVersion: 1`、`coreBlock`（版本、原始基线哈希、合并后安装哈希）、`projectOwned`、`lastTransaction` 与可选 `baselineSnapshot`。它们记录升级证据，不是配置或授权来源。旧 schema 5 未升级项目不要求这些字段。

升级后运行分发端 audit。`upgrade.py check --strict` 以及严格 audit 会将升级后再次修改 Core 区块的告警视为失败；这表示需要审阅定制，并非证明定制错误。结构、哈希和锁检查不能替代规则语义审查、项目测试或真实平台验证。
