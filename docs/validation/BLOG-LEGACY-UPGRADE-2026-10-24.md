# 博客旧安装受审阅升级验证（2026-10-24）

dev-workflow v0.13.1 为已有 v0.6.0 安装提供严格限定的审阅冲突事务。原 `apply` 不接受冲突，`resolve-plan` 仅处理同时出现的三项受保护冲突：未知旧 Core 基线、接入文档文本重叠、定制交付 guard 原样保留。解析材料逐项绑定原计划、文件前像、旧／新分发与审阅结果；`apply-resolved` 在原生命周期／配置锁内重新计算并核对，保留原始冲突与解析摘要到事务日志。旧 Core 未被伪造成已证明的基线。

## 来源与边界

本轮的实际目标是用户本机 luohao-blog 检出，原 HEAD `63dd394`、workflow manifest 0.6.0、九个包、onboarding ready；有未提交业务修改。远端博客 main 当时为 `4dcd88e`，仅用独立克隆评估最新业务代码。没有 push、创建博客 PR、改 GitHub 设置或操作生产服务器；博客交付权限字段保持原值。

准确 v0.6.0 Tag 基线对 v0.13.1 的原始计划列出 70 项和三处受保护冲突。审阅结果采用新版 Core 受管区块且保留项目区外原文字节；保留项目接入记录历史并加上当前范围；定制 `scripts/delivery_guard.py` 保持原字节。该 guard 在受保护分支直推、分支保护、按配置的独立 Review 上仍有比通用脚本严格的约束，不能用新版脚本直接替换。manifest 记录实际保留文件和新版源的双哈希；审计只对这一路径与准确哈希给出“经审阅保留”提示，下一次升级仍会产生需审阅的冲突。

历史 `gitPolicy.policyChangedBy=codex` 仅作为已有来源值在 Bash/PowerShell 安装、审计中识别；新安装和新策略修改不会签发该值。实例中实际 `gitPolicy` 内容和 `independentReviewRequired=false` 未变。

## 本机验证

- 审阅式升级的单元回归覆盖冲突范围、Core 区外保留、guard 原样保留、篡改与输入漂移拒绝、大日志回滚、缺失 guard 拒绝及日志容量边界。既有自动 `apply` 仍拒绝冲突。
- 从博客原检出复制准确 70 个受管路径、manifest、Git exclude 和一份未提交前端文件的隔离模拟副本；三项冲突的原计划条目、manifest 与 exclude 摘要与原目标完全一致。模拟 `apply-resolved` 后 strict check 与审计 ready，原权限和 UI 文件哈希不变；下一次 plan 将 guard 列为冲突；rollback 后 Core、接入记录、guard、manifest 和 UI 文件逐字节恢复。
- 原目标先备份已有受管文件、manifest 与 Git exclude，并记录九个原有脏文件哈希。最终事务 `af921cf9db274520a686dcca98f10a33` 把本地 workflowVersion 提至 0.13.1；审计和 strict check 均 ready，仅有明确的审阅 guard 提示；上述权限和九个脏文件哈希不变。先前以未发行本地 0.13.0 修补构建执行的过渡事务已准确回滚，未作为最终安装版本。
- 博客实际检出的后端 `go test ./...` 与前端 `pnpm lint`、`pnpm typecheck`、`pnpm build` 通过；最新 main 的独立克隆也通过相同应用检查。公开首页与状态页的只读 GET 在检查时均为 HTTP 200，这不构成 P2 生产验收。

完整 dev-workflow 本地检查、Windows/PowerShell CI 与 v0.13.1 发行结果以对应 CI、Release 为准。本轮没有把 luohao-blog 生产 Compose（多服务、持久卷、无可信 P2 宿主）称作已通过 P2 `accepted`；其离线部署状态仍为 `executionAvailable=false`、`runtimeVerification=unknown`、`productionReady=false`。
