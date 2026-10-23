# 恢复续跑与诊断验证（2026-10-23）

## 范围与源码

仅修改 dev-workflow；未安装、升级或部署 luohao-blog。主仓库基于 v0.11.0 的 `42cf9e6d4abb3fae9b3b38ef77af4119803d2d13`，功能分支为 `codex/recovery-resume-diagnostics`。本记录对应提交前固定源码验收；主仓库后续交付以该分支的实际提交和 CI 记录为准。

独立合成仓库验证提交为 `e4e1c1e616ff79aff6730e6662d5169cf8337c47`，分支 `codex/recovery-resume-validation`。已逐字节比较主仓库的 72 个产品／测试 Python 文件，与该快照一致。

运行：https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39893477241 。

## 完成内容

- 空选中状态只接受最后写入是独立恢复授权允许的准确候选 DELETE、签名网关完成记录包含 HTTP 204 空响应摘要、认证直接查询证明缺失，且未选中完整映射不变。随后申请全新恢复授权，动作仅为按准确旧配方 create/start。
- 完整 HTTP 错误仅证明写入已结束，不证明清理成功；500／404 后资源外部消失、恢复实例创建后又外部消失、未知上游结果均保持阻塞。
- `FileWriterGate.diagnose_generation` 只读验证签名状态并返回 pending/unknown/done 统计、固定原因和指引；不追加签名记录、关闭 generation 或签发 proof。
- `deployment_recover.explain_failure` 仅解释白名单错误码，未知异常不回显；不读取现场、访问网络、签发请求或授予权限。
- 更新当前治理与恢复文档；历史验证记录不改写。

## 已核验结果

五个真实 Linux Docker／mTLS job 均成功：原部署在创建候选后、删除旧实例后崩溃两组；再加恢复删除候选、创建旧版本恢复实例、启动恢复实例后再次崩溃三组。故障均由独立子进程 `os._exit` 注入，网关完成真实写入，observer 尚未记录响应。父进程确认死亡后重新构建可信适配器、核对现场及签名记录，生成新的独立恢复请求。

五组制品均报告 `restoredBefore=true`、`preservedApiInstance=true`、health/smoke 为 passed、恢复请求重放拒绝。后三组还确认 `actualRecoveryChildCrash=true`、`independentRecoveryRequest=true`。所有写入使用明确的合成测试授权，`realRecoveryGitHubOIDC=false`；本轮不冒充真实 GitHub 人工审批验证。未启用的真实审批 job 按配置跳过。

独立代码审查曾指出“definitive completion 不等于成功删除”；已用准确 HTTP 204 空响应摘要修复并加入拒绝回归，复审通过。根因专项 3 项通过，覆盖丢失 observer 响应后的正例与失败删除后的负例。

最终运行 `success`，10 个实际运行 job 全部成功：Ubuntu/macOS × Python 3.10/3.13、Windows 全量 Python 与 PowerShell 集成、五组真实 Docker 崩溃恢复。两个真实审批 job 在合成模式下按配置跳过。

- Ubuntu Python 3.10：634 项，623 通过、11 项条件限定跳过，Bash 集成成功。
- Windows Python 3.10：554 项，535 通过、19 项条件限定跳过；随后 PowerShell 明确输出 `PowerShell integration tests passed.`。
- 本机 Python 3.14 最终完整检查：634 项，623 通过、11 项条件限定跳过；Python AST、Bash 语法及 Bash 安装／卸载／升级集成通过，`scripts/check.sh` 退出码 0。
- 早期边编辑文档边运行的本地检查在安装／卸载之间触发源文件哈希保护，633 项中一项拒绝卸载；该次不作为最终验收。固定源码后重跑上述完整检查通过，没有放宽哈希保护。

本轮不新增依赖、不改持久记录 schema 或放宽权限策略；网关响应摘要由既有签名 finish 记录重新读出，未知完成仍不能变成成功删除。

## 保留的限制

仍仅支持既有无状态、非 root、只读、无挂载、无需迁移的单组件规格；不保证任意中断点可恢复。未知写入不能靠 TTL、重启或手工修改记录解除。中断操作仍需原 coordinator 身份；每次恢复重新授权，不退款、不隐式重试。密钥轮换、备份迁移、业务部署和生产验收未扩展，`productionReady=false`。
