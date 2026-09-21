# Git Worktree 隔离开发流程

_模式：由 `docs/development/README.md` 选择 required / recommended / disabled_
_更新：YYYY-MM-DD_

## 1. 目标

代码任务在独立分支和标准 Git worktree 中完成修改、检查、运行时验证和提交；集成时只移动已经验证的提交，不覆盖项目工作树中的其他改动。

```text
确认仓库与基线
→ 创建/核验任务 worktree
→ 修改与定向验证
→ 必要时重启任务服务并冒烟
→ 精确暂存与提交
→ 同步最新目标分支并重新验证
→ 按 manifest 的权限策略 push 并创建/更新 PR
→ 通过 PR、CI 和独立 Review 门禁
→ 按权限策略合并远端 PR
```

## 2. 开始前核验

记录并确认：

```bash
git rev-parse --show-toplevel
git worktree list --porcelain
git branch --show-current
git rev-parse HEAD
git status --short --branch
```

### 大型计划拆分门

大型计划在创建任务 worktree、修改产品代码或创建交付 PR 前，先按 [实施计划](../plans/README.md) 的确认门拆成 `2-6` 个切片，并向用户展示目标结果、范围、依赖、验收方式和回退点。状态保持 `awaiting_user_confirmation`，直到用户批准或调整拆分。

确认后将切片写入 `docs/plans/`，默认使用一个任务分支和一个 PR；每个切片形成可验证的提交或检查点。只有切片可以独立发布、需要不同回滚窗口或必须隔离高风险时才拆成多个 PR。每次只推进一个切片，完成验证并记录证据后再进入下一个。

如果新证据实质改变已确认的范围、顺序、接口、迁移或风险，暂停后续提交并重新确认；切片内部的普通实现调整不触发新的确认轮次。

- 明确项目工作树、任务工作树、目标分支和基线 HEAD。
- 不复用归属、分支、HEAD 或状态不明确的 worktree。
- 项目工作树存在他人改动时，不 stash、reset、覆盖或顺带提交。
- 新 worktree 只能创建在已验证的任务目录中，不在产品仓库内部嵌套。

示例：

```bash
git worktree add <task-worktree-path> -b <task-branch> <base-ref>
```

## 3. 修改与验证

每组可独立验证的修改后：

1. 运行与改动直接相关的测试、lint、类型、静态或构建检查。
2. 执行 `git diff --check`。
3. 若运行时代码、配置、依赖或启动逻辑变化：
   - 核验任务服务的 PID、启动时间、命令行、工作目录和监听端口；
   - 只停止当前任务拥有的进程；
   - 使用项目已有启动方式重启；
   - 验证端口、进程和至少一个健康/业务冒烟入口。
4. 不按进程名批量结束共享的 Python、Node、Java、容器或其他进程。

## 4. 精确暂存与提交

```bash
git status --short
git diff -- <task-owned-files>
git add -- <task-owned-files>
git diff --cached --check
git diff --cached
git commit -m "<project commit format>"
```

- 禁止使用 `git add .` 和 `git add -A` 暂存范围不明的文件。
- 提交后确认任务工作树干净并记录已验证 SHA。
- push、PR 创建/更新和远端 PR merge 是否自动执行以及由谁执行，以 `.dev-workflow/manifest.json` 的 `gitPolicy` 为准；缺失时按 `manual + user`。
- 持久策略变更固定需要人工确认，不得由当前权限自我升级。一次性授权必须绑定 `repo + remote + remote URL + operation + source ref + target ref + exact SHA + expiry + maxUses`；任一项变化即失效，不改变 manifest 默认 actor。授权文件放在本地 `.dev-workflow/authorizations/`，不得提交。
- AI 执行 push、PR 创建/更新或远端 PR merge 前运行 `python3 scripts/delivery_guard.py check`。`actor=user` 时 guard 固定拒绝 AI 执行；用户本人按证据直接操作。`actor=ai` 的验证阶段可不带 `--consume`；紧邻真实远端操作的最终检查必须带 `--consume`，避免同一授权超次数复用。guard 失败或输出不是 `decision=allow` 时停止。
- dev-workflow 本地文件以 Git 解析出的 `info/exclude` 为保护边界；交付前若审计报告文件已被跟踪或最终 ignore 规则未生效，必须先解决告警，不能仅凭 managed block 文本判定安全。
- `forcePushAllowed=false`，不使用 `git push --force`；`directProtectedBranchPushAllowed=false`，不得直接 push 到保护分支。也不使用 `git reset --hard` 或语义不明的 ours/theirs。

## 5. 同步与重新验证

集成前重新读取目标分支 HEAD。目标已前进且任务分支未发布时，可以按项目策略 rebase：

```bash
git rebase <current-target-head>
```

发生冲突时先 `git rebase --abort`，再根据双方语义做明确决定。rebase 改变 SHA 后，重新执行所有适用检查、服务重启和冒烟。

## 6. PR 与集成

- 仅在项目工作树和任务工作树都满足项目的干净状态要求时集成。
- `codex/*` 只用于本地 Agent 临时 worktree 或执行分支，禁止直接 push 到任何远端，也不得作为线上 PR 的 source branch。
- 创建线上 PR 前，必须把已验证的提交移动到符合项目约定的交付分支，例如 `feat/*`、`fix/*`、`refactor/*`、`docs/*`、`test/*`、`chore/*`、`ci/*`、`build/*`、`perf/*`、`release/*` 或 `hotfix/*`；具体允许集合以项目规则为准。
- push 前核验 `git branch --show-current`，发现分支以 `codex/` 开头时停止交付，先切换或创建合规的线上分支，再重新检查提交和验证结果。
- 本地 `git merge` 只用于本地分支整理；项目要求线性历史时，先验证目标 HEAD 是任务 HEAD 的祖先，再使用 `git merge --ff-only <task-head>`。本地 merge 不获得 push 或远端 PR merge 权限。
- `pullRequestRequired=true`、`ciRequired=true`、`independentReviewRequired=true` 是默认质量门，不因 mode/actor 授权而关闭。实现者不得作为唯一审批者，AI review 或自审不计作独立批准。
- feature、bug、安全、跨模块或其他需要审计追踪的工作应先关联 Issue；小型、局部、低风险改动不强制创建 Issue。
- `mode=manual` 时必须获得本次操作确认；`actor=user` 时只能由用户执行，一次性授权不能覆盖 actor。若要改由 AI 执行，必须先通过独立人工确认修改持久 actor 策略。
- `mode=auto` 仅可与 `actor=ai` 组合；它只免除有效授权范围内的再次交互，不代表长期全局授权。AI 执行仍必须持有尚未过期、未超次数且与准确 SHA 完全匹配的一次性授权。push、PR 创建/更新、远端 PR merge 相互独立，不可互相推断授权。
- 远端 PR merge 前必须 fail-closed 验证：PR 存在且开放，head/base 与授权目标一致，准确 head SHA 未变化，required CI 全部通过，独立 Review 已批准，远端分支保护允许合并。任一项缺失、过期、失败或无法读取都停止。
- `--provider-evidence-file` 必须来自紧邻操作的托管平台查询，并绑定 repository、remote 名称与 URL、operation、source/target ref、准确 head SHA 和 `verifiedAt`；超过五分钟或字段不全即失败。push 还需 `force=false`、`delete=false`、`fastForward=true`、`targetBranchProtected=false`；PR 需远端 source SHA 和 base 存在证据；merge 还需 PR number、授权 grantId、open 状态、head/base、required checks、独立人工审批、mergeable 和分支保护允许状态。
- `deleteAllowed=false` 不授予任何删除权限；删除远端分支、标签、Release 或其他难恢复对象需针对明确目标另行授权。
- `privilegedOperationsDefault=deny`：tag/Release、package/image publish、deploy、migration/backfill、rollback、traffic switch、仓库设置、凭据和发布工作流操作均需逐目标授权，merge 不蕴含这些权限。
- manifest 只约束当前机器。远端仍必须用 branch protection、required checks、CODEOWNERS/独立审批和 environment approval 强制执行；远端门禁无法验证时停止交付。

示例授权文件：

```json
{
  "grantId": "change-123-push-1",
  "repository": "/absolute/path/to/repository",
  "remote": "origin",
  "remoteUrl": "git@github.com:example/project.git",
  "operation": "push",
  "sourceRef": "feat/change-123",
  "targetRef": "feat/change-123",
  "sha": "0123456789abcdef0123456789abcdef01234567",
  "expiresAt": "2030-01-01T00:00:00Z",
  "maxUses": 1,
  "approvedBy": "user"
}
```

示例最终检查：

```bash
python3 scripts/delivery_guard.py check \
  --operation push \
  --repo "$(git rev-parse --show-toplevel)" \
  --remote origin \
  --source-ref feat/change-123 \
  --target-ref feat/change-123 \
  --sha "$(git rev-parse refs/heads/feat/change-123)" \
  --authorization-file .dev-workflow/authorizations/change-123-push-1.json \
  --provider-evidence-file .dev-workflow/provider-evidence/change-123-push-1.json \
  --consume
```

本地 guard 是合规执行器的 fail-closed preflight，不是针对同一操作系统用户下恶意进程的安全边界；本地 JSON 的来源真实性最终仍依赖调用工具和人工审批通道。不可绕过的强制层必须配置在远端 Ruleset/Branch Protection、Required Checks、CODEOWNERS/Required Reviews 和部署环境审批中。

## 7. 完成条件

- 任务提交来自已核验的任务 worktree。
- 适用检查、重启和冒烟已完成。
- 最终 SHA、验证证据和剩余风险已记录。
- 无任务外文件被暂存或提交。
- 交付状态按 `committed → pushed → pr_open → ci_passed → review_approved → merged` 更新；未发生的阶段不得标记完成。
- PR 证据记录仓库/remote、PR 链接或编号、source/target ref、准确 head SHA、required CI、独立 reviewer、merge commit（如已合并）和验证时间。
- 集成、push、PR 和 worktree 清理符合项目规则。
