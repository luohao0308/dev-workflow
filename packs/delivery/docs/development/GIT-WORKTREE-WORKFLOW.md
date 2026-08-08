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
→ 按项目策略集成
→ 获得授权后 push/发布
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
- 不自动 push；不使用 `git push --force`、`git reset --hard` 或语义不明的 ours/theirs。

## 5. 同步与重新验证

集成前重新读取目标分支 HEAD。目标已前进且任务分支未发布时，可以按项目策略 rebase：

```bash
git rebase <current-target-head>
```

发生冲突时先 `git rebase --abort`，再根据双方语义做明确决定。rebase 改变 SHA 后，重新执行所有适用检查、服务重启和冒烟。

## 6. 集成

- 仅在项目工作树和任务工作树都满足项目的干净状态要求时集成。
- 项目要求线性历史时，先验证目标 HEAD 是任务 HEAD 的祖先，再使用 `git merge --ff-only <task-head>`。
- 需要 PR、人工审查或明确确认的项目，不绕过对应门禁。
- push、发布、生产变更或不可逆操作只在项目规则明确授权后执行。

## 7. 完成条件

- 任务提交来自已核验的任务 worktree。
- 适用检查、重启和冒烟已完成。
- 最终 SHA、验证证据和剩余风险已记录。
- 无任务外文件被暂存或提交。
- 集成、push 和 worktree 清理符合项目规则。
