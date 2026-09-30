# CI Git 边界检查

`info/exclude` 只影响当前克隆中的未跟踪文件，不能作为团队安全门禁。启用 Delivery pack 的项目应把 Git 边界检查加入 required CI；该检查以 Git index 为输入，因此不受 runner 的本机 exclude 配置影响。

```yaml
name: Git Boundary Check
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  git-boundaries:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python3 scripts/check-git-boundaries.py --repo .
```

将 `git-boundaries` 配置为 CI 的 required check。其他 CI 平台运行同一命令即可。

该工具是误提交预防和高置信度秘密标记检查，不是完整 secret scanner，也不能替代 GitHub Secret Scanning、组织 DLP 或凭据轮换流程。发现疑似泄漏时，CI 只报告路径和类别，不输出内容；应立即吊销凭据并按组织流程处理历史清理。

例外必须精确到文件并留在 CI 命令中，例如 `--allow-path docs/project-memory/shared-policy.md`。不接受目录级或通配 allowlist。环境变量示例优先使用 `.env.example`，其中只能包含占位值。
