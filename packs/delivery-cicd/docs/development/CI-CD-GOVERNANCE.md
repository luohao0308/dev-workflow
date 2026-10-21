# CI/CD 治理专项

适用能力：`cicd:github-actions`、`cicd:gitlab-ci`、`cicd:jenkins`、`cicd:generic`。

## 最小检查

- 工作流从默认分支或发布分支触发，权限最小化，第三方 action/plugin 固定到可审计版本。
- 构建、测试、契约/安全检查和制品发布有明确依赖顺序；required checks 与 CI 配置一致。
- secrets 只通过平台 secret/受控注入进入需要的 job；日志脱敏且不打印环境快照。
- 发布制品绑定 commit/tag/digest 等不可变身份，失败路径有停止条件和重试/回滚边界。
- workflow 变更自身经过 lint/静态校验和最小真实入口冒烟，不能只验证 YAML 可解析。

## 停止条件

无法确认 workflow 权限、required check、制品身份或 environment approval 时，不把 CI 绿灯当作可发布证据。
