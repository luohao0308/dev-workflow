# 契约治理入口

_状态：待初始化 | 权威范围：对外可观察的 API、事件、Schema、CLI 和文件格式 | 更新：YYYY-MM-DD_

## 权威顺序

1. 已验证的运行中行为和机器可解析契约；
2. 生成机器契约的源代码或 Schema；
3. 契约测试与消费者测试；
4. 人工使用指南和示例；
5. 历史快照与归档。

人工指南不能悄悄覆盖机器契约。出现冲突时先验证当前实现，再同步修正文档和生成物。

## 契约索引

| 契约 | 类型 | 生产者 | 消费者 | 权威源 | 生成/验证入口 | 兼容策略 |
|---|---|---|---|---|---|---|
| <!-- name --> | HTTP/event/schema/CLI/file | <!-- producer --> | <!-- consumers --> | <!-- code/schema/runtime --> | <!-- command/test --> | <!-- version/deprecation --> |

## 生成物规则

- 机器使用的固定文件名保持稳定，不复制出 `final`、`new`、`latest` 等并行版本。
- 生成物写明来源、生成时间和版本/提交身份；无法验证来源时不伪造更新日期。
- 自动生成文件不手工修补；修改源定义后重新生成并检查差异。
- 历史快照进入归档并标注日期，不继续作为当前导入源。
- 示例只使用占位符或环境变量，不包含真实凭据、Cookie、Token 或签名 URL。

## 变更流程

契约变更先使用 [CHANGE-CHECKLIST.md](CHANGE-CHECKLIST.md) 判断兼容性。新增契约从 [CONTRACT-TEMPLATE.md](CONTRACT-TEMPLATE.md) 建立；涉及数据 Schema 或回填时同时使用 [MIGRATION-TEMPLATE.md](MIGRATION-TEMPLATE.md)。
