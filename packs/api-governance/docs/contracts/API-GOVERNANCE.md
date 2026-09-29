# API 治理专项

适用能力：`api:rest-openapi`、`api:graphql`、`api:grpc`、`api:websocket`、`api:sse`。

只有在项目 manifest 启用了对应 capability 且本 pack 已安装时，本规则才是专项治理要求。

## 最小检查

- 明确机器契约的唯一来源；OpenAPI、GraphQL schema 或 protobuf 不手工修改生成物。
- 写清鉴权、授权、输入限制、错误结构、超时、重试、幂等和敏感字段脱敏。
- 破坏兼容的字段、状态码、事件或消息变更必须有版本/弃用窗口和消费者迁移方案。
- 运行契约测试和至少一个关键消费者回归；流式协议覆盖断连、重连、重复和终止语义。
- 生成物、示例和运行行为一致，示例不得包含真实凭据或签名 URL。

详细契约模板复用 `contracts` pack 的 `docs/contracts/CONTRACT-TEMPLATE.md` 和 `CHANGE-CHECKLIST.md`。

## 停止条件

无法确认生产者、消费者、兼容窗口或回滚方式时，先停在 L2 决策门，不把未验证的 API 设计当作完成。
