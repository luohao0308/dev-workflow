# dev-workflow 治理能力扩展计划

状态：`awaiting_user_confirmation`

本计划属于 `dev-workflow` 分发仓库本身，开发位置为：
`/Users/luohao/Desktop/vibecoding/dev-workflow`。

Harness 只是已接入的示例项目，不再承载本计划的实现、状态或临时资料。

## 目标

在现有 Git、分支、worktree 和文档边界之上，增加按风险和项目能力启用的治理层：

- 统一规则入口，消除分支/worktree 语义分裂；
- 增加团队级 Git 安全门禁；
- 提供只读 worktree 生命周期报告；
- 提供 `L0/L1/L2` 自适应技术决策门和停止条件；
- 让 API、容器、部署和 CI/CD 以可选能力与 profile 进入流程；
- 不让没有相关技术栈的项目被迫安装 REST、Docker、Kubernetes 或特定 CI 平台规则。

## 设计边界

Core 只负责通用判断、风险分级、复用优先、验证、回滚和所有权规则。

具体技术标准通过可选 pack/profile 提供：

- `api-governance`: `rest-openapi`、`graphql`、`grpc`、`websocket`、`sse`；
- `containers`: OCI/Docker、Compose 和镜像供应链；
- `delivery-cicd`: GitHub Actions、GitLab CI、Jenkins、generic；
- `deployment`: Compose、Kubernetes/Helm、VM/systemd、serverless 或其他目标。

安装的 pack 与项目实际启用的 capability/profile 分开记录在 manifest 中。

## 实施切片

| 切片 | 目标结果 | 主要范围 | 依赖 | 验收方式 | 回退点 |
|---|---|---|---|---|---|
| S1 | 统一规则入口 | 唯一的分支/worktree 决策表、文档引用和冲突扫描 | 无 | 文档校验、规则冲突扫描 | 文档回退 |
| S2 | 团队级 Git 安全门禁 | CI 检查本机记忆、上下文、日志、环境快照、凭据和已跟踪流程文件 | S1 | 合法样例通过，违规样例失败，workflow 校验 | 删除独立检查 |
| S3 | Worktree 生命周期报告 | 孤儿 worktree、重复分支绑定、未提交改动、已合并分支、磁盘占用和过期产物报告 | S1 | 构造多种状态并核对报告；默认只读 | 工具独立移除 |
| S4 | 自适应技术决策门 | `L0/L1/L2`、复用/边界/验证检查、ADR/RFC 触发条件和停止条件 | S1 | 用局部功能、跨模块功能、高风险变更演练 | 规则独立回退 |
| S5 | 可选能力模型和任务路由 | manifest `capabilities`、profile、能力缺失提示、API/容器/部署/CI/CD 触点路由 | S1、S4 | 安装/升级/审计矩阵和 profile 路由测试 | 保留旧 packs 行为 |
| S6 | 具体治理 packs | `api-governance`、`containers`、`delivery-cicd`、deployment profiles，以及安装器、卸载器、审计器和测试 | S2、S5 | 各 pack 独立集成测试、最小项目安装测试、审计结果 | 按 pack 独立禁用 |

## 决策等级

### L0：直接实现

不改变 API、事件、Schema、数据、权限、依赖、部署或运行时边界，且已有模式可复用。
不生成 ADR，不做方案比较，只执行定向验证。

### L1：轻量决策

新增功能或跨一个模块，存在复用/新建、同步/异步、内存/持久化等选择。
输出现状、推荐、主要边界和最小验证，不默认创建 ADR。

### L2：正式技术决策

涉及契约、迁移、安全、依赖、基础设施、性能、恢复、发布、长期所有权，或存在不可逆/高成本方案。
要求方案比较、兼容窗口、迁移、回滚、监控、所有权和验收证据，必要时建立 ADR/RFC 并等待确认。

## 停止条件

- 默认最多比较 2-3 个方案；
- 已有成熟仓库模式优先复用；
- 没有真实约束时不做规模、性能或成本假设；
- 不因“未来可能需要”引入依赖或抽象；
- 方案差异不足以改变验收结果时直接采用现有模式；
- 没有实际技术决策时不创建 ADR；
- 能力未启用时不得假装完成该能力的专业审查，应报告缺失并推荐 profile。

## 确认门

S1-S5 可按已确认范围继续准备；S6 的具体 pack/profile 会在 S5 完成后根据 manifest 设计和最小安装矩阵再次确认，避免一次性把所有技术栈规则强制进入默认安装。
