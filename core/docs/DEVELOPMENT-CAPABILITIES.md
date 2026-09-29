# 项目能力路由

`.dev-workflow/manifest.json` 的 `enabledCapabilities` 是项目明确声明的技术触点，不是已安装流程包清单。旧 manifest 升级到 schema 5 时默认为空；安装器不扫描代码、不推断栈，也不自动启用 profile。

通过安装器显式维护声明：

```sh
bash scripts/install.sh --target /path/to/project --enable-capabilities api:rest-openapi,containers:compose
bash scripts/install.sh --target /path/to/project --disable-capabilities containers:compose
# PowerShell: -EnableCapabilities 'api:rest-openapi','containers:compose'
# PowerShell: -DisableCapabilities 'containers:compose'
```

升级未传这两个参数时保留原声明。同一 ID 同时启用和禁用时，禁用优先。部分卸载流程包不会改变项目能力声明；完整卸载会删除 manifest。

| 领域 | Capability ID | 触点 | 专项 pack |
|---|---|---|---|
| API | `api:rest-openapi` | REST endpoint、HTTP contract、OpenAPI | `api-governance` |
| API | `api:graphql` | GraphQL schema、resolver、operation | `api-governance` |
| API | `api:grpc` | protobuf、gRPC service | `api-governance` |
| API | `api:websocket` | WebSocket protocol/event | `api-governance` |
| API | `api:sse` | Server-Sent Events | `api-governance` |
| Containers | `containers:oci-docker` | OCI image、Dockerfile、image supply chain | `containers` |
| Containers | `containers:compose` | Docker Compose service/runtime | `containers` |
| CI/CD | `cicd:github-actions` | GitHub Actions workflow | `delivery-cicd` |
| CI/CD | `cicd:gitlab-ci` | GitLab pipeline | `delivery-cicd` |
| CI/CD | `cicd:jenkins` | Jenkins pipeline | `delivery-cicd` |
| CI/CD | `cicd:generic` | Other CI provider or repository pipeline | `delivery-cicd` |
| Deployment | `deployment:compose` | Compose-based deployment | `deployment` |
| Deployment | `deployment:kubernetes-helm` | Kubernetes manifests, Helm chart, rollout | `deployment` |
| Deployment | `deployment:vm-systemd` | VM, systemd service deployment | `deployment` |
| Deployment | `deployment:serverless` | Function/serverless deployment | `deployment` |
| Deployment | `deployment:generic` | Other deployment target | `deployment` |

The specialist packs are independent. Install only the pack that matches the
enabled capability; no pack enables a capability by itself. Existing `contracts`
and `operations` packs remain reusable foundations, while these S6 packs add
domain-specific checklists and entry points.

When an enabled ID matches a task touchpoint, apply its installed specialist pack guidance. If the capability is enabled but its specialist pack is absent, report that the profile is declared but detailed governance is unavailable. S5 defines the registry and routing contract; S6 supplies concrete specialist packs.
