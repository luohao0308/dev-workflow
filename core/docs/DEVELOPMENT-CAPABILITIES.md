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

| 领域 | Capability ID | 触点 |
|---|---|---|
| API | `api:rest-openapi` | REST endpoint、HTTP contract、OpenAPI |
| API | `api:graphql` | GraphQL schema、resolver、operation |
| API | `api:grpc` | protobuf、gRPC service |
| API | `api:websocket` | WebSocket protocol/event |
| API | `api:sse` | Server-Sent Events |
| Containers | `containers:oci-docker` | OCI image、Dockerfile、image supply chain |
| Containers | `containers:compose` | Docker Compose service/runtime |
| CI/CD | `cicd:github-actions` | GitHub Actions workflow |
| CI/CD | `cicd:gitlab-ci` | GitLab pipeline |
| CI/CD | `cicd:jenkins` | Jenkins pipeline |
| CI/CD | `cicd:generic` | Other CI provider or repository pipeline |
| Deployment | `deployment:compose` | Compose-based deployment |
| Deployment | `deployment:kubernetes-helm` | Kubernetes manifests, Helm chart, rollout |
| Deployment | `deployment:vm-systemd` | VM, systemd service deployment |
| Deployment | `deployment:serverless` | Function/serverless deployment |
| Deployment | `deployment:generic` | Other deployment target |

When an enabled ID matches a task touchpoint, apply its installed specialist pack guidance. If the capability is enabled but its specialist pack is absent, report that the profile is declared but detailed governance is unavailable. S5 defines the registry and routing contract; S6 supplies concrete specialist packs.
