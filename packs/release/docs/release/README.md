# 发布准备与受控执行（可选 release 包）

`release_prepare.py` 提供只读发布检查与计划记录。`release_execute.py` 提供执行计划和进程内 SDK；`release_github.py` 提供真实 GitHub.com Tag / Release 适配器，`release_host.py` 提供受信 GitHub Actions 授权集成。本地 CLI 仍仅准备；真实执行需要项目之外的可信宿主策略、凭据与人工环境审批。安装或已有 push 权限不构成发布授权。没有安装 Skill 也可以运行脚本。

## 项目配置

在已采纳的 `workflow.config.json` 中启用 `release` 能力：

```json
{
  "schemaVersion": 1,
  "enabledCapabilities": ["release"],
  "commands": {},
  "documents": {},
  "extensions": {
    "release": {
      "strategy": "commit-sha",
      "tagPrefix": "v",
      "components": ["web", "api", "proxy"]
    }
  }
}
```

使用 Core 配置工具采纳修改后的配置；未采纳或与安装状态冲突的配置将阻止准备。三种策略：

- `none`：不管理版本，不要求版本号，也不提出打 tag。
- `commit-sha`：以准确提交追踪产物，不创建 Git tag。
- `semver-tag`：要求明确的 SemVer 版本号，允许输入一个 `v` 前缀；规范化后附加配置的 `tagPrefix`。只检查本地同名 tag。同名同提交会报告已存在，不同提交会失败。远端 tag 状态保持未核实。

## 使用

安装包后从目标仓库执行：

```sh
python3 scripts/release_prepare.py --repo . --json
python3 scripts/release_prepare.py --repo . --sha HEAD --version v1.2.0 --json
python3 scripts/release_prepare.py --repo . --component-source web=HEAD --component-source api=HEAD~1 --component-build web='local build' --json
python3 scripts/release_prepare.py --repo . --output .dev-workflow/releases/next.json
python3 scripts/release_prepare.py --repo . --check-plan .dev-workflow/releases/next.json
```

`--sha` 可指定提交或引用，默认 HEAD；解析结果固定为完整 commit SHA。检查计划时，重新解析保存的目标引用（也可显式 `--sha`），HEAD 或目标变更会使计划失效。配置改变、脏工作树、本地 tag 冲突也使检查失败。

本地离线检查禁用 Git fsmonitor、交互凭据提示与按需对象获取。为避免 Git 回调或隐式网络访问，准备及 `--check-plan` 拒绝带有 partial-clone/promisor 配置键的仓库（即使配置值为 false）、Git submodule/gitlink 和启用内容 filter 属性的工作树；这些工作树暂不支持离线发布准备。

`--component-source NAME=SHA` 可独立指定组件来源，不强制组件与目标提交一致。未提供的组件来源为 null；`--component-build NAME=DESCRIPTION` 记录本地构建或其他来源声明。两者都不证明构建、部署或线上状态。

默认只打印结果。`--output` 才新建记录，路径必须在仓库 `.dev-workflow/releases/` 内，已存在文件不覆盖。该目录的记录不参与脏工作树检查；其余未提交与未跟踪文件均阻止准备。记录应由项目保留，卸载包不删除记录或项目配置。

## JSON 记录契约

记录 `schemaVersion: 1`、`kind: release-preparation`，字段如下：

| 字段 | 语义 |
| --- | --- |
| preparedAt | UTC 准备时间 |
| strategy / version | 配置策略和显式版本；非 SemVer 策略可为 null |
| headSha / targetRef / targetSha | 准备时 HEAD、目标输入及完整目标提交 |
| configurationHash | 规范化 release 配置的 SHA-256，用于失效检查 |
| tag / tagStatus | 本地 tag 建议和本地检查结果，策略未请求时 tag 为 null |
| components | name、sourceSha、buildSource、artifactDigest/imageId（未核实时为 null）、verification（固定 unknown） |
| environment / configurationVersion / migrationVersion / previousDeployment | 准备阶段未核实，均为 null；不从历史文档猜测生产身份 |
| states | ci、image、deployment、live 四个独立状态，初始全部 unknown |
| scope | 准备边界说明 |

任何输入声明（包括“CI passed”）都不会提升验证状态。CI 成功不代表镜像已构建、服务已部署或线上已验收。`--check-plan` 是重新运行本地 preflight，不是授权令牌，也不证明远端资源状态。

## 执行计划与宿主集成

```sh
python3 scripts/release_execute.py status
python3 scripts/release_execute.py plan --repo . --preparation .dev-workflow/releases/next.json
# 仅在明确需要保存时指定输出；已有文件不覆盖。
python3 scripts/release_execute.py plan --repo . --preparation .dev-workflow/releases/next.json --remote origin --output .dev-workflow/releases/execution.json
```

默认只打印 JSON；本地 `status` 的 `executionAvailable` 固定为 `false`。`plan` 重新验证准备记录、当前提交/配置和 tag 身份，固定 remote 名称及 URL，不能证明远端存在或可用。执行计划输出要求准确目标路径被 Git 忽略，且整个 `.dev-workflow/` 没有已跟踪文件。可用显式 `--release-spec` JSON 文件准备远端 Release 的准确内容，格式及 SDK 边界见 [执行集成契约](EXECUTION.md)。Release notes 与本机记录只有用户明确要求时才写入。

执行基础把本地 tag 创建、远端 tag 推送、远端 Release 创建分成独立操作。分发 CLI 的 `execute` 在任何仓库读取、网络访问或变更前拒绝；真实执行使用固定可信版本的宿主，不从待发布项目加载授权实现。宿主核验签名 OIDC、受保护环境中准确 bundle hash 的真实人工审批，并在独立账本仓库创建不可覆盖的一次性消耗标记。不要通过自制授权 JSON、伪造 OIDC、环境变量、TTY 确认、加载任意 provider 文件或直接调用 Git/托管平台命令绕过该边界。

首次接入须配置可信工作流、固定仓库 ID / workflow SHA、人工 reviewer ID、目标和独立账本仓库身份，以及宿主管理的凭据。宿主首先支持 GitHub-hosted Linux，使用 `/usr/bin/openssl` 验证 RS256；SDK 与本地准备仍按跨平台测试支持。远端 tag 只创建 lightweight ref，目标 commit 必须已在远端；不上传 Git 对象、不执行分支 push。Release 检查使用具有 push 可见性的凭据分页覆盖草稿与已发布记录，准确匹配内容，创建时 `make_latest=false`。没有配置可信宿主或尚未取得真实审批时，只交付计划和具体阻塞。分发端 `scripts/release_host_runner.py` 和 [工作流模板](host-workflow.example.yml) 用于独立宿主，不是目标项目的本地授权入口。完整设置、失败处理与当前验收边界见 [执行集成契约](EXECUTION.md)。
