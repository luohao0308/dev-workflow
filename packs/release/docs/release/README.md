# 发布准备（可选 release 包）

此包提供只读发布检查与计划记录。它不创建或移动 Git tag、不推送、不创建远端 Release、不构建镜像、不部署，也不将安装或已有 push 权限解释为发布授权。没有安装 Skill 也可以运行脚本。

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

任何输入声明（包括“CI passed”）都不会提升验证状态。CI 成功不代表镜像已构建、服务已部署或线上已验收。`--check-plan` 是重新运行本地 preflight，不是授权令牌，也不证明远端资源状态；真实发布执行不在当前版本范围内。
