# 可信主机接入与历史维护验证（2026-10-23—24）

## 范围与版本

基于 v0.11.1（`4a0b0bf622ba750d819b1bfe368345d16ba3126f`），仅修改 dev-workflow，分支 `codex/host-onboarding-maintenance`。未安装、升级或部署 luohao-blog。

本轮完成两项：可信主机配置模板与只读 doctor；认证历史 backup/verify/restore、健康宿主 rotate/status/resume。工具只存在于完整可信分发中，安装 deployment 包不会复制这些主机 CLI、模板或凭据入口到候选项目。新增 schema-v2 导入历史与维护状态，保留旧 v1 历史认证兼容。

## 审查与本地验收

存储/网关基础层与主机工具分开审查，修复后复审均通过。doctor 用 Git 原始对象比较文件字节，避免触发项目 clean/process filter；真实 Git 哨兵回归证明不执行过滤器。CLI 使用固定轮换错误码白名单，任意异常保持脱敏；真实 CLI rotate/status/resume 已执行验证。

本机 Python 3.14：697 项单元测试，685 通过、12 项条件跳过；Python AST、Bash 语法与安装/卸载/升级集成全部通过，`scripts/check.sh` 退出码 0。

实际子进程 `os._exit` 覆盖 intent、pending store/gate、import record、prepared、gate latch/retired、store retired、store/gate active 共十个持久化断点。原事务精确续跑后保持原始采集时间和固定深度来源；A→B→C 后 A→B 不复活 B。源数据变化、未知写入、未完成日志、已存在目标、复用身份/密钥、篡改事务均拒绝。

## 独立环境与平台矩阵

矩阵快照 `21af0847cf5cddb35f0793a447e42035cbf8c03d`，运行 [39978311938](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39978311938)。Ubuntu/macOS × Python 3.10/3.13 均执行 697 项测试（12 项条件跳过），Bash 集成全部通过。

首轮 Windows 执行 617 项测试，37 项条件跳过，1 项测试夹具错误：临时 Git 仓库受 autocrlf 转换影响，工作区原始字节与 HEAD blob 不同，doctor 正确拒绝。仅在测试仓库设置 `core.autocrlf=false`，未放宽产品比较规则。本机 doctor 12 项复测通过（1 条条件跳过）；修正后的 Windows [定向运行 39982555964](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39982555964)（提交 `d67ffc48813d42dce633585d754697373558176e`）doctor 12 项通过、5 项条件跳过，原生 PowerShell 集成明确输出 `PowerShell integration tests passed.`。主仓库最终全量 CI 另行验收，不将定向重跑称为全量通过。

首轮 maintenance-live 失败是测试脚本把新鲜采集时间戳也要求全等，随后三处历史比较也改为准确的原始 captured 记录。产品源码未因该失败修改。修正后的真实维护快照 `003ae8137412a698c6ae87e5c8e4bce2857bd582`，运行 [39979177485](https://github.com/luohao0308/dev-workflow-p0-host-public-20261022/actions/runs/39979177485)：maintenance-live 与原五组 Docker 崩溃恢复共六个实际 job 全部成功。未启用的跨平台与真实审批 job 按合成模式配置跳过；不把首轮整体运行描述为全绿。

194 个分发/测试文件与最新合成提交 `d67ffc48813d42dce633585d754697373558176e` 逐字节核对，差异为零。相对维护实测提交，最后只改 doctor 测试换行设置、版本号与主机文档链接；产品实现未变。合成工作流为定向 Windows 验证临时调整，未改主仓发布工作流。

## 真实维护结果

使用两个固定身份的合成 GitHub 仓库，在临时 Linux Actions Docker 环境中执行。真实 mTLS reader 和固定 GitHub GET 检查全部 pass：分发提交、运行状态、仓库与 commit 身份、审批环境 reviewer policy。未签发 OIDC 或执行授权；`authorityGranted=false`。

维护报告确认：轮换成功；旧历史对象、存储、网关拒绝使用；删除旧 key 文件后用新 key 读取导入历史；源目录不存在时独立 verify/restore 成功；恢复未创建 gate；容器全部实例保持不变；新网关与新 collector 核验成功。历史恢复与导入结果保留原始完整 snapshot。

五组原有真实 Docker/mTLS 场景覆盖部署创建候选/删除旧实例后崩溃，以及恢复删除候选/创建旧实例/启动恢复实例后再崩溃。均成功恢复旧版本并保留 api 实例。写入使用明确的合成测试授权，`realRecoveryGitHubOIDC=false`；本轮不冒充新的人工审批验证。

## 升级验证与保留边界

独立临时项目从真实 v0.11.1 tag 安装 deployment 包，升级到 v0.12.0 后验证新增维护基础模块正确安装、主机 CLI/模板未安装、用户数据保留；工具事务 rollback 回到 v0.11.1。没有使用业务项目进行实验。

所有报告仍为 `productionReady=false`。Windows CLI 私有 ACL 未证明时明确返回 unknown/incomplete、退出码 2；SDK 文件系统测试不证明 Windows Docker 部署支持。只有历史恢复，无执行授权恢复；部分 restore 保持 pending，不提供通用续恢复。轮换只适用于健康、排空的宿主，不迁移证书、目标、活跃操作或未知结果。全权限文件系统回退不在停用保证内。

部署仍限既有无状态、非 root、只读、无挂载、无数据库迁移的单组件规格；未增加流量切换、多组件编排或生产业务验收。旧备份仍需独立保管的原验证 key；工具文件回退不能当作宿主状态回退或密钥轮换逆操作。
