# Native cold worker 的源码归档保管

## 交付范围

将固定、受限的诊断启动入口与现有 cold SDK / native writer 生命周期相连。归档内容须匹配独立固定的 Git commit，实际进程只能从该归档解包目录导入项目代码。固定入口执行既有 Engine/GitHub 替身用例，验证真实 Linux MainPID、消费后的登记、已闭合前缀检查点和停止后的新进程读取。

本片实现源码保管和 loader 的明确事实；通用生产 worker 协议、全局 writer replacement 排他和 scene-owner restart adoption 继续单独交付。`sourceRevalidated`、`linuxQuiescenceVerified`、`runtimePermit` 和 `productionReady` 保持 false。

## 契约

- 保留旧源码分发 profile 和 schema-1 native 检查点的默认行为。新诊断 profile 是固定集合，不能传入任意路径策略、模块或回调。
- 固定 bootstrap 通过受限长度帧接收 ZIP 和闭合配置，核对独立 SHA/digest、唯一普通文件成员与解包预算。启动入口固定，工作目录不参与项目模块导入。
- 原进程内部发行的 loaded-source 对象验证实际隔离 loader、原归档和已加载项目模块。对象限定 PID/线程，序列化、复制、fork 或任意摘要不能发行该事实。
- native 登记在真实消费后绑定 loaded-source、当前原生 origin 和内部执行 frame。检查点仅在闭合且未完成的执行结束后发布，保管原 ZIP 并读回核对。
- schema-2 的独立 descriptor 固定源归档和记录，冷读重验原 CAS、归档哈希和全部认证历史。校验事实不替代后续写入的排他、精确审批或 CAS。

## 验收

覆盖错 SHA/digest、成员缺失或篡改、错误入口、非原始发行对象、复制/跨线程/fork、导入路径或归档漂移，以及 CAS 篡改；验证旧 schema/profile 兼容。Python 3.10 和 3.14 定向验证后运行完整 CI。

真实 Linux 隔离验收必须从准确源码构建并验证归档，通过固定 systemd unit 的 stdio 启动；工作目录不能提供模块。由原管理器核对 MainPID/origin，存活 writer 拒绝，停止后新 consumer 成功重验保管归档和检查点。Engine/GitHub 使用明确替身，真实 Docker 写入为零。保留源码 SHA、归档摘要、测试结果和清理结果。

## 已完成验证（2026-11-10）

源码 `5b41bc6f4118907c57838022fdedf20fe9469c0f` 的固定诊断 profile 归档与 Git tree/blob 内容完整一致。真实 Linux 正常停止与 pidfd SIGKILL 两轮均通过：实际隔离 loader 发行凭据、原管理器 MainPID/origin 一致、存活 writer 拒绝、停止后新 consumer 重验 schema-2 历史与保管归档，逻辑索引九，父目录清理完成，真实 Docker 写入零。

相关 67 项回归在 Python 3.10 / 3.14 均通过，各跳过 Linux /proc 和既有 native-unit 环境检查两项；新增普通子进程退出保管回归在两版通过。Linux Python 3.12 的七项源码/保管回归全部通过，无跳过。正常退出时保管 CAS 的测试临时目录由父管理器统一清理，避免解释器退出 finalizer 先于冷读删除材料。AST、diff 检查及独立架构复审通过。

证据见 [固定归档与强杀验收](../validation/NATIVE-SOURCE-LOADER-2026-11-10.json)。本片是固定诊断入口接入 SDK 的源码保管；通用生产 worker 协议和全局排他/owner 接管继续待办。完整 CI 在最终文档提交上另行核对。
