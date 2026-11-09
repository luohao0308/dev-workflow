# 通用多服务部署与恢复

## 目标与当前边界

沿用 V3 的固定请求、独立人工审批、一次消费、签名见证、逐写入 Gate、受信现场和 CAS。2026-11-09 已通过的单服务 scene 仍使用原有契约。通用批次需要从现有 SDK 的多服务排序与闭合前缀恢复，逐步接入受管跨进程执行。

## 实施顺序

1. 多服务执行入口。受信 embedding 明确提供逐服务 readiness 回调。协调器按依赖顺序等待每个服务就绪，全部服务完成后使用完整回执表核验两次终态。验证双服务完整部署、新授权回滚、候选失败时零旧服务停止，以及九个闭合写入切点的恢复。
2. 受管批次准备与胶囊。提供按服务绑定的 sourceFacts、原始 inspect、镜像与配方，以及独立 schema/kind 的批次胶囊。重新采集全部已部署服务作为回滚基线，由原认证归档构造逆向目标。接入固定受信宿主，验证真实双服务部署和回滚。
3. 多服务检查点。新增版本化材料契约，保存任意已知闭合批次前缀、完整回执和独立基线。旧材料继续按原单服务首 create 语义读取。producer 退出后，consumer 重验源码、见证及旧 writer 停止，再经新请求与审批接续。
4. 多代恢复。定义有界祖先链，逐代绑定父请求摘要、父历史摘要和闭合尾部。统一历史认证、恢复准备、准入和初始 fence 的祖先语义。新一代从累计写入索引继续，既有 create 回执只登记一次。独立见证存储继续作为信任前提。
5. 故障与真实环境验收。覆盖每个写入的准备前、准入后、响应未观测、闭合后及检查点发布时的控制端退出。对未知写入保持冻结。各闭合切点重启后只执行后继。以双服务及保护数据服务验证完整部署、回滚和再次中断恢复。

## 首片接口

`execute_operation(..., readiness_probe=None)` 仅接受受信宿主传入的 callable，参数为 service 与候选容器 ID。未传回调时使用现有固定场景探测。回调返回值必须严格为 True。完整 receipts 仅在协调器成功返回后用于终态双采样。

## 当前进度（2026-11-09）

首片受信 embedding 接口与本地组合验证已完成。双服务完整部署和独立授权回滚各执行十笔写入，校验正向依赖启动、反向依赖停止与删除、独立创建回执、保护服务不变和闭合父历史。候选核验失败、readiness 返回 False 或非布尔真值、readiness 抛异常、终态第二次采样漂移均拒绝继续或拒绝成功结果。

九个已闭合写入切点的恢复均经现有恢复准备、签名见证、Gate 与 TLS/Unix 执行路径验证。它们覆盖累计索引及后继接续。后续进程 SIGKILL、跨进程批次材料和多代恢复按实施顺序继续推进。

相关恢复及既有 worker 测试在 Python 3.10 / 3.14 各 34 项通过，新增双服务与参数拒绝用例在两版各 7 项通过。最终依赖与回滚顺序断言另行定向验证。AST 和 diff 空白检查通过。

`deployment_compose_batch_restart_material_v3_host.capture_material/reopen_material` 使用独立 material kind，支持 root deploy 任意已闭合且未完成的多服务前缀。新 reader 从外部固定的 digest/context、公钥、Gate key 与只读 witness transport 重建认证历史。旧 reader 拒绝 batch kind。八项 batch 用例与十二项旧材料用例在 Python 3.10 / 3.14 均通过。

已验证九个双服务前缀冷读后进入原恢复准备器，以及第一笔 create 后和最后一个服务启动前的真实 producer 子进程退出、新 consumer 进程只读认证。该子进程用例复制测试见证并配置测试签名材料，证明材料跨进程重验。原认证 CAS 到恢复准备器的组合接线另行验证，原 CAS 的独立外部 key 仍须可用；缺失基线或 key 错误会拒绝准备新请求。

## 后续契约约束

- 不能仅移除 services 数量或 parent 深度检查。每层验证必须同时理解累计前缀、局部分段、祖先容量和当前活跃尾部。
- 跨代材料保存历史事实与验证材料。执行仍需要新鲜现场、writer 排他、精确审批、一次消费和新的尾部 CAS。
- 现有见证全链容量为 32 个 scope 和 256 个事件。部署、回滚与后续恢复必须计入累计容量，在写入前拒绝超限。
- 不确定写入、未闭合见证、复制或回退的状态、错祖先和现场漂移均须在后继写入前拒绝。
- 生产镜像来源、迁移、备份恢复及受信宿主登记单独验收。

## 多代 SDK 契约

历史对象与恢复准备器显式选择 `ancestry_profile='bounded-recovery-v1'`。该模式的历史使用 schema 3，全局 `scopes` 包含全部祖先记录，`segments` 描述每代的请求、bundle、消费摘要、父历史摘要、全局 scope 区间和本次逻辑操作的起始写入索引。

恢复沿用最近一代的 bundle、基线、累计写入前缀和回执。回滚使用新 bundle，逻辑写入索引从零开始，原部署的 scopes 仍计入全局链与容量。恢复中的再次恢复必须取得新请求、新消费回执及新 successor，绑定最近一代完整快照。深度上限为八，拒绝环、重复请求和重复 binding。

旧 schema 1/2 继续按原分段语义处理。多代恢复上下文使用独立 schema 2 和 ancestry profile 字段。字节准入、scope 和事件容量必须在 successor CAS 前纳入全部祖先；累计全局 scope 数与当前 bundle 的写入索引分别计算。

此阶段使用通用 SDK 与原有回调式 writer 停止证明。受管 scene 的旧胶囊、首 create 检查点与固定四笔尾部仍按原契约读取。冷读后的实际 worker 接续与 scene-owner 接管需要后续接线。

## 多代 SDK 验证进度

显式模式已实现于历史、恢复准备、witness 容量准入和 startup fence。单服务和双服务均验证了 deploy → recovery₁ 部分完成 → recovery₂ 完成，执行通过真实 Gate、签名、mTLS 和 Unix HTTP，Engine/GitHub 与 writer 停止证明使用测试替身。

回滚前缀可产生新的恢复请求，保持回滚 bundle 的逻辑索引。部署十个 scope 加一个回滚 create 的历史计入全局容量，恢复请求的起始索引为一；预计完整链共二十个 scope。容量限制降为十九时，真实 recovery fence 在 CAS 与授权核验前拒绝。已有回滚再次恢复请求的准备已验证，完整该路径的真实 Engine 执行仍待后续验收。

十五项多代用例覆盖祖先篡改、循环和重复、错 key/policy/epoch、旧契约拒绝、活跃尾部的逻辑索引、深度八的前置拒绝，以及读取回调在最终签名响应后修改祖先或切换模式时拒绝。完整祖先指纹由纯内存数据构成，在首次回调前和最后回调后核对。

最终十五项多代用例在 Python 3.10 / 3.14 各通过，相关历史、恢复准备、fence 与字节预算的四十项既有用例在两版通过。多代代码经独立复审，回调一致性缺陷修复后复审通过。Python AST 与 diff 空白检查通过。

第一版允许根 deploy 发起 rollback，然后对该 rollback 发起 recovery。已恢复部署再发起新 rollback 的准备接线、整个 coordinator 崩溃和 scene-owner 重启接管，继续作为后续工作。

## 多代材料冷读

`deployment_compose_bounded_restart_material_v3_host.capture_material/reopen_material` 使用独立的 `compose-bounded-restart-material-v3` 格式，保存 root 到 leaf 的每代请求、bundle、消费摘要、首 scope、已审父快照以及各 bundle 的基线和默认值。材料限制八个节点及 16 MiB，只接受当前逻辑操作已闭合且未完成的前缀。

捕获和重建均核对每代与认证 segments 的顺序、请求/回执摘要、父历史摘要和首 binding。全部祖先共享源、目标、宿主、daemon、环境、组件集合、policy 以及独立配置的验证密钥。回滚使用其独立 bundle 与基线。默认值通过请求的域隔离 plan hash 查找后重新构造校验。

调用方分别保存材料和独立 digest/context pins，并在新进程外部配置 Gate key、公钥和只读见证 transport。返回历史重新认证全部祖先并逐字节比较快照，可进入显式模式的现有恢复准备器。原认证 CAS 及其外部 key 仍须独立保留。

测试覆盖三代双服务冷读后准备新请求、回滚后的两套基线、伪造/重排/缺失祖先、已知 scope 的错误首 binding、错密钥和 pin、输入回调期间变更、只读 transport 及 producer 正常退出或真实 SIGKILL 后的新 consumer。子进程用例使用复制的测试见证与测试签名材料，验证的是检查点发布进程退出后的只读重建。真实 coordinator、writer 停止与 scene-owner 接管另行验证。

新模块十项测试在 Python 3.10 / 3.14 各通过，最终加强的完整前缀拒绝用例在两版另行通过。AST、diff 空白检查和独立架构复审通过。

## 验证

首片使用真实本机签名、HMAC、mTLS、Unix socket 和 Gate。新双服务组合用例中的 GitHub、Docker Engine、phase observations 和 readiness 使用测试替身。此结果单列为本地受信 embedding 组合验证。九切点恢复测试复用现有签名历史、CAS、PhaseGuard 与执行器，Engine 与 GitHub 使用替身。后续真实场景必须按源码 SHA、两套 CI、新审批和清理回执留证。

首片需断言依赖顺序、完整候选回执、保护服务无变更、失败后无后继写入、九个闭合切点恢复的绝对索引和原 create 不重派。多代片需验证 deploy → recovery₁ 部分完成 → recovery₂ 完成，以及 rollback 后再次恢复、旧代重放拒绝、祖先篡改拒绝、深度与字节预算拒绝。
