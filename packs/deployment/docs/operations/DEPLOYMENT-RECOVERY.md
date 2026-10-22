# 持久化历史与中断恢复（可选 P1-5）

本扩展解决两件事：可信进程重启后仍能验证旧版本历史；部署停在中间态时，能在新的独立授权下执行有限恢复。它不恢复旧 permit，不自动续跑，也不接受项目导出的 JSON 作为授权。

## 历史记录

宿主显式注入 `StorePolicy(repository_id, store_id, key_id, runtime_policy)`、候选目录之外的私有目录和至少 32 字节随机 HMAC key，构造 `HostStore`。没有 CLI／环境 key loader。POSIX 目录／文件要求 0700／0600；Windows 须由宿主部署私有 ACL，chmod 不提供等价保证。密钥和完整规格不能写入项目、审计或制品。

`capture_history(collector, observation)` 复核实际新鲜完整现场后保存签名不可变记录，返回 reference。另一可信进程可用相同目标、签名身份与密钥创建 store，再调用 `load_history(ref, collector=..., before=fresh_current)`。加载校验完整签名、UTC 先后顺序、真实仓库 ID、daemon/project/环境/target/production/全组件集合，以及所有历史组件的镜像来源、产物和可信规格仍匹配当前目录。

新 catalog 可以增加版本，传输证书可轮换；历史仍保留原始 producer policy。改变旧配方、移除旧镜像／目录项、改组件集合或目标、错误密钥／签名均拒绝。返回的 `HistoricalSnapshot` 是绑定当前 collector 和 before 对象的历史能力，仅供新回滚请求使用；它不能替代实时 observation。普通导出、拷贝、重建对象和未经宿主验证的文件不获得签发权。加载之后的每次使用仍检查签名和配置兼容；实际中间态由执行器逐步复核，不要求历史记录冒充当前运行状态。

## 写入隔离与操作日志

启用恢复须同时配置 `ExecutionPolicy.history_policy_hash`、`gateway_policy_hash`、原始 HostCoordinator 和受控网关。`scripts/deployment_gateway_host.py` 是分发侧固定 mTLS／本机 Unix Docker 网关参考宿主，不安装到候选项目。reader 和 writer 为不同证书，writer 只能提交宿主签发的准确单次 method/path/body 摘要；无 admission 的请求被服务端拒绝。原始 Docker socket 必须只供该受控宿主使用，旁路 daemon 权限会破坏这一保证。

```python
coordinator = HostCoordinator(store, gate, collector, execution_policy)
executor = DockerExecutor(execution_policy, client, collector,
                          verifier=verifier, coordinator=coordinator)
intent = executor.prepare(root, plan, operation, observation=current,
                          rollback_target=history_or_none)
with coordinator.operation(root, plan, intent) as host_operation:
    # request 仍由 build_request 按同一 intent 构造。
    permit = authorize(root, plan, request, collector=collector,
                       observation=current, approval=approval,
                       rollback_target=history_or_none,
                       execution_intent=intent, host_operation=host_operation)
    result = executor.execute(root, permit, intent, host_operation=host_operation)
```

目标宿主文件锁跨授权与执行持有，锁顺序为 HostStore 目标锁，再到 Core 生命周期锁。日志记录固定目标、真实 Core owner、授权／消耗摘要、原始映射、受控资源名和 ID、完整配置／管理文件摘要、每次准确写入尝试与核验响应；不保存原始 Env/Config。未解决日志阻塞普通新操作。

每次写入有独立 generation；签名尝试在最后 SDK guard 前持久化。网关先持久化 admission，再转发，只有读完完整上游 HTTP 响应才记录 definitive completion，随后响应客户端。关闭 generation 禁止旧请求继续进入；只有全部已 admission 的写入确实完成，才签发排空证明。客户端响应丢失但网关已完成时可以证明排空；上游响应未知、截断或仍在执行则阻塞，即使进程已死、现场看起来稳定或等待很久也不推断完成。

文件记录使用域分离 HMAC、独占创建、fsync、签名链和内核锁；拒绝链接、reparse、硬链接和身份替换。首版仅支持一个宿主共享的本地文件系统，不提供多宿主 HA。Windows ACL、备份、目录保护及宿主管理员不回滚整个可信存储属于部署前提；HMAC 不防持有密钥的管理员伪造或还原完整旧存储。

## 独立恢复授权

`inspect(root, operation_id)` 关闭旧 generation 并只读核对签名日志、实际完整项目 inventory、已知完整 ID／名称的直接查询、未选中实例与管理文件、来源／规格、原始 Core owner 和实际进程存活。只有经认证的 Docker HTTP 404 能证明准确资源不存在；过滤列表里没看到、网络失败或任意空 JSON 都不算。

`prepare_recovery(..., expires_at=...)` 签发新的 RecoveryRequest，绑定原日志、现场、排空证明、准确动作、项目 HEAD／配置和全部宿主策略。`recover(request, approval)` 在持有目标锁时消费新的恢复域授权，再执行。普通 release、deploy、rollback 请求／grant 均不能替代它。GitHub 使用独立 audience `dev-workflow-deployment-recovery-host`、账本 `workflow-recovery-grants` 和受保护精确审批。即使只核对完整前／后状态、没有 Docker 写入，关闭中断日志或接管旧锁仍需新恢复授权。

若遗留 Core owner，必须与签名日志的完整 pid/token/operation/transaction 相等且确实已死；Core 在恢复 guard 内、删除前再次比较 `expected_owner`。活进程、未知存活结果、被替换 owner 和未知 recovery.lock 均保留并阻塞。授权消费后失败不退款；每次写入仍重新检查范围、原始日志、当前阶段、项目、权限、期限与未选中实例。

| 实际状态 | 首版处理 |
|---|---|
| 原实例仍运行，候选已创建且停止 | 删除准确候选，核对原映射和验收 |
| 原实例停止，候选停止或不存在 | 先清理候选（如有），再启动原实例 |
| 原实例已删除，准确候选停止 | 清理候选，再按保留的旧配方创建和启动恢复实例 |
| 已知恢复实例已创建／运行 | 按日志和现场检查后继续受支持步骤，不盲目重复 create |
| 完整新版本已运行 | 只核验并解决日志，不隐式回滚；要回旧版本另申请普通回滚 |
| 外来／变更资源、未知上游响应、无可验证日志或旧配方 | 阻塞，无写入 |

恢复资源名固定为 `dev-workflow-recover-<原 intentId>`，标签及准确配方受宿主约束；每次恢复审批另有新 request ID。恢复不删除运行中的外来资源、不删除镜像、卷或日志之外的数据。返回实际 observation 前重新采集完整映射；配置 P1-4 时还按恢复镜像的 profile 检查健康和业务响应。

## 当前限制和升级注意事项

- 中断操作需保留原 coordinator 策略身份；普通历史能兼容 catalog 增加，不意味着中断日志可跨任意策略升级恢复。
- 若恢复在“候选已清理、旧实例尚未重建”的空选中状态再次崩溃，当前闭合状态表会阻塞，不能保证所有中断点都可自动恢复。
- admission 已持久化但上游完成未知时永久拒绝自动排空；需宿主运维核对，不能用超时强解锁或复用审批。
- 本机 Unix Docker 网关参考宿主用于 Linux；Windows 测试覆盖 SDK、持久化／文件锁和 PowerShell，不代表 Windows 容器执行或 Windows daemon 网关已交付。
- 未设置可选哈希时保留 P1-3 行为和原哈希，不自动启用存储、探针或恢复。不迁移进程内旧 capability，不为已有 P1-3 中断现场补造签名日志。首次启用须创建受控私有存储和全新精确授权。
- 旧的无签名 inode／mutex 绑定存储不自动升级；新建受控存储，不覆盖未知记录。密钥轮换／备份迁移尚无自动适配器。
- 此恢复只针对现有无状态、只读、无挂载、无需迁移的单组件规格；不提供数据库／备份恢复、生产验收、切流或多宿主编排。`productionReady` 保持 false。
