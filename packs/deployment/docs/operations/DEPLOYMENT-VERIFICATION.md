# 健康与业务验收（可选 P1-4）

容器处于 running 不代表应用可用。`deployment_verify.py` 在完整运行映射通过核验后，先检查健康响应，再检查业务响应。检查未通过时报告 `executed-unhealthy`，保留实际运行 observation，停止后续验收；不会隐式回滚。权限、仓库或运行状态漂移则报告未核验，而不是冒充应用不健康。

## 宿主配置

宿主显式创建 `ProbePolicy(runtime_policy_hash, profiles_json, total_timeout=60)` 和 `TrustedProbeVerifier(policy, runtime_policy, ca_file=...)`，将策略哈希加入 `ExecutionPolicy.verification_policy_hash`，向执行器注入原始 verifier。prepare 将探针绑定摘要写入执行 intent；已有 `execution_policy_hash` 审批覆盖这项能力。策略、缓存、实例或绑定不匹配都拒绝，不能在批准后更换同策略检查器。

每个 profile 绑定 component、不可变 imageId、可信 specHash、containerPort、hostIp/hostPort 和固定 address。声明端口和实际发布端口均须匹配选中容器。宿主负责确保该地址确实通向选定 daemon 的发布端口；不从项目 URL、标签或目标声明推导服务身份。

profile 必须至少有一个 health 和一个 smoke。探针包含 id、固定 path、预期 2xx status、`jsonExpectations`（JSON Pointer 到标量）、attempts、retryDelay、timeout 和 maxBodyBytes。例如 `/ready` 校验 `/ready: true` 与版本，`/business` 校验版本及业务值。布尔、数字、null 和缺失字段严格区分；旧版本响应不能通过新镜像的版本验收。

只发送 GET，HTTP 仅限固定 IPv4 loopback；HTTPS 使用显式 CA、主机名和服务端 DER pin，连接固定字面 IP，不查询 DNS。拒绝重定向、分块／压缩响应、重复或矛盾长度、超量响应、重复 JSON 字段、非有限数字及不支持的编码。首版服务应返回有明确长度或连接关闭的普通 JSON。每次响应最多 64 KiB，不发送项目凭据、不读取代理或环境凭据。

每个探针最多 5 次只读尝试，单次网络期限不超过 10 秒，总验收期限不超过 120 秒，同时受整体执行期限约束。探针前后都复核授权和完整预期运行状态。复核耗时计入总期限，不计入已完成的网络请求期限；流式慢响应仍受 watchdog 限制。

## 结果与限制

`verification.health/smoke` 为实际 `passed/failed/not-run`；未配置时保留 unknown。`probeChecks` 只保存检查 ID、阶段、次数、耗时、响应摘要、状态码和固定错误码，不保存原始响应、URL、预期业务值或异常文本。摘要不加密，仍应限制审计访问。

健康失败不运行 smoke；业务失败不产生额外 Docker 写入。实际当前状态完整时，可重新规划并申请独立回滚。恢复也按恢复后选中镜像的原始 profile 验收，不能用目标 v2 的响应要求判断恢复后的 v1。

这项能力不提供数据库事务、写业务探针、自动切流、零停机、蓝绿／灰度或生产 SLA。探针通过仅证明本次指定检查通过，`productionReady` 仍为 false。独立真实验证与平台 CI 证据见分发仓库的验证记录；能力存在不等于已替任何业务项目部署。
