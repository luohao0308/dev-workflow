# Mac进程重启恢复

## 当前事实与目标

`d9e9969`真实首create闭合→独立审批四步续作→终态证书已验收，但原Mac进程一直保留。新进程验签只验证历史证明，不提供执行恢复。

原controller的gate/store及准备材料密钥只在内存；原admission保留真实approval/consumption对象、PID/issuer与epoch。远端daemon还绑定原writer父进程，失联会停止。因此不能反序列化旧admission，也不能让新SSH连接继承旧现场权限。

## 首切片：重新认证私有闭合前缀

交付可由后续恢复准备器消费的只读history与独立基线，不注册admission或连接Engine。先限单服务deploy的首create闭合切点，拒绝pending、unknown-response、多步或恢复后history。

- 保留原bundle/request/policy、消费摘要、first binding、原认证snapshot、独立baseline字节及执行源码归档身份；不保存grant、OIDC、旧approval/consumption对象或签名私钥。
- 完整保留经原生产端认证的image defaults，使用原bundle构造器重建并逐字节核对包括派生字段的完整bundle；defaults摘要不能替代原值。
- 验证密钥、见证transport及材料摘要/context pin由可信embedding独立提供；材料中的公钥或摘要不能自行建立信任。
- 新进程重建原只读AuthenticatedHistoryV3并通过原OperationWitnessClientV3重验真实SSHSIG和gate HMAC；从见证重新capture，不能仅相信保存的snapshot。
- 再次捕获须与独立固定的历史摘要及完整snapshot相等，基线须与bundle摘要相符。认证失败不修复、覆盖或推进见证。
- 输出不得宣称当前Engine/phase新鲜、旧writer已停止、反回滚根已登记或任何执行权限。可信独占本地见证存储仍是前提。

优先复用原类型、规范化、签名校验和只读操作；不新增依赖，不改既有PID/issuer检查、wire协议或普通CLI支持矩阵。

首版API为`capture_material(original_history, *, baseline_bytes, authenticated_image_defaults, archive_digest)`及`reopen_material(raw, *, expected_digest, expected_context, gate_key, witness_public_key, witness_transport)`。首版只提供bytes接口，不实现文件写入或自动密钥保管；可信embedding负责私有文件权限、独立pin和外部密钥/transport来源。`expected_context`严格包含sourceSha、hostId、daemonId、archiveDigest、historyDigest、baselineStateDigest。

返回冻结的只读history/snapshot/baseline上下文，私有字段不进入repr；材料不含gate/store密钥。显式核对原request的policy_hash等于GatePolicy.identity_hash。历史过期请求可以审计，但不续期或创建旧权限。新nonce读取不证明存储不可整体回滚，输出所有权限、phase freshness、Linux quiescence及production标志均为false。

## 方案取舍

选择重新读取认证见证：能给后续RecoveryPreparationHostV3/恢复capsule校验提供原history类型与独立基线，直接补原controller进程内数据缺口。

仅新增部分历史签名证书虽容易跨进程验签，但会重复现有历史证明，并不能重验原见证或恢复准备器输入，暂不采用。

## 验证

1. 生产者子进程生成真实Gate/HMAC/SSHSIG闭合历史和私有材料后退出；另一全新进程在外部可信密钥/transport下重读见证并认证相同前缀。Engine/provider只用明确替身。
2. 篡改、重复键、非规范输入、超限、错误源码/host/archive/history/baseline/key或材料pin拒绝；pending/unknown和见证推进/旧前缀不匹配拒绝。
3. 只允许read/check/events_after/chain_status；register/append/transition、Engine及审批调用不得发生。验证前后见证字节不变。
4. 私有材料不可通过repr/公开摘要泄漏body；文件接口若纳入本切片，必须拒绝符号链接、非0600文件、替换和不安全目录。
5. 保留原history/capsule/admission/session相关回归。证据必须区分新进程历史认证与新进程执行恢复。

## 后续执行恢复的未闭合边界

可信密钥保管/登记、外部单调见证、旧writer独立终止证明、已停Engine的重新绑定与实时phase、全新session及新精确消费、尾部CAS须分别实现和验收。首切片不解除这些条件，不启动生产。
