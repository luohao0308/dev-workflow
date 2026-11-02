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

## 第二切片：原controller捕获与本地私有保管

将首切片接到原managed普通controller的仅本地可选`on_restart_checkpoint`回调：提供回调即启用捕获和私有保管；默认None保持原路径。原恢复phase验证通过后、第二次精确审批消费前保存材料，并通过回调交付一次独立descriptor/pins；回调只接收深复制的描述性摘要，不含body、key、grant。raw-Popen和固定诊断画像拒绝此扩展，不新增wire字段。defaults须从已经认证的原deploy capsule用原image HMAC派生逻辑重新得到，不能从声称的摘要猜测。

材料与读取所需的gate/store密钥分开保存在本次Mac私有case中；见证签名私钥继续使用原来的独立文件，不复制进材料或公开摘要。只接受POSIX当前用户0700目录和0600普通单链接文件，全路径拒绝符号链接；完整临时写入、fsync、独占发布，不覆盖旧结果或修复残片。两文件不是事务，任意写入或目录fsync失败都不得交付descriptor，冷读拒绝不完整pair。保存或回调失败必须在第二审批前拒绝，并沿原controller异常/清理路径退出。

冷读入口必须显式接收来自可信embedding的材料摘要、密钥保管文件摘要、六项context pin及见证公钥摘要；邻接manifest不自证。这是可信独占主机上的私有文件保管，不声称Keychain/KMS、抵抗主机管理员或全局单调存储登记。新增custody只保存历史重验所需gate/store密钥，不复制旧grant、OIDC、approval/consumption对象或intent签名私钥；原controller已有签名文件的生命周期不在本切片内改写。

冷读重开原OperationWitnessStoreV3，仅允许原只读dispatch及新nonce签名响应，交给原reopen_material继续完整认证。reader的PID/thread/对象身份和关闭状态须防复制、fork或外线程关闭原句柄；所有文件身份及权限前后重验。原writer已退出不构成独立终止证明，冷读成功也不能恢复执行。

验收采用原managed controller及真实本地管道/HMAC/SSHSIG，在首create闭合并落盘后从原生回调保留独立pins，再故意拒绝第二审批，旧producer正常完成异常清理并退出，再由新进程读取；不得patch保存函数获取pins或从邻接manifest补造信任。并覆盖文件权限/链接/替换、错误外部pin、部分发布/重复发布、读后关闭或复制/fork，以及见证已推进时旧checkpoint拒绝；不产生第二次消费或Engine派发。读取保留原store阻塞flock边界，不声明全局硬期限。

## 第三切片：Linux原writer身份与冷进程停止核验

当前manager交付给Mac的六字段binding不含PID/startTicks及cgroup inode，不能从daemon身份或JSON猜出旧writer身份。先补Linux本地完整origin及独立冷读核验；Mac端的外层origin frame、nonce/旧六字段绑定和checkpoint接线后续单列。

原OwnedRecoveryUnitV3在确定启动后，重新验证同boot、原InvocationID/PID/startTicks、原cgroup与parent inode，才能导出canonical只读origin。origin同时固定producer的`/proc/self/ns/pid` device/inode，并验证`/proc/self/stat`中的PID等于`os.getpid()`；consumer必须匹配同一PID namespace与一致的/proc视图，避免把不同命名空间中看不到PID误判为原进程死亡。源码/归档身份取原固定loader构造参数。未启动、启动不确定、PID/Invocation/cgroup/namespace替换均拒绝。

相同数字PID不能证明相同namespace；[Linux pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)说明procfs按挂载者namespace呈现进程。实现据此再比较`/proc/1/ns/pid`与`/proc/self/ns/pid`，并在捕获前后核对原MainPID的namespace与producer一致；即使数字PID偶合也不能混合不同视图的身份。

冷核验器显式接收原origin字节及外部固定digest/source/archive，不复活旧owner对象。只接受固定`dw-writer-host-<16hex>.service`命名范围，cgroup路径由名称派生；只读systemctl show、/proc和cgroup。当前boot须匹配，原PID须已消失（包括zombie或PID复用均拒绝），unit须为严格not-found或原Invocation明确停止态，原cgroup须已消失或同inode递归空。两次完整观测须稳定一致，任何权限、解析、状态推进或身份变化均拒绝；所有读共享原有界deadline。

停止观测只说明原wrapper/cgroup在本次观测中已停止，不说明daemon、业务、现场新鲜或后续永不重启；所有执行/恢复权限保持false。描述性结果不能作为新admission或stop能力。

测试覆盖原owner活着时捕获、旧producer停止退出后全新consumer只读核验、残留后代、PID/unit/cgroup复用、错pin与错误boot、PID namespace及/proc视图不匹配、观测期间变化、权限失败与deadline。真实专用Linux/root测试仅启动等待归档的原固定loader，不发送归档/config、不启动worker或Engine；原owner负责停止，新consumer不得执行任何启停命令。
