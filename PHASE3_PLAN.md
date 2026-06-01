# Phase 3 — 高级对抗 + 保护方案

## 当前薄弱点分析

| # | 薄弱环节 | 攻击面 | 风险等级 |
|---|---------|--------|---------|
| 1 | 管道名固定 `\\.\pipe\asio_r0_probe_PID` | ACE/EAC 枚举 Named Pipes 可直接发现 | **Critical** |
| 2 | Hint 文件路径固定 `%TEMP%\asio_pipe_name.txt` | 文件系统监控可发现 | **High** |
| 3 | 协议魔数固定 `0x52303058` / `0x52524F58` | 流量分析/内存特征匹配 | **Medium** |
| 4 | CE 进程无保护 | 被 Ring3 AC 注入/扫描模块列表 | **Critical** |
| 5 | Server 进程可见 | 任务管理器/进程列表暴露 | **High** |
| 6 | LCL 窗口类名 `TMainForm` `TfrmAutoInject` | FindWindow/EnumWindows 检测 | **Medium** |
| 7 | 读写走 Named Pipe I/O | 标准 I/O 拦截点 | **Medium** |
| 8 | Driver .sys 文件名特征 `AsIO64_D38774B8F812` | 驱动签名/文件名黑名单 | **Low** |

---

## 3.1 管道名随机化 (Pipe Name Randomization)

**目标**: 每次启动生成不可预测的管道名，ACE/EAC 的 `NtQueryDirectoryObject(\Device\NamedPipe\)` 枚举无法匹配硬编码模式。

**实现方案**:

### Server 端 (Kmapper/main.cpp)
```
- 移除固定前缀 "asio_r0_probe"
- 管道名 = 随机 Base36 字符串 (8-12 字符)，例如: \\.\pipe\7f3kx9m2
- 使用 BCryptGenRandom 生成 CSPRNG 随机数
- PID 后缀也移除 (暴露进程关联)
```

### Client 端 (AsioBridge.pas)
```
- Hint 文件名也随机化: %TEMP%\{random}.tmp (而非固定的 asio_pipe_name.txt)
- 使用 HMAC(machineGUID + timestamp) 生成一致的临时文件名
  (Server 和 Client 都能计算出相同路径，无需硬编码)
- Hint 文件使用后立即删除 (读取成功 → DeleteFile)
```

### 对抗级别
- Level 1: 随机管道名 (基础)
- Level 2: 使用 Section Object (`\BaseNamedObjects\{GUID}`) 代替 Named Pipe (绕过管道枚举)
- Level 3: 使用 Raw Socket / localhost TCP 代替命名管道 (突破 Named Pipe 监控)

**推荐**: 先做 Level 1，后续可升级到 Level 2/3。

---

## 3.2 通信加密 (Encrypted IPC)

**目标**: 即使管道被拦截，流量内容不可辨认，无法通过模式匹配识别为 R0 通信。

**实现方案**:

### 加密协议
```
1. 握手阶段:
   - Client 发送 ECDH-X25519 公钥 (32 bytes)
   - Server 回复 ECDH-X25519 公钥 (32 bytes)
   - 双方计算共享密钥: SharedKey = X25519(privKey, peerPubKey)

2. 数据传输:
   - 每个数据包: [Nonce(12B)][EncryptedPayload][Tag(16B)]
   - 加密算法: ChaCha20-Poly1305 (AEAD)
   - Nonce: 递增计数器 (无需传输随机 nonce)

3. 前向保密:
   - 每次连接重新协商密钥
   - 旧密钥无法解密新会话
```

### 数据包混淆
```
- 移除固定 Magic Number (0x52303058)
- 替换为: 加密后的数据流无可辨识的固定模式
- 添加随机 padding (4-64 bytes) 打乱包长度特征
- 模拟 HTTP/WebSocket 流量模式 (可选)
```

---

## 3.3 进程保护 (Process Self-Defense)

**目标**: 防止 AC 注入 DLL、扫描模块列表、读取进程内存。

### 3.3.1 Anti-Inject (CE端)
```
- Hook NtMapViewOfSection / LdrLoadDll 拦截未授权 DLL 加载
- 周期性扫描模块列表检测新加载的未知 DLL
- 使用 SetProcessMitigationPolicy:
  - ProcessSignaturePolicy: 仅允许 Microsoft 签名 DLL
  - ProcessDynamicCodePolicy: 禁止远程线程创建
  - ProcessExtensionPointDisablePolicy: 禁用 Shell 扩展
```

### 3.3.2 Anti-Read (Server端)
```
- Server 进程设置 DACL: 仅允许 SYSTEM + 当前用户访问
- 使用 ObRegisterCallbacks (需驱动支持) 拦截 OpenProcess
  → 对非授权进程返回 STATUS_ACCESS_DENIED
- PPL (Protected Process Light) 标记 (如果签名允许)
```

### 3.3.3 Anti-Debug (CE+Server)
```
- IsDebuggerPresent / NtQueryInformationProcess(ProcessDebugPort)
- 检测硬件断点 (GetThreadContext → DR0-DR3)
- 定时检查 PEB.BeingDebugged 和 NtGlobalFlag
- 检测 ScyllaHide / TitanHide 等反反调试工具
```

---

## 3.4 窗口隐藏 + 类名随机化

**目标**: 防止 `FindWindow`/`EnumWindows` 发现 CE 窗口。

### 实现方案
```
1. 窗口类名随机化:
   - 在 Application.Initialize 前修改 TApplication.ClassName
   - 或使用 SetClassLongPtr(GCL_ATOM) 替换注册的窗口类名
   - 每次启动生成随机类名 (如 "Wnd_8f3k2m")

2. 窗口标题动态变化:
   - 空标题 / 随机标题 / 模拟系统窗口标题
   - 定时 (每5秒) 改变标题防止静态匹配

3. 从 EnumWindows 隐藏:
   - Hook user32!EnumWindows 回调
   - 或使用 SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) 
   - Cloaked 窗口: DwmSetWindowAttribute(DWMWA_CLOAK)
```

---

## 3.5 Server 进程隐匿

**目标**: Kmapper server 进程从系统进程列表中隐形。

### 实现方案
```
1. DKOM (Direct Kernel Object Manipulation):
   - 已有驱动权限 → 从 EPROCESS 双向链表摘除 Server 进程
   - ActiveProcessLinks.Flink/Blink 修改
   - 效果: Task Manager / CreateToolhelp32Snapshot 不可见
   - 风险: PatchGuard 检测 (需配合 PG 绕过)

2. 替代方案 - 寄生注入:
   - Server 逻辑注入到可信系统进程 (如 svchost.exe / lsass.exe)
   - 不创建新进程，完全隐藏在已有进程中
   - 管道也在目标进程地址空间内创建

3. 进程名伪装:
   - PEB.ProcessParameters.ImagePathName 修改为合法路径
   - 如 "C:\Windows\System32\svchost.exe"
   - CommandLine 也同步修改
```

---

## 3.6 Driver 反检测

**目标**: 驱动加载后不留下可检测痕迹。

### 实现方案
```
1. 驱动卸载 (Load-and-Unload):
   - 驱动仅在初始化阶段加载 (建立物理内存映射)
   - 初始化完成后立即卸载 (sc stop + sc delete)
   - 内存映射 (MDL) 在卸载后仍有效
   - 效果: 驱动模块不在 DriverObject 链表中

2. 手动映射 (Manual Map):
   - 不通过 SCM 加载驱动，直接手动映射到内核空间
   - 无注册表痕迹 (HKLM\SYSTEM\CurrentControlSet\Services)
   - 无 DriverObject / DeviceObject
   - 效果: WinObj / DriverView 不可见

3. .sys 文件清理:
   - 驱动加载后删除磁盘上的 .sys 文件
   - 或使用 FILE_FLAG_DELETE_ON_CLOSE 打开
   - 效果: 文件系统扫描无法发现
```

---

## 3.7 内存特征消除

**目标**: 进程内存中不包含可被模式匹配的特征字符串。

### 实现方案
```
1. 字符串加密:
   - 所有敏感字符串编译时 XOR 加密
   - 运行时按需解密到栈上，用完立即覆盖清零
   - 对 Pascal 用 resourcestring → 自定义加载器

2. 代码段变异:
   - 运行时修改关键函数的字节码 (插入 NOP / 调换指令)
   - 每次启动函数入口不同，防止特征码匹配

3. 堆内存清理:
   - 通信缓冲区用完后 SecureZeroMemory
   - 页面属性周期性变更 (R/W → R/X → R/W)
   - 不使用全局静态缓冲区

4. PE Header 擦除:
   - 加载后清除 MZ/PE header (VirtualProtect → memset 0)
   - 防止内存 dump 恢复
```

---

## 3.8 心跳 + 自毁机制

**目标**: 检测到 AC 分析行为时自动清理痕迹。

### 实现方案
```
1. 环境检测:
   - 检测虚拟机环境 (CPUID leaf 检测 / 时序分析)
   - 检测沙箱 (低资源/短运行时间/已知文件名)
   - 检测调试器附加

2. 心跳机制:
   - CE ↔ Server 定期心跳 (每3秒)
   - 心跳丢失 → 自动断开 + 清理
   - 心跳包含环境状态 (是否被调试/注入)

3. 自毁流程:
   - 触发条件: AC注入检测 / 调试器 / 管道被劫持
   - 动作: 
     a. SecureZeroMemory 所有敏感内存
     b. 关闭管道连接
     c. 删除 hint 文件
     d. 卸载驱动
     e. 修改日志/注册表清除痕迹
     f. 进程退出
```

---

## 实施优先级

| 优先级 | 模块 | 预计工作量 | 对抗效果 |
|--------|------|-----------|---------|
| ★★★★★ | 3.1 管道名随机化 | 2h | 直接防止管道枚举发现 |
| ★★★★★ | 3.3 进程保护 (Mitigation Policy) | 2h | 防止 DLL 注入 |
| ★★★★☆ | 3.2 通信加密 (ChaCha20) | 4h | 流量不可识别 |
| ★★★★☆ | 3.4 窗口类名随机化 | 1h | 防止 FindWindow 检测 |
| ★★★☆☆ | 3.7 内存特征消除 | 3h | 防止内存签名扫描 |
| ★★★☆☆ | 3.5 Server 进程隐匿 (PEB伪装) | 2h | 进程列表不可疑 |
| ★★☆☆☆ | 3.6 Driver 反检测 | 3h | 驱动痕迹清除 |
| ★★☆☆☆ | 3.8 心跳 + 自毁 | 2h | 被检测时自动清理 |

---

## 推荐执行顺序

```
Phase 3A (立即 — 防止发现):
  → 3.1 管道名随机化
  → 3.4 窗口类名随机化
  → 3.3.1 进程保护 (SetProcessMitigationPolicy)

Phase 3B (核心 — 通信安全):
  → 3.2 通信加密 (X25519 + ChaCha20-Poly1305)
  → 3.7 内存特征消除 (字符串加密 + PE header擦除)

Phase 3C (高级 — 深度隐匿):
  → 3.5 Server PEB 伪装
  → 3.6 Driver 卸载清理
  → 3.8 心跳 + 自毁
```

---

## 技术依赖

| 模块 | 依赖 |
|------|------|
| 3.1 | BCryptGenRandom (Win API) |
| 3.2 | libsodium 或手写 X25519+ChaCha20 (~500行C) |
| 3.3 | SetProcessMitigationPolicy (Win8.1+) |
| 3.4 | SetClassLongPtr / RegisterClassEx |
| 3.5 | PEB 结构体偏移 (Win10/11 不同版本不同) |
| 3.6 | 当前 Kmapper 驱动加载逻辑 |
| 3.7 | 编译时宏 / 自定义 resourcestring 加载器 |
| 3.8 | CreateTimerQueueTimer / 独立看门狗线程 |
