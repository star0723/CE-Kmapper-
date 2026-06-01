# CE-Kmapper + Kmapper: 完整实施计划

## 最终目标

实现 Cheat Engine 核心功能，**全链路通过 CR3 页表遍历 + 物理内存映射**完成，绕过 ACE/EAC/BE 的用户态和内核态监控。

## 反作弊绕过原理

### 被监控的 API（触发检测）

| API | 被谁 Hook |
|-----|-----------|
| `NtReadVirtualMemory` / `NtWriteVirtualMemory` | EAC, BE, ACE |
| `NtQueryVirtualMemory` | EAC, BE |
| `NtOpenProcess` / `OpenProcess` | EAC, BE, ACE |
| `CreateToolhelp32Snapshot` / `Module32First` | EAC, BE |
| `NtQuerySystemInformation` | EAC, BE |
| `NtSetInformationThread` (HWBP via debug regs) | BE |
| `CreateRemoteThread` / `NtCreateThreadEx` | EAC, BE, ACE |

### 我们的替代路径（不触发检测）

| CE 功能 | 传统路径（被检测） | AsioR0 路径（绕过） |
|---------|-------------------|-------------------|
| 打开进程 | `OpenProcess` | `ASIO_OP_ATTACH`: 内核遍历 `EPROCESS` 链表找 CR3 |
| 读内存 | `NtReadVirtualMemory` | `ASIO_OP_READ`: CR3→PTE→物理地址→`memcpy` |
| 写内存 | `NtWriteVirtualMemory` | `ASIO_OP_WRITE`: 同上反向写 |
| 查询内存区域 | `NtQueryVirtualMemory` | `ASIO_OP_ENUM_REGIONS`: PTE 遍历推断区域信息 |
| 枚举进程 | `CreateToolhelp32Snapshot` | `ASIO_OP_ENUM_PROCS`: `PsGetNextProcess` 内核链表 |
| 枚举模块 | `Module32First/Next` | `ASIO_OP_ENUM_MODULES`: PEB→LDR 链表直读 |
| 内存扫描 | 用户态循环读+比较 | `ASIO_OP_SCAN_VALUE/AOB`: **服务端完成**，CE 只收结果 |
| 内存分配 | `VirtualAllocEx` | `ASIO_OP_ALLOC`: 内核态分配 |
| DLL 注入 | `CreateRemoteThread` | `ASIO_OP_INJECT_DLL`: R0 APC + 线程劫持 |
| 硬件断点 | `SetThreadContext` | `ASIO_OP_HWBP_SET/CLEAR`: 内核直接操作 DR0-DR3 |

### 通信链路

```
CE 进程  ──命名管道──>  asio_kdmapper.exe (--server)
                            │
                            │ DeviceIoControl (AsIO64.sys)
                            ▼
                       物理内存映射 (CR3 页表遍历)
                            │
                            ▼
                       目标进程内存 (不经过任何被监控的 API)
```

---

## 当前状态

### Kmapper (服务端) — ✅ 基本完整

已实现的 Handler：
- [x] `HandleAttach` — EPROCESS 解析 + CR3 获取
- [x] `HandleRead` — CR3 直读 + MDL 回退
- [x] `HandleWrite` — CR3 直写 + MDL 回退
- [x] `HandleEnumModules` — PEB 链表遍历
- [x] `HandleEnumRegions` — PTE 遍历全地址空间
- [x] `HandleQueryRegion` — 单地址区域查询
- [x] `HandleEnumProcesses` — PsGetNextProcess 内核遍历
- [x] `HandleScanAob` — 服务端 AOB 模式扫描
- [x] `HandleScanValue` — 服务端类型化值扫描
- [x] `HandleScanNext` — 服务端二次扫描（服务端缓存）
- [x] `HandleHwbpSet/Clear` — 硬件断点
- [x] `HandleAlloc/Free` — 内核态内存分配/释放
- [x] `HandleInjectDll` — R0 APC + 线程劫持注入
- [x] `asio_r0_proto.h` — 协议头文件（之前缺失，已创建）

### CE-Kmapper (客户端) — 🔧 部分完成

**已实现 (AsioBridge.pas):**
- [x] 管道连接/断开 (`AsioConnect`, `AsioDisconnect`)
- [x] 进程附加 (`AsioAttach`)
- [x] 内存读/写 (`AsioRead`, `AsioWrite`)
- [x] 内存分配/释放 (`AsioAlloc`, `AsioFree`)
- [x] 模块枚举 (`AsioEnumModules`)
- [x] 进程枚举 (`AsioEnumProcesses`)
- [x] 值扫描 (`AsioScanValue`, `AsioScanNext`)
- [x] AOB 扫描 (`AsioScanAob`)
- [x] 区域缓存 (`AsioPreloadRegionCache`, `AsioVqeLookup`)
- [x] 线程安全 (CriticalSection)
- [x] 管道状态保护 (PipeDrain)

**已实现 (DBK32functions.pas hook):**
- [x] `OP()` → `AsioAttach`
- [x] `ReadProcessMemory64_Internal` → `AsioRead`
- [x] `ReadProcessMemory64` → 转发
- [x] `WPM` / `WriteProcessMemory64` → `AsioWrite`
- [x] `VQE` → `AsioVqeLookup` (缓存)
- [x] `VAE` → `AsioAlloc`

**已实现 (memscan.pas):**
- [x] `AsioFirstScan` — 值扫描 + AOB 扫描委托
- [x] `AsioNextScan` — 二次扫描委托
- [x] `lastScanUsedAsio` 标志

**已实现 (ProcessWindowUnit.pas):**
- [x] R0 进程枚举 (tab 1)

---

## Phase 1: 补全核心链路（使 CE 基本可用）

### 1.1 自动连接管道 ⚡ 关键
**文件**: `DBK32functions.pas`, `AsioBridge.pas`

当前问题：`AsioConnect` 从未被调用。CE 启动后无法连接到 Kmapper 服务端。

实现：
- `DBK32Initialize` 开头自动调用 `AsioConnect`
- `AsioConnect` 优先从 `%TEMP%\asio_pipe_name.txt` 读取实际管道名（含 PID 后缀）
- 连接成功 → 跳过驱动加载；失败 → 回退到原始 DBK 驱动路径
- `LoadDBK32` 中设置 `DBKLoaded := AsioReady or (hdevice <> INVALID_HANDLE_VALUE)`

### 1.2 模块枚举集成
**文件**: `CEFuncProc.pas`

当前问题：`GetModuleList` 使用 `CreateToolhelp32Snapshot`（被 EAC/BE Hook）。

实现：
- `GetModuleList` 检测 `AsioReady` 时改用 `AsioEnumModules`
- 解析返回的 `AsioR0ModuleEntry[]` 填充 `ModuleList: TStrings`

### 1.3 编译验证
- 安装 Lazarus IDE
- 编译完整 CE 项目
- 修复编译错误

---

## Phase 2: 增强稳定性和兼容性

### 2.1 区域枚举性能优化
**文件**: `Kmapper/main.cpp` `HandleEnumRegions`

当前问题：逐页（4KB）遍历 128TB 用户空间，极慢。

实现：
- PML4 级跳过：如果 PML4 条目不存在，跳过 512GB
- PDPT 级跳过：如果 PDPT 条目不存在，跳过 1GB
- PD 级跳过：如果 PD 条目不存在，跳过 2MB
- 只有最后一级（PT）才逐页扫描

### 2.2 VQE 缓存刷新
**文件**: `AsioBridge.pas`

当前问题：`regionCacheValid` 在 `AsioPreloadRegionCache` 后始终为 true，如果目标进程分配/释放了新内存，缓存过期。

实现：
- 添加 `AsioInvalidateRegionCache` 过程
- 在每次 `ASIO_OP_ALLOC` / `ASIO_OP_FREE` 后调用
- 在扫描前刷新缓存（如果超过一定时间）

### 2.3 MDL 读写错误恢复
**文件**: `Kmapper/main.cpp`

当前问题：MDL 路径中 `MmProbeAndLockPages` 失败会 bugcheck（蓝屏）。

实现：
- 添加 SEH (Structured Exception Handling) 通过 `.pdata` 注册的方式
- 或者：在 shellcode 中用 `MmIsAddressValid` 预检查

---

## Phase 3: 高级反检测

### 3.1 管道隐藏
当前问题：`\\.\pipe\asio_r0_probe` 管道名可被扫描检测。

实现：
- 管道名使用随机 GUID：`\\.\pipe\{random-uuid}`
- 通过共享内存或注册表传递管道名给 CE

### 3.2 进程保护
- Kmapper 服务端使用 `PsSetCreateProcessNotifyRoutine` 监控自身
- 移除 Kmapper 的 PEB 中的模块条目
- 使用 `RtlSetProcessIsCritical` 保护进程

### 3.3 内存访问模式混淆
- 读写时添加随机延迟
- 读取周围区域（noise read）混淆访问模式
- 服务端定期变更 NtAddAtom hook 目标函数

---

## Phase 4: 完善 CE 功能

### 4.1 指针扫描
CE 的指针扫描 (`Pointer scan`) 依赖大量内存读取，当前已通过 `ReadProcessMemory64` → `AsioRead` 路径支持。

### 4.2 结构分析
CE 的 Structure Dissector 同样依赖内存读取，已覆盖。

### 4.3 Debugger
当前 HWBP 已支持。软件断点（int3）需要额外工作：
- `ASIO_OP_SWBP_SET/CLEAR` — 写入 `0xCC` 到目标地址
- 需要与 Windows 调试子系统交互来接收断点事件

### 4.4 Lua 引擎
CE 的 Lua 脚本引擎中的内存操作（`readBytes`, `writeBytes` 等）已通过 DBK32functions 路径自动走 AsioR0。

---

## 实施优先级

```
Phase 1（立即执行 — 使 CE 可用）
  ├── 1.1 自动连接管道         ← 最高优先
  ├── 1.2 模块枚举集成         ← 高优先
  └── 1.3 编译验证             ← 必须通过

Phase 2（稳定性）
  ├── 2.1 区域枚举优化
  ├── 2.2 缓存刷新
  └── 2.3 MDL 安全

Phase 3（反检测加固）
  ├── 3.1 管道隐藏
  ├── 3.2 进程保护
  └── 3.3 模式混淆

Phase 4（功能完善）
  ├── 4.1-4.3 高级 CE 功能
  └── 4.4 Lua 引擎验证
```

---

## 文件变更清单（Phase 1）

| 文件 | 变更 |
|------|------|
| `AsioBridge.pas` | `AsioConnect` 管道名发现（hint file）|
| `DBK32functions.pas` | `DBK32Initialize` 自动连接 |
| `NewKernelHandler.pas` | `LoadDBK32` 兼容 AsioReady |
| `CEFuncProc.pas` | `GetModuleList` R0 路径 |
| `memscan.pas` | (已完成) |
| `ProcessWindowUnit.pas` | (已完成) |
