# AsioR0 <-> Cheat Engine integration notes

This note describes the shortest path to adapt official Cheat Engine to the
`asio_kdmapper` R0 pipe backend without rebuilding `DBKKernel` first.

## Recommended approach

Phase 1 should hook the existing `dbk32/DBK32functions.pas` kernel-mode
switches and redirect them to the R0 pipe protocol:

- `OpenProcess` -> attach current PID to the pipe session
- `ReadProcessMemory` -> read through `ASIO_OP_READ`
- `WriteProcessMemory` -> write through `ASIO_OP_WRITE`
- `VirtualQueryEx` -> query memory region information from the pipe backend

This keeps the rest of CE intact: scanner, address list, pointer logic,
memory viewer, and the existing DBK toggle flow.

## Existing opcodes to keep

Keep the current wire format and opcodes unchanged:

- `0x00` `ASIO_OP_PING`
- `0x01` `ASIO_OP_ATTACH`
- `0x02` `ASIO_OP_READ`
- `0x03` `ASIO_OP_WRITE`
- `0x04` `ASIO_OP_GET_BASE`
- `0x05` `ASIO_OP_ALLOC`
- `0x06` `ASIO_OP_FREE`
- `0x07` `ASIO_OP_INJECT_DLL`
- `0x08` `ASIO_OP_ENUM_MODULES`

The first phase does not need to change these. `ATTACH`, `READ`, `WRITE`, and
`ENUM_MODULES` are already enough to start the CE integration.

## New opcode(s) to add

### Required

Add one opcode for `VirtualQueryEx`-equivalent region lookup:

- `0x09` `ASIO_OP_QUERY_REGION`

Purpose:

- input: virtual address
- output: one `MEMORY_BASIC_INFORMATION`-like region description

This is the minimum missing piece for CE scanning, because CE repeatedly walks
the target address space by memory regions.

### Recommended optional extension

If you want fewer round-trips and better scan speed, add a bulk region snapshot:

- `0x0A` `ASIO_OP_ENUM_REGIONS`

Purpose:

- input: none
- output: full region list for the attached process

This lets CE cache the full region table once per attach and answer
`VirtualQueryEx` from cache on the client side.

## New structs to add

### Minimal single-region query

```c
#pragma pack(push, 1)
struct AsioR0QueryRegionReq {
    uint64_t va;
};

struct AsioR0QueryRegionResp {
    uint64_t allocation_base;
    uint64_t base;
    uint64_t region_size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t allocation_protect;
    uint32_t reserved;
};
#pragma pack(pop)
```

Suggested mapping rules:

- `state == 0` or `protect == PAGE_NOACCESS` can be treated as free/unusable
- `base` should be page-aligned
- `region_size` should be page-aligned
- `allocation_base` should reflect the allocation start if known

### Optional bulk region snapshot

```c
#pragma pack(push, 1)
struct AsioR0RegionListResp {
    uint32_t count;
    uint32_t reserved;
};

struct AsioR0RegionEntry {
    uint64_t allocation_base;
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t allocation_protect;
    uint32_t reserved;
};
#pragma pack(pop)
```

This bulk form is optional, but it is the better long-term choice if the CE
side wants to cache all regions for the current attach session.

## DBK32functions.pas hook points

These are the concrete CE-side functions that should be redirected to the
AsioR0 backend first.

### Mandatory for phase 1

1. `function {OpenProcess}OP(...)`

   - Replace the `IOCTL_CE_OPENPROCESS` path with:
     - send `ASIO_OP_ATTACH` using the target PID
     - create or update the local handle map entry
   - Keep the fallback Windows path only for non-Asio modes.

2. `function ReadProcessMemory64_Internal(...)`

   - Replace `IOCTL_CE_READMEMORY` with `ASIO_OP_READ`
   - Keep chunking/page splitting if you want safer failure isolation
   - This is the main read path used by CE scanners

3. `function ReadProcessMemory64(...)`

   - Keep the wrapper logic and local `handlemap`
   - When the handle is attached to the R0 backend, forward to
     `ReadProcessMemory64_Internal(...)`

4. `function {WriteProcessMemory}WPM(...)`

   - Keep it as a wrapper
   - Redirect to the backend write path

5. `function WriteProcessMemory64(...)`

   - Replace `IOCTL_CE_WRITEMEMORY` with `ASIO_OP_WRITE`
   - Keep chunking if you want to mirror the existing DBK behavior

6. `function {VirtualQueryEx}VQE(...)`

   - Replace `IOCTL_CE_QUERY_VIRTUAL_MEMORY`
   - Use `ASIO_OP_QUERY_REGION`
   - If you add `ASIO_OP_ENUM_REGIONS`, this function can read from cache

### Recommended but optional for phase 1

7. `function {VirtualAllocEx}VAE(...)`

   - Map to `ASIO_OP_ALLOC`
   - Useful for future injection / code cave workflows

8. `function IsValidHandle(...)`

   - Usually no protocol change needed
   - Keep the local `handlemap` semantics

### Leave untouched in phase 1

- `GetPhysicalAddress(...)`
- `GetMemoryRanges(...)`
- `VirtualQueryExPhysical(...)`
- DBVM-specific paths
- debugger / breakpoint / thread-control IOCTLs

Those are separate feature branches. They are not required to get the scan and
address-list workflow working with AsioR0.

## Suggested implementation order

1. Add `ASIO_OP_QUERY_REGION`
2. Implement `AsioR0QueryRegionReq` / `AsioR0QueryRegionResp`
3. Patch `OpenProcess`, `ReadProcessMemory64`, `WriteProcessMemory64`,
   `VirtualQueryEx`
4. Verify:
   - attach
   - first scan
   - next scan
   - address list read/write
5. Only after that, decide whether `ENUM_REGIONS` caching is needed

## Short version

If the goal is "make official CE read/write through `asio_kdmapper`", the
minimal missing protocol piece is **region query**. Everything else can stay
close to the existing DBK flow.
