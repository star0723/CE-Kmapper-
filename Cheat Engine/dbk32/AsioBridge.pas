unit AsioBridge;

{$MODE Delphi}

interface

uses
  windows, sysutils, classes;

const
  ASIO_R0_REQ_MAGIC       = $52303058;
  ASIO_R0_RSP_MAGIC       = $52524F58;
  ASIO_R0_PROTO_VERSION   = 1;
  ASIO_R0_DEFAULT_PIPE    = '\\.\pipe\asio_r0_probe';

  ASIO_OP_PING         = $00;
  ASIO_OP_ATTACH       = $01;
  ASIO_OP_READ         = $02;
  ASIO_OP_WRITE        = $03;
  ASIO_OP_GET_BASE     = $04;
  ASIO_OP_ALLOC        = $05;
  ASIO_OP_FREE         = $06;
  ASIO_OP_INJECT_DLL   = $07;
  ASIO_OP_ENUM_MODULES = $08;
  ASIO_OP_SCAN_AOB     = $09;
  ASIO_OP_SCAN_VALUE   = $0A;
  ASIO_OP_SCAN_NEXT    = $0B;
  ASIO_OP_HWBP_SET     = $0C;
  ASIO_OP_HWBP_CLEAR   = $0D;
  ASIO_OP_QUERY_REGION = $0E;
  ASIO_OP_ENUM_REGIONS = $0F;
  ASIO_OP_ENUM_PROCS   = $10;
  ASIO_OP_ENUM_THREADS = $11;
  ASIO_OP_FREE_MEM     = $12;
  ASIO_OP_SHUTDOWN     = $FF;

  ASIO_OK              = 0;
  ASIO_ERR_BAD_MAGIC   = 1;
  ASIO_ERR_BAD_OPCODE  = 2;
  ASIO_ERR_BAD_PAYLOAD = 3;
  ASIO_ERR_NOT_ATTACHED= 4;
  ASIO_ERR_RESOLVE     = 5;
  ASIO_ERR_PHYS_IO     = 6;
  ASIO_ERR_VA_TO_PA    = 7;
  ASIO_ERR_INTERNAL    = 8;
  ASIO_ERR_NOMEM       = 9;

  ASIO_SCAN_T_BYTE   = 0;
  ASIO_SCAN_T_WORD   = 1;
  ASIO_SCAN_T_DWORD  = 2;
  ASIO_SCAN_T_QWORD  = 3;
  ASIO_SCAN_T_FLOAT  = 4;
  ASIO_SCAN_T_DOUBLE = 5;

  ASIO_SCAN_OP_EQ        = 0;
  ASIO_SCAN_OP_NEQ       = 1;
  ASIO_SCAN_OP_GT        = 2;
  ASIO_SCAN_OP_LT        = 3;
  ASIO_SCAN_OP_GE        = 4;
  ASIO_SCAN_OP_LE        = 5;
  ASIO_SCAN_OP_RANGE     = 6;
  ASIO_SCAN_OP_CHANGED   = 7;
  ASIO_SCAN_OP_UNCHANGED = 8;
  ASIO_SCAN_OP_INCREASED = 9;
  ASIO_SCAN_OP_DECREASED = 10;

type
  TUint64Array = array of uint64;

  TAsioR0Header = packed record
    magic: uint32;
    version: uint32;
    opcode: uint32;
    reserved: uint32;
    payload_len: uint64;
  end;

  TAsioR0Response = packed record
    magic: uint32;
    version: uint32;
    status: int32;
    reserved: uint32;
    payload_len: uint64;
  end;

  TAsioR0AttachResp = packed record
    cr3: uint64;
    image_base: uint64;
    image_size: uint64;
  end;

  TAsioR0RegionEntry = packed record
    allocation_base: uint64;
    base: uint64;
    region_size: uint64;
    state: uint32;
    protect: uint32;
    _type: uint32;
    allocation_protect: uint32;
  end;

  TRegionArray = array of TAsioR0RegionEntry;

  TAsioProcEntry = packed record
    pid: uint32;
    reserved: uint32;
    name: array[0..15] of AnsiChar;
  end;

  TAsioProcArray = array of TAsioProcEntry;

  TAsioThreadEntry = packed record
    tid: uint32;
    reserved: uint32;
    startAddress: uint64;
    teb: uint64;
  end;
  TAsioThreadArray = array of TAsioThreadEntry;

var
  AsioReady: boolean = false;

function AsioConnect(const pipeName: string = ''): boolean;
procedure AsioDisconnect;
function AsioIsConnected: boolean;

function AsioAttach(pid: uint32; var cr3, imageBase, imageSize: QWord): boolean;
function AsioRead(va: QWord; buf: pointer; size: QWord): boolean;
function AsioWrite(va: QWord; buf: pointer; size: QWord): boolean;
function AsioAlloc(size: QWord; protect: uint32; var va: QWord): boolean;
function AsioFree(va: QWord): boolean;
function AsioFreeMem(va: QWord; size: QWord): boolean;
function AsioEnumModules(var moduleData: TBytes): boolean;
function AsioEnumProcesses(var procs: TAsioProcArray): boolean;
function AsioEnumThreads(var threads: TAsioThreadArray): boolean;

function AsioScanAob(rangeStart, rangeEnd: QWord; alignment: uint32;
                     const pattern: SysUtils.TBytes; const mask: SysUtils.TBytes;
                     var hits: TUint64Array): boolean;
function AsioScanValue(rangeStart, rangeEnd: QWord; alignment: uint32;
                       valueType, scanOp: uint8; valueLo, valueHi: QWord;
                       var hits: TUint64Array): boolean;
function AsioScanNext(scanOp: uint8; valueLo, valueHi: QWord;
                      var hits: TUint64Array): boolean;

// VQE cache: attach 时一次性加载, 后续纯本地查询
function AsioPreloadRegionCache: boolean;
procedure AsioInvalidateRegionCache;
function AsioVqeLookup(address: QWord;
                       var allocBase, baseAddr, regionSize: QWord;
                       var state, protect, rtype, allocProtect: uint32): boolean;

// Hardware breakpoint via R0 pipe (bypasses SetThreadContext on target)
function AsioHwbpSet(tid: uint32; drIndex: uint8; va: QWord;
                     condition: uint8; len: uint8): boolean;
function AsioHwbpClear(tid: uint32; drIndex: uint8): boolean;

function AsioGetLastError: string;

implementation

type
  PAsioR0Header = ^TAsioR0Header;
  PAsioR0Response = ^TAsioR0Response;

  TReadReq = packed record
    va: uint64;
    size: uint64;
  end;
  PReadReq = ^TReadReq;

  TWriteReq = packed record
    va: uint64;
    size: uint64;
  end;
  PWriteReq = ^TWriteReq;

  TAllocReq = packed record
    size: uint64;
    protection: uint32;
    reserved: uint32;
  end;
  PAllocReq = ^TAllocReq;

  TAobReq = packed record
    range_start: uint64;
    range_end: uint64;
    alignment: uint32;
    max_hits: uint32;
    pattern_len: uint16;
    mask_len: uint16;
    reserved: uint32;
  end;
  PAobReq = ^TAobReq;

  TAsioR0ScanAobResp = packed record
    hit_count: uint32;
    truncated: uint32;
  end;

  TAsioR0ScanValueResp = packed record
    hit_count: uint32;
    truncated: uint32;
  end;

  TValueReq = packed record
    range_start: uint64;
    range_end: uint64;
    alignment: uint32;
    max_hits: uint32;
    value_type: uint8;
    scan_op: uint8;
    reserved: uint16;
    value_lo: uint64;
    value_hi: uint64;
  end;

  TNextReq = packed record
    scan_op: uint8;
    reserved: array[0..6] of byte;
    value_lo: uint64;
    value_hi: uint64;
  end;

  TRegionListResp = packed record
    count: uint32;
    reserved: uint32;
  end;

var
  hPipe: THandle = INVALID_HANDLE_VALUE;
  lastError: string = '';
  attachedPid: uint32 = 0;
  pipeCS: TRTLCriticalSection;
  pipeCsInit: boolean = false;

  // VQE region cache — sorted by base, binary searched
  regionCache: TRegionArray = nil;
  regionCacheCount: integer = 0;
  regionCacheValid: boolean = false;
  regionCacheTime: uint64 = 0;  // GetTickCount64 when cache was last loaded
  REGION_CACHE_TTL: uint64 = 30000; // auto-refresh after 30 seconds

procedure EnsurePipeCS;
begin
  if not pipeCsInit then
  begin
    InitCriticalSection(pipeCS);
    pipeCsInit := true;
  end;
end;

procedure PipeDrain(h: THandle; remaining: uint64);
var
  buf: array[0..4095] of byte;
  toRead, got: DWORD;
begin
  while remaining > 0 do
  begin
    if remaining > sizeof(buf) then toRead := sizeof(buf) else toRead := DWORD(remaining);
    if not ReadFile(h, buf[0], toRead, got, nil) or (got = 0) then break;
    dec(remaining, got);
  end;
end;

function AsioGetLastError: string;
begin
  result := lastError;
end;

function PipeWriteAll(h: THandle; const data; size: uint64): boolean;
var
  written, toWrite: DWORD;
  p: PByte;
begin
  p := @data;
  while size > 0 do
  begin
    if size > $10000 then toWrite := $10000 else toWrite := DWORD(size);
    if not WriteFile(h, p^, toWrite, written, nil) or (written = 0) then
    begin
      lastError := 'PipeWriteAll: ' + SysErrorMessage(GetLastError);
      exit(false);
    end;
    inc(p, written);
    dec(size, written);
  end;
  result := true;
end;

function PipeReadAll(h: THandle; var data; size: uint64): boolean;
var
  got, toRead: DWORD;
  p: PByte;
begin
  p := @data;
  while size > 0 do
  begin
    if size > $10000 then toRead := $10000 else toRead := DWORD(size);
    if not ReadFile(h, p^, toRead, got, nil) or (got = 0) then
    begin
      lastError := 'PipeReadAll: ' + SysErrorMessage(GetLastError);
      exit(false);
    end;
    inc(p, got);
    dec(size, got);
  end;
  result := true;
end;

function SendRecv(opcode: uint32; const reqData; reqSize: uint64;
                  var respData; respCapacity: uint64;
                  var respSize: uint64; var status: int32): boolean;
var
  hdr: TAsioR0Header;
  resp: TAsioR0Response;
begin
  result := false;
  if hPipe = INVALID_HANDLE_VALUE then
  begin
    lastError := 'Not connected';
    exit;
  end;

  EnsurePipeCS;
  EnterCriticalSection(pipeCS);
  try
    hdr.magic := ASIO_R0_REQ_MAGIC;
    hdr.version := ASIO_R0_PROTO_VERSION;
    hdr.opcode := opcode;
    hdr.reserved := 0;
    hdr.payload_len := reqSize;

    if not PipeWriteAll(hPipe, hdr, sizeof(hdr)) then exit;
    if (reqSize > 0) and not PipeWriteAll(hPipe, reqData, reqSize) then exit;

    if not PipeReadAll(hPipe, resp, sizeof(resp)) then exit;
    if resp.magic <> ASIO_R0_RSP_MAGIC then
    begin
      lastError := 'Bad response magic';
      exit;
    end;

    status := resp.status;
    respSize := resp.payload_len;

    if respSize > 0 then
    begin
      if respSize > respCapacity then
      begin
        PipeDrain(hPipe, respSize);
        lastError := 'Response too large';
        exit;
      end;
      if not PipeReadAll(hPipe, respData, respSize) then exit;
    end;

    result := true;
  finally
    LeaveCriticalSection(pipeCS);
  end;
end;

function SendRecvNoPayload(opcode: uint32; var respData; respCapacity: uint64;
                           var respSize: uint64; var status: int32): boolean;
var
  dummy: byte;
begin
  dummy := 0;
  result := SendRecv(opcode, dummy, 0, respData, respCapacity, respSize, status);
end;

function TryPipeConnect(const pn: string): boolean;
var
  pingStatus: int32;
  pingRespSize: uint64;
  dummy: byte;
begin
  result := false;
  hPipe := CreateFile(PChar(pn), GENERIC_READ or GENERIC_WRITE,
                      0, nil, OPEN_EXISTING, 0, 0);
  if hPipe = INVALID_HANDLE_VALUE then exit;

  if SendRecvNoPayload(ASIO_OP_PING, dummy, 0, pingRespSize, pingStatus) and
     (pingStatus = ASIO_OK) then
  begin
    AsioReady := true;
    result := true;
  end
  else
  begin
    CloseHandle(hPipe);
    hPipe := INVALID_HANDLE_VALUE;
  end;
end;

function DeriveHintFilePath: string;
var
  tmpDir: array[0..MAX_PATH-1] of char;
  hk: HKEY;
  machineGuid: array[0..63] of AnsiChar;
  sz: DWORD;
  hash: uint32;
  i: integer;
begin
  GetTempPath(MAX_PATH, @tmpDir[0]);
  // Read MachineGuid from registry (same as server)
  FillChar(machineGuid, SizeOf(machineGuid), 0);
  StrCopy(machineGuid, 'default');
  sz := SizeOf(machineGuid);
  if RegOpenKeyEx(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Cryptography', 0,
                  KEY_READ or KEY_WOW64_64KEY, hk) = 0 then
  begin
    RegQueryValueEx(hk, 'MachineGuid', nil, nil, @machineGuid[0], @sz);
    RegCloseKey(hk);
  end;
  // FNV-1a hash
  hash := $811c9dc5;
  i := 0;
  while machineGuid[i] <> #0 do
  begin
    hash := hash xor Byte(machineGuid[i]);
    hash := hash * $01000193;
    inc(i);
  end;
  result := IncludeTrailingPathDelimiter(string(tmpDir)) + IntToHex(hash, 8) + '.tmp';
end;

function DiscoverPipeName: string;
var
  hintPath: string;
  sl: TStringList;
begin
  result := '';
  hintPath := DeriveHintFilePath;
  if not FileExists(hintPath) then exit;
  sl := TStringList.Create;
  try
    sl.LoadFromFile(hintPath);
    if sl.Count > 0 then
      result := Trim(sl[0]);
  finally
    sl.Free;
  end;
end;

function AsioConnect(const pipeName: string): boolean;
var
  hintName: string;
begin
  result := false;
  AsioDisconnect;

  if pipeName <> '' then
  begin
    result := TryPipeConnect(pipeName);
    if not result then
      lastError := 'Connect: ' + SysErrorMessage(GetLastError);
    exit;
  end;

  // 1. Try hint file (server writes actual pipe name with PID suffix)
  hintName := DiscoverPipeName;
  if hintName <> '' then
  begin
    result := TryPipeConnect(hintName);
    if result then
    begin
      // Delete hint file after successful connection to avoid leaving pipe name on disk
      DeleteFile(PChar(DeriveHintFilePath));
      exit;
    end;
  end;

  // 2. Try default pipe name
  result := TryPipeConnect(ASIO_R0_DEFAULT_PIPE);
  if not result then
    lastError := 'Connect: no pipe found (tried hint + default)';
end;

procedure AsioDisconnect;
var
  hdr: TAsioR0Header;
  written: DWORD;
begin
  if hPipe <> INVALID_HANDLE_VALUE then
  begin
    hdr.magic := ASIO_R0_REQ_MAGIC;
    hdr.version := ASIO_R0_PROTO_VERSION;
    hdr.opcode := ASIO_OP_SHUTDOWN;
    hdr.reserved := 0;
    hdr.payload_len := 0;
    WriteFile(hPipe, hdr, sizeof(hdr), written, nil);
    CloseHandle(hPipe);
    hPipe := INVALID_HANDLE_VALUE;
  end;
  AsioReady := false;
  attachedPid := 0;
  regionCacheValid := false;
  regionCache := nil;
  regionCacheCount := 0;
end;

function AsioIsConnected: boolean;
begin
  result := (hPipe <> INVALID_HANDLE_VALUE) and AsioReady;
end;

function AsioAttach(pid: uint32; var cr3, imageBase, imageSize: QWord): boolean;
var
  req: uint32;
  resp: TAsioR0AttachResp;
  respSize: uint64;
  status: int32;
begin
  result := false;
  req := pid;
  if not SendRecv(ASIO_OP_ATTACH, req, sizeof(req),
                  resp, sizeof(resp), respSize, status) then exit;
  if (status = ASIO_OK) and (respSize >= sizeof(resp)) then
  begin
    cr3 := resp.cr3;
    imageBase := resp.image_base;
    imageSize := resp.image_size;
    attachedPid := pid;
    regionCacheValid := false;
    result := true;
  end
  else
    lastError := 'Attach failed: ' + IntToStr(status);
end;

function AsioRead(va: QWord; buf: pointer; size: QWord): boolean;
var
  req: TReadReq;
  respSize: uint64;
  status: int32;
begin
  result := false;
  req.va := va;
  req.size := size;
  if not SendRecv(ASIO_OP_READ, req, sizeof(req),
                  buf^, size, respSize, status) then exit;
  result := (status = ASIO_OK) and (respSize = size);
  if not result then lastError := 'Read: ' + IntToStr(status);
end;

function AsioWrite(va: QWord; buf: pointer; size: QWord): boolean;
var
  reqBuf: TBytes;
  resp: uint64;
  respSize: uint64;
  status: int32;
begin
  result := false;
  SetLength(reqBuf, sizeof(TWriteReq) + size);
  PWriteReq(@reqBuf[0])^.va := va;
  PWriteReq(@reqBuf[0])^.size := size;
  if size > 0 then Move(buf^, reqBuf[sizeof(TWriteReq)], size);
  if not SendRecv(ASIO_OP_WRITE, reqBuf[0], length(reqBuf),
                  resp, sizeof(resp), respSize, status) then exit;
  result := (status = ASIO_OK);
  if not result then lastError := 'Write: ' + IntToStr(status);
end;

function AsioAlloc(size: QWord; protect: uint32; var va: QWord): boolean;
var
  req: TAllocReq;
  resp: uint64;
  respSize: uint64;
  status: int32;
begin
  result := false;
  req.size := size;
  req.protection := protect;
  req.reserved := 0;
  if not SendRecv(ASIO_OP_ALLOC, req, sizeof(req),
                  resp, sizeof(resp), respSize, status) then exit;
  if (status = ASIO_OK) and (respSize >= sizeof(uint64)) then
  begin
    va := resp;
    result := true;
    AsioInvalidateRegionCache; // memory layout changed
  end
  else
    lastError := 'Alloc: ' + IntToStr(status);
end;

function AsioFree(va: QWord): boolean;
var
  respSize: uint64;
  status: int32;
  dummy: byte;
begin
  result := SendRecv(ASIO_OP_FREE, va, sizeof(va),
                     dummy, 0, respSize, status) and (status = ASIO_OK);
  if result then
    AsioInvalidateRegionCache; // memory layout changed
end;

function AsioEnumModules(var moduleData: TBytes): boolean;
var
  respSize: uint64;
  status: int32;
begin
  SetLength(moduleData, 64 * 1024);
  result := SendRecvNoPayload(ASIO_OP_ENUM_MODULES, moduleData[0],
                              length(moduleData), respSize, status) and (status = ASIO_OK);
  if result then SetLength(moduleData, respSize)
  else lastError := 'EnumModules: ' + IntToStr(status);
end;

function AsioEnumProcesses(var procs: TAsioProcArray): boolean;
var
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  header: TRegionListResp; // reuse layout: count + reserved
  count: integer;
begin
  result := false;
  if not AsioIsConnected then exit;

  SetLength(respBuf, 1024 * 1024);
  if not SendRecvNoPayload(ASIO_OP_ENUM_PROCS, respBuf[0],
                           length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < 8) then
  begin
    lastError := 'EnumProcesses: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], header, sizeof(header));
  count := header.count;
  // Validate count against actual response size to prevent buffer overread
  if count > integer((respSize - sizeof(header)) div sizeof(TAsioProcEntry)) then
    count := integer((respSize - sizeof(header)) div sizeof(TAsioProcEntry));
  SetLength(procs, count);
  if count > 0 then
    Move(respBuf[sizeof(header)], procs[0], count * sizeof(TAsioProcEntry));
  result := true;
end;

function AsioEnumThreads(var threads: TAsioThreadArray): boolean;
var
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  count: integer;
  header: TRegionListResp; // reuse: count + reserved
begin
  result := false;
  if not AsioIsConnected then exit;

  SetLength(respBuf, 512 * 1024);
  if not SendRecvNoPayload(ASIO_OP_ENUM_THREADS, respBuf[0],
                           length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < 8) then
  begin
    lastError := 'EnumThreads: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], header, sizeof(header));
  count := header.count;
  if count > integer((respSize - 8) div sizeof(TAsioThreadEntry)) then
    count := integer((respSize - 8) div sizeof(TAsioThreadEntry));
  SetLength(threads, count);
  if count > 0 then
    Move(respBuf[8], threads[0], count * sizeof(TAsioThreadEntry));
  result := true;
end;

function AsioFreeMem(va: QWord; size: QWord): boolean;
var
  req: packed record
    addr: uint64;
    sz: uint64;
  end;
  respSize: uint64;
  status: int32;
  dummy: byte;
begin
  result := false;
  if not AsioIsConnected then exit;
  req.addr := va;
  req.sz := size;
  result := SendRecv(ASIO_OP_FREE_MEM, req, sizeof(req), dummy, 0, respSize, status);
  if status <> ASIO_OK then
    lastError := 'FreeMem: ' + IntToStr(status);
  result := result and (status = ASIO_OK);
end;

// ---- VQE region cache ----

function AsioPreloadRegionCache: boolean;
var
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  header: TRegionListResp;
begin
  result := false;
  if not AsioIsConnected then exit;

  SetLength(respBuf, 64 * 1024 * 1024);
  if not SendRecvNoPayload(ASIO_OP_ENUM_REGIONS, respBuf[0],
                           length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < sizeof(TRegionListResp)) then
  begin
    lastError := 'EnumRegions: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], header, sizeof(header));
  regionCacheCount := header.count;
  // Validate count against actual response size to prevent buffer overread
  if regionCacheCount > integer((respSize - sizeof(header)) div sizeof(TAsioR0RegionEntry)) then
    regionCacheCount := integer((respSize - sizeof(header)) div sizeof(TAsioR0RegionEntry));
  SetLength(regionCache, regionCacheCount);
  if regionCacheCount > 0 then
    Move(respBuf[sizeof(header)], regionCache[0],
         regionCacheCount * sizeof(TAsioR0RegionEntry));
  regionCacheValid := true;
  regionCacheTime := GetTickCount64;
  result := true;
end;

procedure AsioInvalidateRegionCache;
begin
  regionCacheValid := false;
  regionCacheCount := 0;
  regionCache := nil;
end;

// Binary search: find region whose base <= address < base+region_size
function AsioVqeLookup(address: QWord;
                       var allocBase, baseAddr, regionSize: QWord;
                       var state, protect, rtype, allocProtect: uint32): boolean;
var
  lo, hi, mid: integer;
  e: TAsioR0RegionEntry;
begin
  result := false;
  if (not regionCacheValid) or
     (GetTickCount64 - regionCacheTime > REGION_CACHE_TTL) then
  begin
    if not AsioPreloadRegionCache then exit;
  end;

  lo := 0;
  hi := regionCacheCount - 1;
  while lo <= hi do
  begin
    mid := (lo + hi) div 2;
    e := regionCache[mid];
    if address < e.base then
      hi := mid - 1
    else if address >= e.base + e.region_size then
      lo := mid + 1
    else
    begin
      // Found
      allocBase := e.allocation_base;
      baseAddr := e.base;
      regionSize := e.region_size;
      state := e.state;
      protect := e.protect;
      rtype := e._type;
      allocProtect := e.allocation_protect;
      exit(true);
    end;
  end;
  // Not in any committed region → MEM_FREE
  allocBase := address and $FFFFFFFFFFFFF000;
  baseAddr := address and $FFFFFFFFFFFFF000;
  regionSize := $1000;
  state := $10000; // MEM_FREE
  protect := $01;  // PAGE_NOACCESS
  rtype := 0;
  allocProtect := 0;
  result := true;
end;

// ---- Scan operations ----

function AsioScanAob(rangeStart, rangeEnd: QWord; alignment: uint32;
                     const pattern: TBytes; const mask: TBytes;
                     var hits: TUint64Array): boolean;
var
  reqBuf: TBytes;
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  resp: TAsioR0ScanAobResp;
  patLen: integer;
begin
  result := false;
  patLen := length(pattern);
  if (patLen <> length(mask)) or (patLen = 0) then
  begin
    lastError := 'Pattern/mask mismatch';
    exit;
  end;

  SetLength(reqBuf, sizeof(TAobReq) + patLen * 2);
  PAobReq(@reqBuf[0])^.range_start := rangeStart;
  PAobReq(@reqBuf[0])^.range_end := rangeEnd;
  PAobReq(@reqBuf[0])^.alignment := alignment;
  PAobReq(@reqBuf[0])^.max_hits := 1 shl 20;
  PAobReq(@reqBuf[0])^.pattern_len := patLen;
  PAobReq(@reqBuf[0])^.mask_len := patLen;
  PAobReq(@reqBuf[0])^.reserved := 0;
  Move(pattern[0], reqBuf[sizeof(TAobReq)], patLen);
  Move(mask[0], reqBuf[sizeof(TAobReq) + patLen], patLen);

  SetLength(respBuf, 8 * 1024 * 1024);
  if not SendRecv(ASIO_OP_SCAN_AOB, reqBuf[0], length(reqBuf),
                  respBuf[0], length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < sizeof(TAsioR0ScanAobResp)) then
  begin
    lastError := 'ScanAob: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], resp, sizeof(resp));
  SetLength(hits, resp.hit_count);
  if resp.hit_count > 0 then
    Move(respBuf[sizeof(resp)], hits[0], resp.hit_count * sizeof(uint64));
  result := true;
end;

function AsioScanValue(rangeStart, rangeEnd: QWord; alignment: uint32;
                       valueType, scanOp: uint8; valueLo, valueHi: QWord;
                       var hits: TUint64Array): boolean;
var
  req: TValueReq;
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  resp: TAsioR0ScanValueResp;
begin
  result := false;
  req.range_start := rangeStart;
  req.range_end := rangeEnd;
  req.alignment := alignment;
  req.max_hits := 1 shl 20;
  req.value_type := valueType;
  req.scan_op := scanOp;
  req.reserved := 0;
  req.value_lo := valueLo;
  req.value_hi := valueHi;

  SetLength(respBuf, 8 * 1024 * 1024);
  if not SendRecv(ASIO_OP_SCAN_VALUE, req, sizeof(req),
                  respBuf[0], length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < sizeof(TAsioR0ScanValueResp)) then
  begin
    lastError := 'ScanValue: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], resp, sizeof(resp));
  SetLength(hits, resp.hit_count);
  if resp.hit_count > 0 then
    Move(respBuf[sizeof(resp)], hits[0], resp.hit_count * sizeof(uint64));
  result := true;
end;

function AsioScanNext(scanOp: uint8; valueLo, valueHi: QWord;
                      var hits: TUint64Array): boolean;
var
  req: TNextReq;
  respBuf: TBytes;
  respSize: uint64;
  status: int32;
  resp: TAsioR0ScanValueResp;
begin
  result := false;
  req.scan_op := scanOp;
  FillChar(req.reserved, sizeof(req.reserved), 0);
  req.value_lo := valueLo;
  req.value_hi := valueHi;

  SetLength(respBuf, 8 * 1024 * 1024);
  if not SendRecv(ASIO_OP_SCAN_NEXT, req, sizeof(req),
                  respBuf[0], length(respBuf), respSize, status) then exit;
  if (status <> ASIO_OK) or (respSize < sizeof(TAsioR0ScanValueResp)) then
  begin
    lastError := 'ScanNext: ' + IntToStr(status);
    exit;
  end;

  Move(respBuf[0], resp, sizeof(resp));
  SetLength(hits, resp.hit_count);
  if resp.hit_count > 0 then
    Move(respBuf[sizeof(resp)], hits[0], resp.hit_count * sizeof(uint64));
  result := true;
end;

function AsioHwbpSet(tid: uint32; drIndex: uint8; va: QWord;
                     condition: uint8; len: uint8): boolean;
var
  req: packed record
    r_tid: uint32;
    r_dr_index: uint8;
    r_condition: uint8;
    r_length: uint8;
    r_reserved: uint8;
    r_va: uint64;
  end;
  respSize: uint64;
  status: int32;
begin
  result := false;
  if not AsioIsConnected then exit;
  req.r_tid := tid;
  req.r_dr_index := drIndex;
  req.r_condition := condition;
  req.r_length := len;
  req.r_reserved := 0;
  req.r_va := va;
  result := SendRecv(ASIO_OP_HWBP_SET, req, sizeof(req), req, 0, respSize, status);
  if status <> ASIO_OK then
    lastError := 'HwbpSet: ' + IntToStr(status);
  result := result and (status = ASIO_OK);
end;

function AsioHwbpClear(tid: uint32; drIndex: uint8): boolean;
var
  req: packed record
    r_tid: uint32;
    r_dr_index: uint8;
    r_reserved: array[0..2] of uint8;
  end;
  respSize: uint64;
  status: int32;
begin
  result := false;
  if not AsioIsConnected then exit;
  req.r_tid := tid;
  req.r_dr_index := drIndex;
  req.r_reserved[0] := 0;
  req.r_reserved[1] := 0;
  req.r_reserved[2] := 0;
  result := SendRecv(ASIO_OP_HWBP_CLEAR, req, sizeof(req), req, 0, respSize, status);
  if status <> ASIO_OK then
    lastError := 'HwbpClear: ' + IntToStr(status);
  result := result and (status = ASIO_OK);
end;

end.
