unit DebuggerInterfaceAPIWrapper;
{
This unit hold the DebuggerInterface currently used, and overrides the default windows debug api's so they make use of the DebuggerInterface's version
}

{$mode delphi}

interface

uses
  Classes, SysUtils, {$ifdef windows}windows,{$endif} debuggerinterface, newkernelhandler, AsioBridge{$ifdef darwin}, macport, macportdefines{$endif};

function WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL;
function ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL;
function SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL; overload;
function SetThreadContext(hThread: THandle; const lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
function SetThreadContext(hThread: THandle; const lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
function SetThreadContext(hThread: THandle; lpContext: pointer; isFrozenThread: Boolean=false): BOOL; overload;
function GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false): BOOL; overload;
function GetThreadContext(hThread: THandle; var lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
function GetThreadContext(hThread: THandle; var lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
function GetThreadContext(hThread: THandle; lpContext: pointer; isFrozenThread: Boolean=false): BOOL; overload;
function GetThreadContextArm(hThread: THandle; var lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL;
function SetThreadContextArm(hThread: THandle; const lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL;
function GetThreadContextArm64(hThread: THandle; var lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL;
function SetThreadContextArm64(hThread: THandle; const lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL;

function DebugActiveProcess(dwProcessId: DWORD): WINBOOL;
function DebugActiveProcessStop(dwProcessID: DWORD): WINBOOL;

var CurrentDebuggerInterface: TDebuggerInterface;

implementation

uses CEDebugger;

{$ifdef windows}
function WinGetThreadId(hThread: THandle): DWORD; stdcall; external 'kernel32.dll' name 'GetThreadId';
{$endif}

function WaitForDebugEvent(var lpDebugEvent: TDebugEvent; dwMilliseconds: DWORD): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.WaitForDebugEvent(lpDebugEvent, dwMilliseconds)
  else
    result:=false;
end;

function ContinueDebugEvent(dwProcessId: DWORD; dwThreadId: DWORD; dwContinueStatus: DWORD): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.ContinueDebugEvent(dwProcessID, dwThreadID, dwContinueStatus)
  else
    result:=false;
end;



function SetThreadContext(hThread: THandle; const lpContext: TContext; isFrozenThread: Boolean=false): BOOL;
{$ifdef windows}
var
  tid: DWORD;
{$endif}
begin
  {$ifdef windows}
  // R0 path: route debug register changes through ASIO pipe
  // This avoids CE directly calling SetThreadContext on target threads
  if AsioReady and ((lpContext.ContextFlags and $10) <> 0) then
  begin
    tid := WinGetThreadId(hThread);
    if tid <> 0 then
    begin
      // Set all 4 debug registers via ASIO pipe
      if lpContext.Dr0 <> 0 then
        AsioHwbpSet(tid, 0, lpContext.Dr0, (lpContext.Dr7 shr 16) and 3, 1);
      if lpContext.Dr1 <> 0 then
        AsioHwbpSet(tid, 1, lpContext.Dr1, (lpContext.Dr7 shr 20) and 3, 1);
      if lpContext.Dr2 <> 0 then
        AsioHwbpSet(tid, 2, lpContext.Dr2, (lpContext.Dr7 shr 24) and 3, 1);
      if lpContext.Dr3 <> 0 then
        AsioHwbpSet(tid, 3, lpContext.Dr3, (lpContext.Dr7 shr 28) and 3, 1);
      // Clear registers that were zeroed
      if (lpContext.Dr0 = 0) and ((lpContext.Dr7 and 1) = 0) then
        AsioHwbpClear(tid, 0);
      if (lpContext.Dr1 = 0) and ((lpContext.Dr7 and 4) = 0) then
        AsioHwbpClear(tid, 1);
      if (lpContext.Dr2 = 0) and ((lpContext.Dr7 and 16) = 0) then
        AsioHwbpClear(tid, 2);
      if (lpContext.Dr3 = 0) and ((lpContext.Dr7 and 64) = 0) then
        AsioHwbpClear(tid, 3);
      result := BOOL(true);
      exit;
    end;
  end;
  {$endif}
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.SetThreadContext(hThread, lpContext, isFrozenThread)
  else
    result:=NewKernelHandler.SetThreadContext(hThread, lpcontext);
end;

function SetThreadContext(hThread: THandle; lpContext: pointer; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.SetThreadContext(hThread, lpContext, isFrozenThread)
  else
    result:=NewKernelHandler.SetThreadContext(hThread, PContext(lpcontext)^);

end;

function SetThreadContext(hThread: THandle; const lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  result:=SetThreadContextArm(hThread, lpContext, isFrozenThread);
end;

function SetThreadContext(hThread: THandle; const lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  result:=SetThreadContextArm64(hThread, lpContext, isFrozenThread);
end;




function GetThreadContextArm(hThread: THandle; var lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.GetThreadContextArm(hThread, lpContext, isFrozenThread)
  else
    result:=false;
end;

function SetThreadContextArm(hThread: THandle; const lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.SetThreadContextArm(hThread, lpContext, isFrozenThread)
  else
    result:=false; //not yet implemented.  ceserver uses it's own setbreakpoint, for now , and I do not support arm32 for darwin(macos)
end;

function GetThreadContextArm64(hThread: THandle; var lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.GetThreadContextArm64(hThread, lpContext, isFrozenThread)
  else
  begin
    {$ifdef darwin}
    result:=macport.GetThreadContextArm64(hThread, lpContext);
    {$else}
    result:=false;
    {$endif}

  end;
end;

function SetThreadContextArm64(hThread: THandle; const lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.SetThreadContextArm64(hThread, lpContext, isFrozenThread)
  else
  begin
    {$ifdef darwin}
    result:=macport.SetThreadContextArm64(hThread, lpContext);
    {$else}
    result:=false;
    {$endif}
  end;
end;

function GetThreadContext(hThread: THandle; var lpContext: TContext; isFrozenThread: Boolean=false): BOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.GetThreadContext(hThread, lpContext, isFrozenThread)
  else
    result:=NewKernelHandler.GetThreadContext(hThread, lpContext);
end;

function GetThreadContext(hThread: THandle; lpContext: pointer; isFrozenThread: Boolean=false): BOOL; overload;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.GetThreadContext(hThread, lpContext, isFrozenThread)
  else
    result:=NewKernelHandler.GetThreadContext(hThread, PContext(lpContext)^);
end;

function GetThreadContext(hThread: THandle; var lpContext: TARMCONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
begin
  result:=GetThreadContextArm(hThread, lpContext, isFrozenThread);
end;

function GetThreadContext(hThread: THandle; var lpContext: TARM64CONTEXT; isFrozenThread: Boolean=false): BOOL; overload;
begin
  result:=GetThreadContextArm64(hThread, lpContext, isFrozenThread);
end;



function DebugActiveProcess(dwProcessId: DWORD): WINBOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.DebugActiveProcess(dwProcessID)
  else
    result:=false;
end;

function DebugActiveProcessStop(dwProcessID: DWORD): WINBOOL;
begin
  if CurrentDebuggerInterface<>nil then
    result:=CurrentDebuggerInterface.DebugActiveProcessStop(dwProcessID)
  else
  {$ifdef windows}
    result:=cedebugger.DebugActiveProcessStop(dwProcessID);
  {$else}
    result:=false;
  {$endif}
end;


end.

