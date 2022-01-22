#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

## This module is designed to be a drop-in replacement for `dynlib pragma`
## and `dynlib module` in Windows. The main part of this module is a pure nim
## implementation of the famous MemoryModule library.
## So that the we can embed all DLLs into the main EXE file.

import tables, macros, md5, locks, os, terminal, strutils, dynlib
import winim/lean, minhook
import memlib/private/sharedseq

when (compiles do: import std/exitprocs):
  import std/exitprocs
  proc addQuitProc(cl: proc() {.noconv.}) = addExitProc(cl)

template atexit(body: untyped): untyped =
  addQuitProc proc () {.noconv.} =
    body

when not defined(windows):
  {.fatal: "Only implementation for Windows".}

type
  DllEntryProc = proc (dll: HINSTANCE, reason: DWORD, reserved: pointer): bool {.stdcall, gcsafe, raises: [], tags: [].}
  ExeEntryProc = proc (): int {.stdcall, gcsafe, raises: [], tags: [].}

  NameOrdinal = object
    cname: LPCSTR
    ordinal: int

  MemoryModuleObj = object
    headers: PIMAGE_NT_HEADERS
    codeBase: pointer
    initialized: bool
    isDll: bool
    isRelocated: bool
    entry: pointer
    modules: SharedSeq[HMODULE]
    symbols: SharedSeq[NameOrdinal]
    hash: MD5Digest
    reference: int
    name: LPCWSTR

  MemoryModule* = ptr MemoryModuleObj
    ## Pointer to a MemoryModule object.

  DllContent* = distinct string
    ## Represents DLL file in binary format.

var
  memLibs: SharedSeq[MemoryModule]
  rtLibs: SharedSeq[HMODULE]
  gLock: Lock
  hookEnabled: bool

proc `[]`[T](x: T, U: typedesc): U =
  ## syntax sugar for cast
  cast[U](x)

proc `{}`[T](x: T, U: typedesc): U =
  ## syntax sugar for zero extends cast
  when sizeof(x) == 1: x[uint8][U]
  elif sizeof(x) == 2: x[uint16][U]
  elif sizeof(x) == 4: x[uint32][U]
  elif sizeof(x) == 8: x[uint64][U]
  else: {.fatal.}

template `++`[T](p: var ptr T) =
  ## syntax sugar for pointer increment
  p = cast[ptr T](p[int] +% sizeof(T))

template `{}`[T](p: T, x: SomeInteger): T =
  ## syntax sugar for pointer (or any other type) arithmetics
  cast[T]((cast[int](p) +% x{int}))

template alignUp[T: uint|pointer](value: T, alignment: uint): T =
  cast[T]((cast[uint](value) + alignment - 1) and not (alignment - 1))

template alignDown[T: uint|pointer](value: T, alignment: uint): T =
  cast[T](cast[uint](value) and not (alignment - 1))

iterator sections(ntHeader: PIMAGE_NT_HEADERS): var IMAGE_SECTION_HEADER =
  let sections = IMAGE_FIRST_SECTION(ntHeader)[ptr UncheckedArray[IMAGE_SECTION_HEADER]]
  for i in 0 ..< int ntHeader.FileHeader.NumberOfSections:
    yield sections[i]

proc getPageSize(): uint {.inline, raises: [].} =
  var sysInfo: SYSTEM_INFO
  GetNativeSystemInfo(sysInfo)
  return sysInfo.dwPageSize{uint}

proc symErrorMessage(sym: LPCSTR): string {.raises: [].} =
  let msg = if HIWORD(sym{uint}) == 0: "ordinal " & $(sym{uint}) else: "symbol " & $sym
  result = "Could not find " & msg

proc validate(data: pointer, size: int): MD5Digest {.raises: [LibraryError].} =
  if data == nil or size < sizeof(IMAGE_DOS_HEADER):
    raise newException(LibraryError, "Invalid data")

  let dosHeader = data[PIMAGE_DOS_HEADER]

  if dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    raise newException(LibraryError, "Invalid data")

  if size < dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS):
    raise newException(LibraryError, "Invalid data")

  let ntHeader = data{dosHeader.e_lfanew}[PIMAGE_NT_HEADERS]
  if ntHeader.Signature != IMAGE_NT_SIGNATURE:
    raise newException(LibraryError, "Invalid data")

  when defined(cpu64):
    if ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64:
      raise newException(LibraryError, "Incorrect architecture")
  else:
    if ntHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_I386:
      raise newException(LibraryError, "Incorrect architecture")

  # Only support section alignments that are a multiple of 2
  if (ntHeader.OptionalHeader.SectionAlignment and 1) != 0:
    raise newException(LibraryError, "Invalid data")

  if size < ntHeader.OptionalHeader.SizeOfHeaders:
    raise newException(LibraryError, "Invalid data")

  var ctx: MD5Context
  ctx.md5Init()
  ctx.md5Update(data[cstring], size)
  ctx.md5Final(result)

proc newMemoryModule(): MemoryModule {.raises: [LibraryError].} =
  result = createShared(MemoryModuleObj)
  if result == nil:
    raise newException(LibraryError, "Out of memory")

  result.modules = newSharedSeq[HMODULE]()
  result.symbols = newSharedSeq[NameOrdinal]()

proc dealloc(lib: MemoryModule) {.inline, raises: [].} =
  deallocShared(lib)

proc allocMemory(lib: MemoryModule, ntHeader: PIMAGE_NT_HEADERS, pageSize: uint) {.raises: [LibraryError].} =
  var lastSectionEnd = 0'u
  for section in ntHeader.sections:
    let endOfSection = section.VirtualAddress{uint}{
      if section.SizeOfRawData == 0: ntHeader.OptionalHeader.SectionAlignment
      else: section.SizeOfRawData
    }

    if endOfSection > lastSectionEnd:
      lastSectionEnd = endOfSection

  let alignedImageSize = alignUp(ntHeader.OptionalHeader.SizeOfImage{uint}, pageSize)
  if alignedImageSize == 0 or alignedImageSize != alignUp(lastSectionEnd, pageSize):
    raise newException(LibraryError, "Invalid data")

  # reserve memory for image of library
  var codeBase = VirtualAlloc(ntHeader.OptionalHeader.ImageBase[pointer],
    alignedImageSize[SIZE_T], MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)

  if codeBase == nil:
    # try to allocate memory at arbitrary position
    codeBase = VirtualAlloc(nil, alignedImageSize[SIZE_T], MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
    if codeBase == nil:
      raise newException(LibraryError, "Out of memory")

  when defined(cpu64):
    var blocked: seq[pointer]
    try:
      # Memory block may not span 4 GB boundaries
      while (codeBase[uint] shr 32) < ((codeBase[uint] + alignedImageSize) shr 32):
        blocked.add codeBase
        codeBase = VirtualAlloc(nil, alignedImageSize[SIZE_T], MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)

        if codeBase == nil:
          raise newException(LibraryError, "Out of memory")

    finally:
      for p in blocked:
        VirtualFree(p, 0, MEM_RELEASE)

  lib.codeBase = codeBase

proc copyHeaders(lib: MemoryModule, dosHeader: PIMAGE_DOS_HEADER, ntHeader: PIMAGE_NT_HEADERS) {.raises: [].} =
  # commit memory for headers
  let headers = VirtualAlloc(lib.codeBase, ntHeader.OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE)

  copyMem(headers, dosHeader, ntHeader.OptionalHeader.SizeOfHeaders)
  lib.headers = headers{dosHeader.e_lfanew}[PIMAGE_NT_HEADERS]

  lib.headers.OptionalHeader.ImageBase = lib.codeBase[ntHeader.OptionalHeader.ImageBase.type]
  lib.isDll = (ntHeader.FileHeader.Characteristics and IMAGE_FILE_DLL) != 0

proc copySections(lib: MemoryModule, data: pointer, size: int, ntHeader: PIMAGE_NT_HEADERS) {.raises: [LibraryError].} =
  let codeBase = lib.codeBase

  for section in lib.headers.sections:
    if section.SizeOfRawData == 0:
      # section doesn't contain data in the dll itself, but may define uninitialized data
      let sectionSize = ntHeader.OptionalHeader.SectionAlignment
      if sectionSize > 0:
        var dest = VirtualAlloc(codeBase{section.VirtualAddress}, sectionSize, MEM_COMMIT, PAGE_READWRITE)
        if dest == nil:
          raise newException(LibraryError, "Out of memory")

        # Always use position from file to support alignments smaller¡¡
        # than page size (allocation above will align to page size).
        dest = codeBase{section.VirtualAddress}

        # NOTE: On 64bit systems we truncate to 32bit here but expand
        # again later when "PhysicalAddress" is used.
        section.Misc.PhysicalAddress = dest[DWORD]
        zeroMem(dest, sectionSize)

      continue

    if size <% (section.PointerToRawData +% section.SizeOfRawData):
      raise newException(LibraryError, "Invalid data")

    # commit memory block and copy data from dll
    var dest = VirtualAlloc(codeBase{section.VirtualAddress}, section.SizeOfRawData, MEM_COMMIT, PAGE_READWRITE)
    if dest == nil:
      raise newException(LibraryError, "Out of memory")

    # Always use position from file to support alignments smaller
    # than page size (allocation above will align to page size).
    dest = codeBase{section.VirtualAddress}

    # NOTE: On 64bit systems we truncate to 32bit here but expand
    # again later when "PhysicalAddress" is used.
    section.Misc.PhysicalAddress = dest[DWORD]
    copyMem(dest, data{section.PointerToRawData}, section.SizeOfRawData)

proc performBaseRelocation(lib: MemoryModule, ntHeader: PIMAGE_NT_HEADERS) {.raises: [].} =

  iterator relocations(codeBase: pointer, directory: IMAGE_DATA_DIRECTORY): PIMAGE_BASE_RELOCATION =
    if directory.Size != 0:
      var relocation = codeBase{directory.VirtualAddress}[PIMAGE_BASE_RELOCATION]
      while relocation.VirtualAddress != 0:
        yield relocation
        relocation = relocation{relocation.SizeOfBlock}

  iterator pairs(relocation: PIMAGE_BASE_RELOCATION): (int, int) =
    let info = relocation{IMAGE_SIZEOF_BASE_RELOCATION}[ptr UncheckedArray[uint16]]
    for i in 0 ..< (relocation.SizeOfBlock{uint} - IMAGE_SIZEOF_BASE_RELOCATION) div 2:
      let
        kind = info[i] shr 12 # the upper 4 bits define the type of relocation
        off = info[i] and 0xfff # the lower 12 bits define the offset

      yield (int kind, int off)

  let delta = int(lib.headers.OptionalHeader.ImageBase - ntHeader.OptionalHeader.ImageBase)
  if delta != 0:
    let
      codeBase = lib.codeBase
      directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]

    if directory.Size == 0:
      lib.isRelocated = false
      return

    for relocation in codeBase.relocations(directory):
      let dest = codeBase{relocation.VirtualAddress}

      for kind, off in relocation:
        if kind == IMAGE_REL_BASED_HIGHLOW:
          let p = dest{off}[ptr int32]
          p[] = p[]{delta}

        when defined(cpu64):
          if kind == IMAGE_REL_BASED_DIR64:
            let p = dest{off}[ptr int64]
            p[] = p[]{delta}

  lib.isRelocated = true

proc buildImportTable(lib: MemoryModule) {.raises: [LibraryError].} =

  iterator descriptors(codeBase: pointer, directory: IMAGE_DATA_DIRECTORY): IMAGE_IMPORT_DESCRIPTOR =
    if directory.Size != 0:
      var desc = codeBase{directory.VirtualAddress}[PIMAGE_IMPORT_DESCRIPTOR]
      while (IsBadReadPtr(desc, UINT_PTR sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0) and (desc.Name != 0):
        yield desc[]
        ++desc

  iterator refs(codeBase: pointer, desc: IMAGE_IMPORT_DESCRIPTOR): (ptr pointer, ptr pointer) =
    var
      funcRef = codeBase{desc.FirstThunk}[ptr pointer]
      thunkRef =
        if desc.OriginalFirstThunk != 0: codeBase{desc.OriginalFirstThunk}[ptr pointer]
        else: funcRef

    while thunkRef[] != nil:
      yield (thunkRef, funcRef)
      ++thunkRef
      ++funcRef

  var
    codeBase = lib.codeBase
    directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

  for desc in codeBase.descriptors(directory):
    let
      cname = codeBase{desc.Name}[LPCSTR]
      handle = LoadLibraryA(cname)

    if handle == 0:
      raise newException(LibraryError, $cname & " not found")

    lib.modules.add handle

    for thunkRef, funcRef in refs(codeBase, desc):
      if IMAGE_SNAP_BY_ORDINAL(thunkRef[][int]):
        let ordinal = IMAGE_ORDINAL(thunkRef[][int])

        funcRef[] = GetProcAddress(handle, ordinal[LPCSTR])
        if funcRef[] == nil:
          raise newException(LibraryError, $ordinal & " not found in " & $cname)

      else:
        let
          thunkData = codeBase{thunkRef[][int]}[PIMAGE_IMPORT_BY_NAME]
          cfunc = thunkData.Name[0].addr[LPCSTR]

        funcRef[] = GetProcAddress(handle, cfunc)
        if funcRef[] == nil:
          raise newException(LibraryError, $cfunc & " not found in " & $cname)

proc finalizeSections(lib: MemoryModule, pageSize: uint) {.raises: [LibraryError].} =
  type
    SectionData = object
      address: pointer
      alignedAddr: pointer
      size: uint
      characteristics: DWORD
      last: bool

  proc realSize(lib: MemoryModule, section: IMAGE_SECTION_HEADER): uint =
    result = section.SizeOfRawData{uint}
    if result == 0:
      if (section.Characteristics and IMAGE_SCN_CNT_INITIALIZED_DATA) != 0:
        result = lib.headers.OptionalHeader.SizeOfInitializedData{uint}
      elif (section.Characteristics and IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0:
        result = lib.headers.OptionalHeader.SizeOfUninitializedData{uint}

  proc finalizeSection(lib: MemoryModule, data: SectionData) =
    if data.size == 0:
      return

    if (data.characteristics and IMAGE_SCN_MEM_DISCARDABLE) != 0:
      if data.address == data.alignedAddr and
          (data.last or
            lib.headers.OptionalHeader.SectionAlignment{uint} == pageSize or
            (data.size mod pageSize) == 0
          ):
        # Only allowed to decommit whole pages
        VirtualFree(data.address, data.size[SIZE_T], MEM_DECOMMIT)
      return

    const flags = [
      [[PAGE_NOACCESS, PAGE_WRITECOPY],
        [PAGE_READONLY, PAGE_READWRITE]],
      [[PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY],
        [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]]
    ]

    # determine protection flags based on characteristics
    var
      executable = int((data.characteristics and IMAGE_SCN_MEM_EXECUTE) != 0)
      readable = int((data.characteristics and IMAGE_SCN_MEM_READ) != 0)
      writeable = int((data.characteristics and IMAGE_SCN_MEM_WRITE) != 0)
      protect = DWORD flags[executable][readable][writeable]
      oldProtect: DWORD

    if (data.characteristics and IMAGE_SCN_MEM_NOT_CACHED) != 0:
      protect = protect or PAGE_NOCACHE

    if VirtualProtect(data.address, data.size[SIZE_T], protect, &oldProtect) == 0:
      raise newException(LibraryError, "protecting page failed")

  when defined(cpu64):
    # "PhysicalAddress" might have been truncated to 32bit above, expand to 64bits again.
    let imageOffset = lib.headers.OptionalHeader.ImageBase and 0xffffffff00000000
  else:
    const imageOffset = 0

  var
    firstSection = true
    data: SectionData

  for section in lib.headers.sections:
    if firstSection:
      data.address = (section.Misc.PhysicalAddress{uint} or imageOffset{uint})[pointer]
      data.alignedAddr = alignDown(data.address, pageSize)
      data.size = lib.realSize(section)
      data.characteristics = section.Characteristics
      data.last = false
      firstSection = false
      continue

    let
      address = (section.Misc.PhysicalAddress{uint} or imageOffset{uint})[pointer]
      alignedAddr = alignDown(address, pageSize)
      size = lib.realSize(section)

    # Combine access flags of all sections that share a page
    if data.alignedAddr == alignedAddr or data.address{data.size} > alignedAddr:
      let combine = data.characteristics or section.Characteristics
      if (section.Characteristics and IMAGE_SCN_MEM_DISCARDABLE) == 0 or
          (data.characteristics and IMAGE_SCN_MEM_DISCARDABLE) == 0:
        data.characteristics = combine and (not IMAGE_SCN_MEM_DISCARDABLE)
      else:
        data.characteristics = combine

      data.size = address{size}[uint] - data.address[uint]
      continue

    lib.finalizeSection(data)
    data.address = address
    data.alignedAddr = alignedAddr
    data.size = size
    data.characteristics = section.Characteristics

  data.last = true
  lib.finalizeSection(data)

proc executeTLS(lib: MemoryModule) {.raises: [].} =
  type
    PIMAGE_TLS_CALLBACK = proc (DllHandle: PVOID, Reason: DWORD, Reserved: PVOID) {.stdcall, gcsafe, raises: [], tags: [].}

  let
    codeBase = lib.codeBase
    directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]

  if directory.VirtualAddress != 0:
    var
      tls = codeBase{directory.VirtualAddress}[PIMAGE_TLS_DIRECTORY]
      callback = tls.AddressOfCallBacks[ptr PIMAGE_TLS_CALLBACK]

    if callback != nil:
      while callback[] != nil:
        callback[](codeBase, DLL_PROCESS_ATTACH, nil)
        ++callback

proc addFunctionTable(lib: MemoryModule) {.raises: [].} =
  when defined(cpu64):
    let
      codeBase = lib.codeBase
      directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]

    var
      funcTablePtr = codeBase{directory.VirtualAddress}[PRUNTIME_FUNCTION]

    RtlAddFunctionTable(funcTablePtr, (directory.Size div sizeof(RUNTIME_FUNCTION).DWORD), codeBase[DWORD64])

proc initialize(lib: MemoryModule) {.raises: [LibraryError].} =
  lib.entry = lib.codeBase{lib.headers.OptionalHeader.AddressOfEntryPoint}
  if lib.entry != nil and lib.isDll:
    let ok = lib.entry[DllEntryProc](lib.codeBase[HINSTANCE], DLL_PROCESS_ATTACH, nil)
    if not ok:
      raise newException(LibraryError, "Initialize failed")

    lib.initialized = true

proc gatherSymbols(lib: MemoryModule) {.raises: [].} =

  iterator entries(codeBase: pointer, exports: PIMAGE_EXPORT_DIRECTORY): (LPCSTR, int) =
    var
      nameRef = codeBase{exports.AddressOfNames}[ptr uint32]
      ordinal = codeBase{exports.AddressOfNameOrdinals}[ptr uint16]

    for i in 0 ..< exports.NumberOfNames:
      let
        name = codeBase{nameRef[]}[LPCSTR]
        index = int ordinal[]

      yield (name, index)

      ++nameRef
      ++ordinal

  let
    codeBase = lib.codeBase
    directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

  if directory.Size != 0:
    let exports = codeBase{directory.VirtualAddress}[PIMAGE_EXPORT_DIRECTORY]
    for cname, ordinal in codeBase.entries(exports):
      lib.symbols.add NameOrdinal(cname: cname, ordinal: ordinal)

  lib.symbols.sort() do (x, y: NameOrdinal) -> int:
    result = lstrcmpA(x.cname, y.cname)

proc findSymbol(lib: MemoryModule, name: LPCSTR): pointer {.raises: [LibraryError].} =
  block:
    if lib == nil: break

    let
      codeBase = lib.codeBase
      directory = lib.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

    if directory.Size == 0: break

    let exports = codeBase{directory.VirtualAddress}[PIMAGE_EXPORT_DIRECTORY]
    if exports.NumberOfFunctions == 0: break

    var index = 0
    if HIWORD(name{uint}) == 0:
      if LOWORD(name{uint})[DWORD] <% exports.Base: break
      index = LOWORD(name{uint})[DWORD] -% exports.Base

    else:
      let found = lib.symbols.binarySearch(name) do (x: NameOrdinal, y: LPCSTR) -> int:
        result = lstrcmpA(x.cname, y)

      if found < 0: break
      index = lib.symbols[found].ordinal

    if index >% exports.NumberOfFunctions: break

    let rva = codeBase{exports.AddressOfFunctions}{index * 4}[ptr uint32][]
    return codeBase{rva}

  raise newException(LibraryError, symErrorMessage(name))

proc register(lib: MemoryModule, hash: MD5Digest) {.raises: [].} =
  withLock(gLock):
    lib.hash = hash
    lib.reference = 1
    memLibs.add lib

proc unregister(lib: MemoryModule) {.raises: [].} =
  withLock(gLock):
    let found = memLibs.find lib
    if found >= 0:
      memLibs.del found

proc reloadCheck(hash: MD5Digest, lib: var MemoryModule): bool {.raises: [].} =
  withLock(gLock):
    for i in 0 ..< memLibs.len:
      if memLibs[i].hash == hash:
        memLibs[i].reference.inc
        lib = memLibs[i]
        return true

proc unloadLib(lib: MemoryModule, force: bool) {.raises: [].} =
  if lib != nil:
    if lib.reference > 1 and not force:
      lib.reference.dec
      return

    if lib.entry != nil and lib.isDll and lib.initialized:
      discard lib.entry[DllEntryProc](lib.codeBase[HINSTANCE], DLL_PROCESS_DETACH, nil)

    lib.unregister()

    for handle in lib.modules:
      FreeLibrary(handle)

    lib.modules.dealloc()
    lib.symbols.dealloc()

    if lib.codeBase != nil:
      VirtualFree(lib.codeBase, 0, MEM_RELEASE)

    if lib.name != nil:
      deallocShared(lib.name)

    lib.dealloc()

proc loadLib(data: pointer, size: int): MemoryModule {.raises: [LibraryError].} =
  try:
    let hash = validate(data, size)
    if reloadCheck(hash, result): return

    let
      pageSize = getPageSize()
      dosHeader = data[PIMAGE_DOS_HEADER]
      ntHeader = data{dosHeader.e_lfanew}[PIMAGE_NT_HEADERS]

    result = newMemoryModule()
    result.allocMemory(ntHeader, pageSize)
    result.copyHeaders(dosHeader, ntHeader)
    result.copySections(data, size, ntHeader)
    result.performBaseRelocation(ntHeader)
    result.buildImportTable()
    result.finalizeSections(pageSize)
    result.executeTLS()
    result.addFunctionTable()
    result.initialize()
    result.gatherSymbols()
    result.register(hash)

  except:
    result.unloadLib(force=true)
    raise getCurrentException()[ref LibraryError]

proc globalExit() =
  for lib in @memLibs:
    lib.unloadLib(force=true)

proc globalInit() =
  gLock.initLock()
  memLibs = newSharedSeq[MemoryModule]()
  rtLibs = newSharedSeq[HMODULE]()

once:
  globalInit()

atexit:
  globalExit()


# exported procs from here

proc checkedLoadLib*(data: DllContent): MemoryModule {.inline, raises: [LibraryError].} =
  ## Loads a DLL from memory. Raise `LibraryError` if the DLL could not be loaded.
  result = loadLib(&data.string, data.string.len)

proc checkedLoadLib*(data: openarray[byte|char]): MemoryModule {.inline, raises: [LibraryError].} =
  ## Loads a DLL from memory. Raise `LibraryError` if the DLL could not be loaded.
  result = loadLib(unsafeaddr data[0], data.len)

proc checkedSymAddr*(lib: MemoryModule, name: string|LPCSTR): pointer {.inline, raises: [LibraryError].} =
  ## Retrieves the address of a procedure from DLL by name.
  ## Raise `LibraryError` if the symbol could not be found.
  result = lib.findSymbol(name)

proc checkedSymAddr*(lib: MemoryModule, ordinal: range[0..65535]): pointer {.inline, raises: [LibraryError].} =
  ## Retrieves the address of a procedure from DLL by ordinal.
  ## Raise `LibraryError` if the ordinal out of range.
  result = lib.findSymbol(ordinal[LPCSTR])

proc loadLib*(data: DllContent): MemoryModule {.inline, raises: [].} =
  ## Loads a DLL from memory. Returns `nil` if the DLL could not be loaded.
  try: result = checkedLoadLib(data)
  except: result = nil

proc loadLib*(data: openarray[byte|char]): MemoryModule {.inline, raises: [].} =
  ## Loads a DLL from memory. Returns `nil` if the DLL could not be loaded.
  try: result = checkedLoadLib(data)
  except: result = nil

proc symAddr*(lib: MemoryModule, name: string|LPCSTR): pointer {.inline, raises: [].} =
  ## Retrieves the address of a procedure from DLL by name.
  ## Returns `nil` if the symbol could not be found.
  try: result = checkedSymAddr(lib, name)
  except: result = nil

proc symAddr*(lib: MemoryModule, ordinal: range[0..65535]): pointer {.inline, raises: [].} =
  ## Retrieves the address of a procedure from DLL by ordinal.
  ## Returns `nil` if the ordinal out of range.
  try: result = checkedSymAddr(lib, ordinal)
  except: result = nil

proc unloadLib*(lib: MemoryModule) {.inline, raises: [].} =
  ## Unloads the DLL.
  lib.unloadLib(force = false)

proc run*(lib: MemoryModule): int {.discardable, raises: [LibraryError].} =
  ## Execute entry point (EXE only). The entry point can only be executed
  ## if the EXE has been loaded to the correct base address or it could
  ## be relocated (i.e. relocation information have not been stripped by
  ## the linker).
  ##
  ## Important: calling this function will not return, i.e. once the loaded
  ## EXE finished running, the process will terminate.
  ##
  ## Raise `LibraryError` if the entry point could not be executed.
  assert lib != nil

  if lib.codeBase == nil or lib.entry == nil:
    raise newException(LibraryError, "No entry point")

  if lib.isDll:
    raise newException(LibraryError, "Cannot run a DLL file")

  if not lib.isRelocated:
    raise newException(LibraryError, "Cannot run without relocation")

  result = lib.entry[ExeEntryProc]()

# for resources

proc findResource*(lib: HMODULE, name: LPCTSTR, typ: LPCTSTR, lang: WORD = 0): HRSRC
    {.raises: [LibraryError].} =
  ## Find the location of a resource with the specified type, name and language.

  proc RtlImageNtHeader(base: HMODULE): PIMAGE_NT_HEADERS {.stdcall, importc, dynlib: "ntdll".}

  proc searchResourceEntry(root: pointer, resources: PIMAGE_RESOURCE_DIRECTORY, key: LPCTSTR): PIMAGE_RESOURCE_DIRECTORY_ENTRY =
    let entries = resources{sizeof IMAGE_RESOURCE_DIRECTORY}[ptr UncheckedArray[IMAGE_RESOURCE_DIRECTORY_ENTRY]]

    if IS_INTRESOURCE(key):
      let
        first = resources.NumberOfNamedEntries.int
        last = first + resources.NumberOfIdEntries.int - 1

      let found = binarySearch(entries.toOpenArray(first, last),
          cast[WORD](key)) do (x: IMAGE_RESOURCE_DIRECTORY_ENTRY, y: WORD) -> int:

        result = system.cmp(x.Name[WORD], y)

      if found >= 0:
        return &entries[found + first]

    else:
      let
        first = 0
        last = resources.NumberOfNamedEntries.int - 1

      let found = binarySearch(entries.toOpenArray(first, last),
          key) do (x: IMAGE_RESOURCE_DIRECTORY_ENTRY, y: LPCTSTR) -> int:

        let
          stru = root{x.NameOffset}[PIMAGE_RESOURCE_DIR_STRING_U]
          length = int32 stru.Length
          lpstr = addr stru.NameString[0]

        result = CompareStringEx(LOCALE_NAME_INVARIANT, LINGUISTIC_IGNORECASE,
          lpstr, length, y, -1, nil, nil, 0) - 2

      if found >= 0:
        return &entries[found + first]

  let
    codeBase = lib
    headers = RtlImageNtHeader(lib)

  if headers == nil:
    raise newException(LibraryError, "Invalid handle")

  let directory = headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
  if directory.Size == 0:
    raise newException(LibraryError, "Resource data not found")

  let
    lang =
      if lang == 0: LANGIDFROMLCID(GetThreadLocale())
      else: lang

    root = codeBase{directory.VirtualAddress}[PIMAGE_RESOURCE_DIRECTORY]

  var
    typeDir, nameDir: PIMAGE_RESOURCE_DIRECTORY
    typeEntry, nameEntry, langEntry: PIMAGE_RESOURCE_DIRECTORY_ENTRY

  typeEntry = searchResourceEntry(root, root, typ)
  if typeEntry == nil:
    raise newException(LibraryError, "Resource type not found")

  typeDir = root{typeEntry[].OffsetToDirectory}[PIMAGE_RESOURCE_DIRECTORY]
  nameEntry = searchResourceEntry(root, typeDir, name)
  if nameEntry == nil:
    raise newException(LibraryError, "Resource name not found")

  nameDir = root{nameEntry[].OffsetToDirectory}[PIMAGE_RESOURCE_DIRECTORY]
  langEntry = searchResourceEntry(root, nameDir, lang[LPCTSTR])
  if langEntry == nil:
    #  requested lang not found, use first available
    if nameDir.NumberOfIdEntries == 0:
      raise newException(LibraryError, "Resource language not found")

    langEntry = nameDir{sizeof(IMAGE_RESOURCE_DIRECTORY)}[PIMAGE_RESOURCE_DIRECTORY_ENTRY]

  return root{langEntry[].OffsetToDirectory}[HRSRC]

proc sizeOfResource*(lib: HMODULE, resource: HRSRC): DWORD =
  ## Get the size of the resource in bytes.
  let entry = resource[PIMAGE_RESOURCE_DATA_ENTRY]
  if entry != nil:
    result = entry.Size

proc loadResource*(lib: HMODULE, resource: HRSRC): HGLOBAL =
  ## Get a pointer to the contents of the resource.
  let entry = resource[PIMAGE_RESOURCE_DATA_ENTRY]
  if entry != nil:
    result = lib{entry[].OffsetToData}[HGLOBAL]

proc loadString*(lib: HMODULE, id: UINT, lang: WORD = 0): string =
  ## Load a string resource.
  let resource = findResource(lib, MAKEINTRESOURCE((id shr 4) + 1), RT_STRING, lang)

  var data = loadResource(lib, resource)[PIMAGE_RESOURCE_DIR_STRING_U]
  for i in 0 ..< (id and 0x0f):
    data = data{int(data.Length + 1) * sizeof(WCHAR)}[PIMAGE_RESOURCE_DIR_STRING_U]

  if data.Length == 0:
    raise newException(LibraryError, "Resource name not found")

  let pucaWchar = cast[ptr UncheckedArray[WCHAR]](&data.NameString[0])
  result = $$toOpenArray(pucaWchar, 0, int data.Length - 1)

proc findResource*(lib: MemoryModule, name: LPCTSTR, typ: LPCTSTR, lang: WORD = 0): HRSRC
    {.inline, raises: [LibraryError].} =
  ## Find the location of a resource with the specified type, name and language.
  if lib == nil:
    raise newException(LibraryError, "Invalid handle")

  result = findResource(lib.codeBase[HMODULE], name, typ, lang)

proc sizeOfResource*(lib: MemoryModule, resource: HRSRC): DWORD
    {.inline, raises: [LibraryError].} =
  ## Get the size of the resource in bytes.
  if lib == nil:
    raise newException(LibraryError, "Invalid handle")

  result = sizeOfResource(lib.codeBase[HMODULE], resource)

proc loadResource*(lib: MemoryModule, resource: HRSRC): HGLOBAL
    {.inline, raises: [LibraryError].} =
  ## Get a pointer to the contents of the resource.
  if lib == nil:
    raise newException(LibraryError, "Invalid handle")

  result = loadResource(lib.codeBase[HMODULE], resource)

proc loadString*(lib: MemoryModule, id: UINT, lang: WORD = 0): string
    {.inline, raises: [LibraryError].} =
  ## Load a string resource.
  if lib == nil:
    raise newException(LibraryError, "Invalid handle")

  result = loadString(lib.codeBase[HMODULE], id, lang)

# for hooks

proc LdrLoadDll(PathToFile: PWCHAR, Flags: PULONG, ModuleFileName: PUNICODE_STRING, ModuleHandle: PHANDLE): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}

proc myLdrLoadDll(PathToFile: PWCHAR, Flags: PULONG, ModuleFileName: PUNICODE_STRING, ModuleHandle: PHANDLE): NTSTATUS {.stdcall, minhook: LdrLoadDll.} =
  withLock(gLock):
    for i in 0 ..< memLibs.len:
      if memLibs[i].name != nil and lstrcmpiW(ModuleFileName[].Buffer, memLibs[i].name) == 0:
        ModuleHandle[] = memLibs[i][HANDLE]
        return STATUS_SUCCESS

  result = LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)

proc myGetProcAddress(hModule: HMODULE, lpProcName: LPCSTR): FARPROC {.stdcall, minhook: GetProcAddress, raises: [].} =
  result = GetProcAddress(hModule, lpProcName)
  if result == nil:
    withLock(gLock):
      for i in 0 ..< memLibs.len:
        if hModule == memLibs[i][HANDLE]:
          return memLibs[i].symAddr(lpProcName)

proc unhook*(lib: MemoryModule) {.raises: [].} =
  ## Removes the hooks.
  assert lib != nil
  if lib.name != nil:
    deallocShared(lib.name)
    lib.name = nil

  withLock(gLock):
    for i in 0 ..< memLibs.len:
      if memLibs[i].name != nil:
        return

    if hookEnabled:
      try:
        queueDisableHook(LdrLoadDll)
        queueDisableHook(GetProcAddress)
        applyQueued()
      except: discard
      hookEnabled = false

proc hook*(lib: MemoryModule, name: string) {.raises: [LibraryError].} =
  ## Hooks the system API (LoadLibrary and GetProcAddress only) with specified name.
  ## Following requests will be redirected to the memory module
  assert lib != nil
  lib.unhook()

  let wstr = string +$name
  lib.name = createShared(char, wstr.len)[LPCWSTR]
  if lib.name == nil:
    raise newException(LibraryError, "Out of memory")

  copyMem(lib.name, &wstr, wstr.len)

  withLock(gLock):
    if not hookEnabled:
      try:
        queueEnableHook(LdrLoadDll)
        queueEnableHook(GetProcAddress)
        applyQueued()
      except: discard
      hookEnabled = true

# for memlib macro

template memlookup(callPtr: ptr pointer, dll: DllContent, sym: LPCSTR, loadLib, symAddr: untyped) =
  var
    hash = toMD5(string dll)
    lib: MemoryModule

  withLock(gLock):
    for i in 0 ..< memLibs.len:
      if memLibs[i].hash == hash:
        lib = memLibs[i]
        break

  if lib == nil:
    lib = loadLib(dll)

  callPtr[] = lib.symAddr(sym)

template rtlookup(callPtr: ptr pointer, name: string, sym: LPCSTR, errorLib, errorSym: untyped) =
  var handle = LoadLibrary(name)
  if handle == 0:
    errorLib

  else:
    withLock(gLock):
      var found = false
      for i in 0 ..< rtLibs.len:
        if rtLibs[i] == handle:
          found = true
          break

      if found:
        FreeLibrary(handle) # decrease reference count only

      else:
        rtLibs.add handle

  callPtr[] = GetProcAddress(handle, sym)
  if callPtr[] == nil:
    errorSym

proc checkedMemlookup*(callPtr: ptr pointer, dll: DllContent, sym: LPCSTR) {.raises: [LibraryError].} =
  ## A helper used by `memlib` macro.
  memlookup(callPtr, dll, sym, checkedLoadLib, checkedSymAddr)

proc memlookup*(callPtr: ptr pointer, dll: DllContent, sym: LPCSTR) {.raises: [].} =
  ## A helper used by `memlib` macro.
  memlookup(callPtr, dll, sym, loadLib, symAddr)

proc checkedLibLookup*(callPtr: ptr pointer, lib: MemoryModule, sym: LPCSTR) {.raises: [LibraryError].} =
  ## A helper used by `memlib` macro.
  callPtr[] = lib.checkedSymAddr(sym)

proc libLookup*(callPtr: ptr pointer, lib: MemoryModule, sym: LPCSTR) {.raises: [].} =
  ## A helper used by `memlib` macro.
  callPtr[] = lib.symAddr(sym)

proc checkedRtlookup*(callPtr: ptr pointer, name: string, sym: LPCSTR) {.raises: [LibraryError].} =
  ## A helper used by `memlib` macro.
  rtlookup(callPtr, name, sym) do:
    raise newException(LibraryError, "Could not load " & name)
  do:
    raise newException(LibraryError, symErrorMessage(sym))

proc rtlookup*(callPtr: ptr pointer, name: string, sym: LPCSTR) {.raises: [].} =
  ## A helper used by `memlib` macro.
  rtlookup(callPtr, name, sym) do:
    return
  do:
    return

proc rewritePragma(def: NimNode, hasRaises: bool): (NimNode, NimNode) =
  var
    sym = def.name.toStrLit
    newPragma = newTree(nnkPragma)
    typPragma = newTree(nnkPragma)
    procty = newTree(nnkProcTy, def.params, typPragma)

  # Procs imported from Dll implies gcsafe and raises: []
  typPragma.add ident("gcsafe")
  newPragma.add ident("gcsafe")

  typPragma.add newColonExpr(ident("raises"), newNimNode(nnkBracket))
  typPragma.add newColonExpr(ident("tags"), newNimNode(nnkBracket))
  if not hasRaises:
    newPragma.add newColonExpr(ident("raises"), newNimNode(nnkBracket))
    newPragma.add newColonExpr(ident("tags"), newNimNode(nnkBracket))

  for node in def.pragma:
    # ignore single importc
    if node.kind == nnkIdent and $node == "importc":
      continue

    # ignore importc: symbol, but copy the symbol
    if node.kind == nnkExprColonExpr and $node[0] == "importc":
      sym = node[1]
      if sym.kind == nnkStrLit:
        sym.strVal = sym.strVal.multiReplace(("$$", "$"), ("$1", $def[0]))
      continue

    # only procDef accept discardable
    if node.kind == nnkIdent and $node == "discardable":
      newPragma.add node
      continue

    newPragma.add node
    typPragma.add node

  def.pragma = newPragma
  return (sym, procty)

proc addParams(def: NimNode) =
  for node in def.params:
    if node.kind == nnkIdentDefs:
      for i in 0 ..< node.len - 2:
        assert def.body[^1].kind == nnkCall
        def.body[^1].add node[i]

proc isVarargs(def: NimNode): bool =
  for i in def.pragma:
    if i.eqIdent("varargs"): return true
  return false

proc compose(dll, def: NimNode, hasRaises: bool): NimNode =
  var
    (sym, procty) = def.rewritePragma(hasRaises)
    memlookup = ident(if `hasRaises`: "checkedmemlookup" else: "memlookup")
    libLookup = ident(if `hasRaises`: "checkedLibLookup" else: "libLookup")
    rtlookup = ident(if `hasRaises`: "checkedrtlookup" else: "rtlookup")
    isVarargs = def.isVarargs()
    name = if isVarargs: ident(def.name.strVal) else: ident("call")

  # We must lookup the symbol on import for proc with varargs.
  # See https://github.com/khchen/memlib/issues/2.

  var code = quote do:
    var
      `name` {.global.}: `procty`
      sym: LPCSTR

    when `sym` is string:
      sym = LPCSTR `sym`
    elif `sym` is SomeInteger:
      sym = `sym`.int[LPCSTR]
    else:
      {.fatal: "importc only allows string or integer".}

    if `name`.isNil:
      {.gcsafe.}:
        when `dll` is DllContent:
          `memlookup`(`name`.addr[ptr pointer], `dll`, sym)

        elif `dll` is MemoryModule:
          `libLookup`(`name`.addr[ptr pointer], `dll`, sym)

        elif `dll` is string: # Load dll at runtime
          `rtlookup`(`name`.addr[ptr pointer], `dll`, sym)

        else:
          {.fatal: "memlib only accepts DllContent, MemoryModule, or string".}

    `name`()

  if isVarargs:
    code.del(code.len - 1) # remove last call
    result = code

  else:
    def.body = code
    def.addParams() # add params to last call
    result = def

macro checkedMemlib*(dll, def: untyped): untyped =
  ## `dynlib` pragma replacement to load DLL from memory or at runtime.
  ## Raise `LibraryError` if error occurred.
  ## See `memlib` for details.
  def.expectKind(nnkProcDef)
  result = compose(dll, def, hasRaises = true)

macro memlib*(dll, def: untyped): untyped =
  ## `dynlib` pragma replacement to load DLL from memory or at runtime.
  ## Accepts a `MemoryModule`, `DllContent`, or `string`. **The program will
  ## crash if error occurred, so only use this for trusted DLL.**
  ## ============  ============================================================
  ## Parameter     Meaning
  ## ============  ============================================================
  ## MemoryModule  Uses the DLL loaded by `loadLib` or `checkedLoadLib`.
  ## DllContent    Loads DLL in binary format that returned by `staticReadDll`.
  ## string        Loads the DLL at runtime by system API.
  ## ============  ============================================================

  runnableExamples:
    const dll = staticReadDll("sqlite3_64.dll")
    let lib = loadLib(dll)
    proc libversion(): cstring {.cdecl, memlib: lib, importc: "sqlite3_libversion".}
    echo libversion()

  runnableExamples:
    const dll = staticReadDll("sqlite3_64.dll")
    proc libversion(): cstring {.cdecl, memlib: dll, importc: "sqlite3_libversion".}
    echo libversion()

  runnableExamples:
    proc libversion(): cstring {.cdecl, memlib: "sqlite3_64.dll", importc: "sqlite3_libversion".}
    echo libversion()

  def.expectKind(nnkProcDef)
  result = compose(dll, def, hasRaises = false)

proc reformat(pragma, n: NimNode): NimNode =
  result = n

  if n.kind == nnkProcDef: # and n[^1].kind == nnkEmpty:
     # a proc def without body, node[4] is pragma
     if n[4].kind == nnkEmpty: n[4] = newNimNode(nnkPragma)
     pragma.copyChildrenTo(n[4])

  elif n.len != 0:
    for i in 0 ..< n.len:
      n[i] = reformat(pragma, n[i])

macro withPragma*(pragma, body: untyped): untyped =
  ## `push` pragma replacement.

  runnableExamples:
    proc test() =
      const dll = staticReadDll("sqlite3_64.dll")
      withPragma { cdecl, memlib: dll, importc: "sqlite3_libversion" }:
        proc libversion(): cstring
      echo libversion()

  result = reformat(pragma, body)

macro buildPragma*(pragma, body: untyped): untyped =
  ## `pragma` pragma replacement.

  runnableExamples:
    proc test() =
      const dll = staticReadDll("sqlite3_64.dll")
      buildPragma { cdecl, memlib: dll, importc: "sqlite3_libversion" }: mylib
      proc libversion(): cstring {.mylib.}
      echo libversion()

  pragma.expectKind({nnkCurly, nnkTableConstr})
  var
    name = body[0]
    pragma = pragma.repr

  result = quote do:
    macro `name`(def: untyped): untyped =
      result = newStmtList(
          newTree(nnkCommand,
            ident("withPragma"),
            parseExpr(`pragma`),
            newStmtList(def)
          ))

proc staticReadDllWithName*(dll: string, hint = true): (string, DllContent) {.compiletime.} =
  ## Compile-time find and read library proc for DLL embedding.
  ## Returns the path and the binary in DllContent format.
  ## Supports `dynlib` name patterns. For example: `libtcl(|8.5|8.4)`.
  proc checkDir(dir, filename: string): string =
    result = normalizedPath(dir / filename)
    if fileExists(result):
      return result

    result = normalizedPath(dir / addFileExt(filename, ".dll"))
    if fileExists(result):
      return result

    return ""

  proc showHint(path: string) =
    echo ansiForegroundColorCode(fgGreen), "Hint: ",
      ansiForegroundColorCode(fgWhite), path,
      ansiForegroundColorCode(fgCyan), " [StaticDllRead]",
      ansiForegroundColorCode(fgWhite)

  proc staticReadDllOne(dll: string, hint = true): (string, DllContent) {.compiletime.} =
    var
      (dir, name, ext) = splitFile(dll)
      filename = name & ext
      dirs: seq[string]

    if dir.len == 0:
      dirs.add getProjectPath()
      dirs.add splitFile(getCurrentCompilerExe())[0]
      for path in getEnv("PATH").split(';'):
        dirs.add path

    else:
      if isAbsolute(dir):
        dirs.add dir

      else:
        dirs.add getProjectPath() / dir

    for dir in dirs:
      let path = checkDir(dir, filename)
      if path != "":
        if hint: showHint(path)
        return (extractFilename(path), DllContent staticRead(path))

  var dest: seq[string]
  libCandidates(dll, dest)

  if dest.len != 1:
    dest.insert(dll, 0)

  for i in dest:
    result = staticReadDllOne(i, hint)
    if result[0].len != 0:
      return

  raise newException(LibraryError, "Cannot locate the DLL file: " & dll)

proc staticReadDll*(dll: string, hint = true): DllContent {.compiletime.} =
  ## Compile-time find and read library proc for DLL embedding.
  ## Returns the binary in DllContent format.
  ## Supports `dynlib` name patterns. For example: `libtcl(|8.5|8.4)`.
  result = staticReadDllWithName(dll, hint)[1]
