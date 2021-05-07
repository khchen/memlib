#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import memlib, dynlib, winim/lean

# Advanced Usage

# Windows DLL can index a function by ordinal. This is aslo supported by memlib.
block:
  type
    libversionProc = proc(): cstring {.cdecl.}

  when defined(cpu64):
    const
      SqliteName = "sqlite3_64.dll"
      SqliteDll = staticReadDll(SqliteName)
      Ordinal = 0x79
  else:
    const
      SqliteName = "sqlite3_32.dll"
      SqliteDll = staticReadDll(SqliteName)
      Ordinal = 0x78

  let
    lib = loadlib(SqliteDll)
    libversion1 = cast[libversionProc](lib.symAddr(Ordinal))

  echo libversion1(), " (loadlib/symAddr in memlib module + Ordinal)"

  proc libversion2(): cstring {.cdecl, memlib: SqliteDll, importc: Ordinal.}
  echo libversion2(), " (memlib macro + embeded DLL + Ordinal)"

  proc libversion3(): cstring {.cdecl, memlib: SqliteName, importc: Ordinal.}
  echo libversion3(), " (memlib macro + runtime DLL + Ordinal)"

  # proc libversion4(): cstring {.cdecl, dynlib: SqliteName, importc: Ordinal.}
  # Error: string literal expected

# Sometimes we use push and pop pragmas for dynlib.
block:
  when defined(cpu64):
    const SqliteDll = "sqlite3_64.dll"
  else:
    const SqliteDll = "sqlite3_32.dll"

  {.push cdecl, dynlib: SqliteDll, importc: "sqlite3_$1".}
  proc libversion(): cstring
  {.pop.}

  echo libversion(), " (push pragma + dynlib pragma)"

# For memlib, you can use `withPragma` macro instead.
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  withPragma { cdecl, memlib: SqliteDll, importc: "sqlite3_$1" }:
    proc libversion(): cstring

  echo libversion(), " (withPragma macro + memlib macro as pragma)"

# Pragma pragma can also be used with dynlib.
block:
  when defined(cpu64):
    const SqliteDll = "sqlite3_64.dll"
  else:
    const SqliteDll = "sqlite3_32.dll"

  {.pragma: mylib1, cdecl, dynlib: SqliteDll, importc: "sqlite3_$1".}
  proc libversion(): cstring {.mylib1.}

  echo libversion(), " (pragma pragma + dynlib pragma)"

# For memlib, you can use `BuildPragma` macro instead.
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  buildPragma { cdecl, memlib: SqliteDll, importc: "sqlite3_$1" }: mylib2
  proc libversion(): cstring {.mylib2.}

  echo libversion(), " (buildPragma macro + memlib macro as pragma)"

# Memlib also privodes the ability to hook the Windows API. This means, you can
# let traditional LoadLibrary/GetProcAddress API to work with an embeded DLL.
# This is the solution if you want embed a chain of DLL (A needs B, B needs C, etc).
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  let lib = loadlib(SqliteDll)
  lib.hook("arbitrary_name")

  type
    libversionProc = proc(): cstring {.cdecl.}

  let
    hModule = LoadLibrary("arbitrary_name")
    libversion = cast[libversionProc](GetProcAddress(hModule ,"sqlite3_libversion"))

  echo libversion(), " (LoadLibrary/GetProcAddress + hooked name)"

# Try to use bulit-in dynlib module, and of course it calls the hooked Windows API
block:
  type
    libversionProc = proc(): cstring {.cdecl.}

  let
    lib = loadLib("arbitrary_name")
    libversion = cast[libversionProc](lib.symAddr("sqlite3_libversion"))

  echo libversion(), " (bulit-in dynlib module + hooked name)"

# Memlib also provides drop-in replacements of following system API: FindResource,
# SizeofResource, LoadResource, LoadString.
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  let
    lib = loadlib(SqliteDll)
    resc = findResource(lib, MAKEINTRESOURCE(1), RT_VERSION)
    adr = cast[LPVOID](loadResource(lib, resc))

  var
    buffer: LPVOID
    size: UINT

  if VerQueryValue(adr, r"\StringFileInfo\040904b0\FileVersion", &buffer, &size):
    echo $cast[LPCTSTR](buffer), " (find resource in MemoryModule)"
