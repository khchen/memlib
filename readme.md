# Memlib
This module is designed to be a drop-in replacement for `dynlib pragma` and `dynlib module` in Windows. The main part of this module is a pure nim implementation of the famous MemoryModule library. [MemoryModule](https://github.com/fancycode/MemoryModule) is a C library that can load a DLL completely from memory without storing on the disk first. So that the we can embed all DLLs into the main EXE file.

## Features
* Nim implementation of MemoryModule with C++ exceptions and SEH support.
* Dynlib module replacement to load DLL from memory.
* Dynlib pragma replacement to load DLL at runtime.
* Compile-time DLL finder for easy embedding.
* Get address of DLL functions by name or by ordinal.
* Hook the system API (LoadLibrary and GetProcAddress) to use a memory module.

## Examples
```nim
import memlib

# Embed DLL and load it from memory.
block:
  const dll = staticReadDll("sqlite3_64.dll")
  proc libversion(): cstring {.cdecl, memlib: dll, importc: "sqlite3_libversion".}
  echo libversion()

# Load DLL at runtime.
block:
  proc libversion(): cstring {.cdecl, memlib: "sqlite3_64.dll", importc: "sqlite3_libversion".}
  echo libversion()
```

Please also check the examples directory. There are some codes to demonstrate how to modify nim/lib/wrappers so that these DLLs (sqlite and ssl, etc.) can be embedded.

## Rtlib
I found the ability to load DLL by memlib at runtime is very handy. So I add a submodule called `rtlib` that only do this job. This is just a subset of memlib, but using rtlib instead of memlib will reduce the output .exe size.

For example, the document of  [SHCreateMemStream](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-shcreatememstream) says: "*Prior to Windows Vista, this function was not included in the public Shlwapi.h file, nor was it exported by name from Shlwapi.dll. To use it on earlier systems, you must call it directly from the Shlwapi.dll file as ordinal 12.*" We can use rtlib to call this API in really easy way.

```nim
import memlib/rtlib
proc SHCreateMemStream(pInit: pointer, cbInit: cint): ptr IStream
  {.rtlib: "shlwapi", stdcall, importc: 12.}

var str = "abcde"
let pStream = SHCreateMemStream(addr str[0], cint str.len)
assert pStream != nil
```

## Docs
* https://khchen.github.io/memlib

## License
Read license.txt for more details.

Copyright (c) 2021-2022 Kai-Hung Chen, Ward. All rights reserved.
