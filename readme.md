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

## Docs
* https://khchen.github.io/memlib

## License
Read license.txt for more details.

Copyright (c) 2021 Kai-Hung Chen, Ward. All rights reserved.
