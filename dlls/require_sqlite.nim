#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

import winim/lean, memlib
import strformat except `&`

when defined(cpu64):
  const SqliteDllName = "sqlite3_64"
else:
  const SqliteDllName = "sqlite3_32"

proc NimMain() {.cdecl, importc.}

withPragma { dynlib: SqliteDllName, cdecl, importc }:
  proc sqlite3_libversion(): cstring

withPragma { exportc, dynlib, stdcall }:
  proc DllMain*(hinst: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL =
    if reason == DLL_PROCESS_ATTACH:
      NimMain()
      echo fmt"SQLITE3 v{$sqlite3_libversion()} loaded"
    return TRUE
