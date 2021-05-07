#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import winim/lean, memlib
import strformat except `&`

proc NimMain() {.cdecl, importc.}

withPragma { exportc, dynlib }:

  var buffer: string

  proc test_cdecl*(a, b, c: cstring): cstring {.cdecl.} =
    buffer = fmt"cdecl {a} {b} {c}"
    return cstring buffer

  proc test_stdcall*(a, b, c: cstring): cstring {.stdcall.} =
    buffer = fmt"stdcall {a} {b} {c}"
    return cstring buffer

  proc test_fastcall*(a, b, c: cstring): cstring {.fastcall.} =
    buffer = fmt"fastcall {a} {b} {c}"
    return cstring buffer

  proc DllMain*(hinst: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL {.stdcall.} =
    if reason == DLL_PROCESS_ATTACH: NimMain()
    return TRUE
