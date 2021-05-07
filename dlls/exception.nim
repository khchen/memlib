#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import winim/lean

proc NimMain() {.cdecl, importc.}

proc test() =
  try:
    echo "try to raise an exception..."
    raise newException(Exception, "")
  except:
    echo "exception catched"
  finally:
    echo "finally executed"

proc DllMain*(hinst: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  if reason == DLL_PROCESS_ATTACH:
    NimMain()
    test()
  return TRUE
