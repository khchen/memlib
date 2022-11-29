#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

import memlib

when defined(cpu64):
  const DllPath = "../dlls/exception64.dll"
else:
  const DllPath = "../dlls/exception32.dll"

const DllData = staticReadDll DllPath

discard checkedLoadLib(DllData)
