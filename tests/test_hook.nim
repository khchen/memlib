#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import winim/lean
import memlib, terminal

when defined(cpu64):
  const
    DllPath = "../dlls/require_sqlite64.dll"
    SqliteDllName = "sqlite3_64"

else:
  const
    DllPath = "../dlls/require_sqlite32.dll"
    SqliteDllName = "sqlite3_32"

const
  DllData = staticReadDll DllPath
  SqliteData = staticReadDll SqliteDllName

SetEnvironmentVariable("path", nil)

echo "Hook the Windows API [Y/N]?"
while true:
  case getch()
  of 'y', 'Y':
    checkedLoadLib(SqliteData).hook(SqliteDllName)
    break
  of 'n', 'N':
    break
  else: discard

echo "Try to load \"require_sqlite32.dll\" ..."
discard checkedLoadLib(DllData)
