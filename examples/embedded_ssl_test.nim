#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

# This example run "ssl_test.exe" with embedded OpenSSL DLLs.
# Using legacy dlls because there are some unresolved issues to load
# DLLs in last version.

# Nim SSL library (openssl.nim) use dynlib pragma to load the OpenSSL DLLs.
# All user code is executed after that, so there is no way to change the
# behavior of dynlib by user code.

# Here provide another way: embedding both dlls and the target exe file.
# Compile this file to embedded_ssl_test.exe and use embedded_ssl_test_run.cmd
# to test it to ensure the DLLs is noted loaded from PATH.

import memlib

const
  ExeFile = staticReadDll("ssl_test.exe")

when defined(cpu64):
  const
    (DLLSSLName, DLLSSLData) = staticReadDllWithName "ssl/ssleay64.dll"
    (DLLUtilName, DLLUtilData) = staticReadDllWithName "ssl/libeay64.dll"
else:
  const
    (DLLSSLName, DLLSSLData) = staticReadDllWithName "ssl/ssleay32.dll"
    (DLLUtilName, DLLUtilData) = staticReadDllWithName "ssl/libeay32.dll"

proc load() =
  var utilMod = checkedLoadLib(DLLUtilData)
  utilMod.hook(DLLUtilName)
  echo "[", DLLUtilName, " hooked]"

  var sslMod = checkedLoadLib(DLLSSLData)
  sslMod.hook(DLLSSLName)
  echo "[", DLLSSLName, " hooked]"

load()
loadLib(ExeFile).run()
