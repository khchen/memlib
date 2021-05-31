# Package

version       = "1.0.1"
author        = "Ward"
description   = "Memlib - Load Windows DLL from memory"
license       = "MIT"
skipDirs      = @["tests", "examples", "docs"]

# Dependencies

requires "nim >= 1.2.0", "winim >= 3.6.0, minhook >= 1.0.0"

task dll, "Build Dlls":
  withDir "dlls":
    exec "nim c -d:danger --opt:size --nomain --app:lib --cpu:amd64 -o:testdll64.dll testdll.nim"
    exec "nim c -d:danger --opt:size --nomain --app:lib --cpu:i386 --passL:-static-libgcc --passL:-Wl,--kill-at -o:testdll32.dll testdll.nim"
    exec "nim c -d:danger --opt:size --nomain --app:lib --cpu:amd64 -o:require_sqlite64.dll require_sqlite.nim"
    exec "nim c -d:danger --opt:size --nomain --app:lib --cpu:i386 --passL:-static-libgcc --passL:-Wl,--kill-at -o:require_sqlite32.dll require_sqlite.nim"
    exec "nim cpp -d:danger --opt:size --nomain --app:lib --cpu:amd64 --exceptions:cpp --passL:-static-libgcc --passL:-static-libstdc++ -o:exception64.dll exception.nim"
    exec "nim cpp -d:danger --opt:size --nomain --app:lib --cpu:i386 --exceptions:cpp --passL:-static-libgcc --passL:-static-libstdc++ -o:exception32.dll exception.nim"

task example, "Build Examples":
  withDir "examples":
    exec "nim c usage1.nim"
    exec "nim c usage2.nim"
    exec "nim c embedded_sqlite.nim"
    exec "nim c -d:ssl -d:nimDisableCertificateValidation embedded_ssl.nim"

task test, "Run Tests":
  withDir "tests":
    exec "nim r test_basic"
    exec "nim r test_exception_dll"
    exec "nim r test_hook"
