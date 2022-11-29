#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

import unittest, memlib
import winim/lean

when defined(cpu64):
  const DllPath = "../dlls/testdll64.dll"
else:
  const DllPath = "../dlls/testdll32.dll"

const DllData = staticReadDll DllPath

suite "Test Suites for Memlib":

  test "Dynlib":
    proc test1(a, b, c: cstring): cstring {.dynlib: DllPath, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.dynlib: DllPath, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.dynlib: DllPath, stdcall, importc: "test_stdcall".}
    proc test_varargs(i: cint): cint {.dynlib: DllPath, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Memlib with string (Loading a DLL at runtime)":
    proc test1(a, b, c: cstring): cstring {.memlib: DllPath, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.memlib: DllPath, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.memlib: DllPath, stdcall, importc: "test_stdcall".}
    proc test4(a, b, c: cstring): cstring {.memlib: DllPath, cdecl, importc: 3.}
    proc test5(a, b, c: cstring): cstring {.memlib: DllPath, fastcall, importc: 4.}
    proc test6(a, b, c: cstring): cstring {.memlib: DllPath, stdcall, importc: 5.}
    proc test_varargs(i: cint): cint {.memlib: DllPath, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test4("a", "b", "c") == "cdecl a b c"
      test5("a", "b", "c") == "fastcall a b c"
      test6("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Memlib with DllContent (Loading a DLL from memory)":
    proc test1(a, b, c: cstring): cstring {.memlib: DllData, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.memlib: DllData, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.memlib: DllData, stdcall, importc: "test_stdcall".}
    proc test4(a, b, c: cstring): cstring {.memlib: DllData, cdecl, importc: 3.}
    proc test5(a, b, c: cstring): cstring {.memlib: DllData, fastcall, importc: 4.}
    proc test6(a, b, c: cstring): cstring {.memlib: DllData, stdcall, importc: 5.}
    proc test_varargs(i: cint): cint {.memlib: DllData, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test4("a", "b", "c") == "cdecl a b c"
      test5("a", "b", "c") == "fastcall a b c"
      test6("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Memlib with preloaded MemoryModule":
    var lib = checkedLoadLib(DllData)
    proc test1(a, b, c: cstring): cstring {.memlib: lib, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.memlib: lib, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.memlib: lib, stdcall, importc: "test_stdcall".}
    proc test4(a, b, c: cstring): cstring {.memlib: lib, cdecl, importc: 3.}
    proc test5(a, b, c: cstring): cstring {.memlib: lib, fastcall, importc: 4.}
    proc test6(a, b, c: cstring): cstring {.memlib: lib, stdcall, importc: 5.}
    proc test_varargs(i: cint): cint {.memlib: lib, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test4("a", "b", "c") == "cdecl a b c"
      test5("a", "b", "c") == "fastcall a b c"
      test6("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Hook the Windows API to use preloaded MemoryModule":
    const Name = "this_dll_not_exist"
    var lib = checkedLoadLib(DllData)
    lib.hook(Name)

    check(LoadLibrary(Name) == cast[HMODULE](lib))
    check(GetProcAddress(LoadLibrary(Name), "test_cdecl") == lib.symAddr("test_cdecl"))
    check(GetProcAddress(LoadLibrary(Name), "test_fastcall") == lib.symAddr("test_fastcall"))
    check(GetProcAddress(LoadLibrary(Name), "test_stdcall") == lib.symAddr("test_stdcall"))
    check(GetProcAddress(LoadLibrary(Name), cast[LPCSTR](3)) == lib.symAddr(3))
    check(GetProcAddress(LoadLibrary(Name), cast[LPCSTR](4)) == lib.symAddr(4))
    check(GetProcAddress(LoadLibrary(Name), cast[LPCSTR](5)) == lib.symAddr(5))
    check(GetProcAddress(LoadLibrary(Name), "test_varargs") == lib.symAddr("test_varargs"))

    proc test1(a, b, c: cstring): cstring {.memlib: Name, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.memlib: Name, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.memlib: Name, stdcall, importc: "test_stdcall".}
    proc test4(a, b, c: cstring): cstring {.memlib: Name, cdecl, importc: 3.}
    proc test5(a, b, c: cstring): cstring {.memlib: Name, fastcall, importc: 4.}
    proc test6(a, b, c: cstring): cstring {.memlib: Name, stdcall, importc: 5.}
    proc test_varargs(i: cint): cint {.memlib: Name, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test4("a", "b", "c") == "cdecl a b c"
      test5("a", "b", "c") == "fastcall a b c"
      test6("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Read and Load a DLL at runtime":
    var lib = checkedLoadLib(DllContent readfile(DllPath))
    proc test1(a, b, c: cstring): cstring {.memlib: lib, cdecl, importc: "test_cdecl".}
    proc test2(a, b, c: cstring): cstring {.memlib: lib, fastcall, importc: "test_fastcall".}
    proc test3(a, b, c: cstring): cstring {.memlib: lib, stdcall, importc: "test_stdcall".}
    proc test4(a, b, c: cstring): cstring {.memlib: lib, cdecl, importc: 3.}
    proc test5(a, b, c: cstring): cstring {.memlib: lib, fastcall, importc: 4.}
    proc test6(a, b, c: cstring): cstring {.memlib: lib, stdcall, importc: 5.}
    proc test_varargs(i: cint): cint {.memlib: lib, cdecl, varargs, importc.}

    check:
      test1("a", "b", "c") == "cdecl a b c"
      test2("a", "b", "c") == "fastcall a b c"
      test3("a", "b", "c") == "stdcall a b c"
      test4("a", "b", "c") == "cdecl a b c"
      test5("a", "b", "c") == "fastcall a b c"
      test6("a", "b", "c") == "stdcall a b c"
      test_varargs(1, 2, 3, 4, 0) == 10

  test "Memlib error handling":
    const NotDll = staticReadDll(currentSourcePath())
    var
      invalidLib = loadLib(NotDll)
      vaildLib = loadLib(DllData)

    check:
      vaildLib != nil
      vaildLib.symAddr("test_cdecl") != nil

      invalidLib == nil
      invalidLib.symAddr("test_cdecl") == nil
      vaildLib.symAddr("test_cdecl_not_exist") == nil

    expect LibraryError:
      discard checkedLoadLib(NotDll)

    expect LibraryError:
      discard invalidLib.checkedSymAddr("test_cdecl")

    expect LibraryError:
      discard vaildLib.checkedSymAddr("test_cdecl_not_exist")

    expect LibraryError:
      proc test1(a, b, c: cstring): cstring {.checkedMemlib: invalidLib, cdecl, importc: "test_cdecl".}
      discard test1("a", "b", "c")

    expect LibraryError:
      proc test1(a, b, c: cstring): cstring {.checkedMemlib: vaildLib, cdecl, importc: "test_cdecl_not_exist".}
      discard test1("a", "b", "c")

    expect LibraryError:
      proc test1(a, b, c: cstring): cstring {.checkedMemlib: vaildLib, cdecl, importc: 999.}
      discard test1("a", "b", "c")

  test "WithPragma macro (Push pragma replacement)":
    withPragma { dynlib: DllPath }:
      block:
        proc test1(a, b, c: cstring): cstring {.cdecl, importc: "test_cdecl".}
        proc test2(a, b, c: cstring): cstring {.fastcall, importc: "test_fastcall".}
        proc test3(a, b, c: cstring): cstring {.stdcall, importc: "test_stdcall".}
        proc test_varargs(i: cint): cint {.cdecl, varargs, importc.}

        check:
          test1("a", "b", "c") == "cdecl a b c"
          test2("a", "b", "c") == "fastcall a b c"
          test3("a", "b", "c") == "stdcall a b c"
          test_varargs(1, 2, 3, 4, 0) == 10

    withPragma { memlib: DllPath }:
      block:
        proc test1(a, b, c: cstring): cstring {.cdecl, importc: "test_cdecl".}
        proc test2(a, b, c: cstring): cstring {.fastcall, importc: "test_fastcall".}
        proc test3(a, b, c: cstring): cstring {.stdcall, importc: "test_stdcall".}
        proc test_varargs(i: cint): cint {.cdecl, varargs, importc.}

        check:
          test1("a", "b", "c") == "cdecl a b c"
          test2("a", "b", "c") == "fastcall a b c"
          test3("a", "b", "c") == "stdcall a b c"
          test_varargs(1, 2, 3, 4, 0) == 10

    withPragma { memlib: DllData }:
      block:
        proc test1(a, b, c: cstring): cstring {.cdecl, importc: "test_cdecl".}
        proc test2(a, b, c: cstring): cstring {.fastcall, importc: "test_fastcall".}
        proc test3(a, b, c: cstring): cstring {.stdcall, importc: "test_stdcall".}
        proc test_varargs(i: cint): cint {.cdecl, varargs, importc.}

        check:
          test1("a", "b", "c") == "cdecl a b c"
          test2("a", "b", "c") == "fastcall a b c"
          test3("a", "b", "c") == "stdcall a b c"
          test_varargs(1, 2, 3, 4, 0) == 10

  test "BuildPragma macro (Pragma pragma replacement)":
    block:
      buildPragma { dynlib: DllPath }: mylib
      proc test1(a, b, c: cstring): cstring {.mylib, cdecl, importc: "test_cdecl".}
      proc test2(a, b, c: cstring): cstring {.mylib, fastcall, importc: "test_fastcall".}
      proc test3(a, b, c: cstring): cstring {.mylib, stdcall, importc: "test_stdcall".}
      proc test_varargs(i: cint): cint {.mylib, cdecl, varargs, importc.}

      check:
        test1("a", "b", "c") == "cdecl a b c"
        test2("a", "b", "c") == "fastcall a b c"
        test3("a", "b", "c") == "stdcall a b c"
        test_varargs(1, 2, 3, 4, 0) == 10

    block:
      buildPragma { memlib: DllPath }: mylib
      proc test1(a, b, c: cstring): cstring {.mylib, cdecl, importc: "test_cdecl".}
      proc test2(a, b, c: cstring): cstring {.mylib, fastcall, importc: "test_fastcall".}
      proc test3(a, b, c: cstring): cstring {.mylib, stdcall, importc: "test_stdcall".}
      proc test_varargs(i: cint): cint {.mylib, cdecl, varargs, importc.}

      check:
        test1("a", "b", "c") == "cdecl a b c"
        test2("a", "b", "c") == "fastcall a b c"
        test3("a", "b", "c") == "stdcall a b c"
        test_varargs(1, 2, 3, 4, 0) == 10

    block:
      buildPragma { memlib: DllData }: mylib
      proc test1(a, b, c: cstring): cstring {.mylib, cdecl, importc: "test_cdecl".}
      proc test2(a, b, c: cstring): cstring {.mylib, fastcall, importc: "test_fastcall".}
      proc test3(a, b, c: cstring): cstring {.mylib, stdcall, importc: "test_stdcall".}
      proc test_varargs(i: cint): cint {.mylib, cdecl, varargs, importc.}

      check:
        test1("a", "b", "c") == "cdecl a b c"
        test2("a", "b", "c") == "fastcall a b c"
        test3("a", "b", "c") == "stdcall a b c"
        test_varargs(1, 2, 3, 4, 0) == 10
