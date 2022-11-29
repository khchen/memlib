#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

import memlib/rtlib

type IStream = object

proc SHCreateMemStream(pInit: pointer, cbInit: cint): ptr IStream
  {.rtlib: "shlwapi", stdcall, importc: 12.}

var str = "abcde"
let pStream = SHCreateMemStream(addr str[0], cint str.len)
assert pStream != nil

proc printf(formatstr: cstring) {.rtlib: "msvcrt", importc: "printf", varargs.}

printf("This works %s", "as expected")
