#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import memlib, dynlib

# Basic Usage

# Try to use built-in dynlib moudle at first (aka. loading DLL at runtime).
block:
  type
    libversionProc = proc(): cstring {.cdecl.}

  when defined(cpu64):
    const SqliteDll = "sqlite3_64.dll"
  else:
    const SqliteDll = "sqlite3_32.dll"

  let
    lib = loadLib(SqliteDll)
    libversion = cast[libversionProc](lib.symAddr("sqlite3_libversion"))

  echo libversion(), " (loadlib/symAddr in bulit-in dynlib module)"

# Memlib can do the same thing as dynlib, but embed the DLL into the output EXE.
block:
  type
    libversionProc = proc(): cstring {.cdecl.}

  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  assert(SqliteDll.type is DllContent)

  let
    lib = loadlib(SqliteDll)
    libversion = cast[libversionProc](lib.symAddr("sqlite3_libversion"))

  echo libversion(), " (loadlib/symAddr in memlib module)"

# A checked version procs will raise exceptions on fail. (otherwise, you may
# enconter "Illegal storage access" message.)
block:
  type
    libversionProc = proc(): cstring {.cdecl.}

  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  try:
    let
      lib = checkedLoadlib(SqliteDll)
      libversion = cast[libversionProc](lib.checkedSymAddr("func_not_exists"))

    echo libversion(), " (checkedLoadlib/checkedSymAddr in memlib module)"

  except LibraryError:
    echo "error (checkedLoadlib/checkedSymAddr in memlib module)"

# Here demonstrate another way to load DLL by built-in `dynlib` pragma.
block:
  when defined(cpu64):
    const SqliteDll = "sqlite3_64.dll"
  else:
    const SqliteDll = "sqlite3_32.dll"

  proc libversion(): cstring {.cdecl, dynlib: SqliteDll, importc: "sqlite3_libversion".}
  echo libversion(), " (dynlib pragma)"

# Again, Memlib can do it but embedding the DLL, via `memlib` macro.
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  proc libversion(): cstring {.cdecl, memlib: SqliteDll, importc: "sqlite3_libversion".}
  echo libversion(), " (memlib macro as pragma + DllContent)"

# The memlib macro also accepts a preloaded library handle.
block:
  when defined(cpu64):
    const SqliteDll = staticReadDll("sqlite3_64.dll")
  else:
    const SqliteDll = staticReadDll("sqlite3_32.dll")

  let lib = loadlib(SqliteDll)
  proc libversion(): cstring {.cdecl, memlib: lib, importc: "sqlite3_libversion".}
  echo libversion(), " (memlib macro as pragma + MemoryModule)"

# Maybe you already have noticed, `staticReadDll` does a lot of magic to find a
# DLL and load it at compile-time. The returned value is in DllContent (distinct
# string) format. Of course you can prepare your own DLL binary data by yourself.
# For example, read from file.
block:
  when defined(cpu64):
    const SqlitePath = r"c:\nim\bin\sqlite3_64.dll"
  else:
    const SqlitePath = r"c:\nim\bin\sqlite3_32.dll"

  try:
    let
      data = readfile(SqlitePath) # must provide the full path
      lib = checkedLoadLib(cast[seq[byte]](data)) # or checkedLoadLib(DllContent data)

    proc libversion(): cstring {.cdecl, memlib: lib, importc: "sqlite3_libversion".}
    echo libversion(), " (memlib macro as pragma + MemoryModule)"

  except:
    echo "error (memlib macro as pragma + MemoryModule)"

# If you provide a string to `memlib` macro. It works, too. However, the DLL
# will NOT be embeded. This is just a EASIER way to load DLL at runtime (compare
# to dynlib module).
block:
  when defined(cpu64):
    const SqliteDll = "sqlite3_64.dll"
  else:
    const SqliteDll = "sqlite3_32.dll"

  # assert(SqliteDll.type is string)
  proc libversion(): cstring {.cdecl, memlib: SqliteDll, importc: "sqlite3_libversion".}
  echo libversion(), " (memlib macro as pragma + const string)"

# What's different to `dynlib` pragma? Don't forget it load DLL at runtime.
# So you can use not only const string but also runtime string .
block:
  when defined(cpu64):
    let SqliteDll = "sqlite3_64.dll"
  else:
    let SqliteDll = "sqlite3_32.dll"

  proc libversion(): cstring {.cdecl, memlib: SqliteDll, importc: "sqlite3_libversion".}
  echo libversion(), " (memlib macro as pragma + runtime string)"

# If the DLL is not exists, you can catch an exception instead of quitting (needs
# checkedMemlib macro).
block:
  try:
    proc libversion(): cstring {.cdecl, checkedMemlib: "DllNotExists", importc: "sqlite3_libversion".}
    echo libversion(), " (checkedMemlib macro as pragma)"

  except LibraryError:
    echo "error (checkedMemlib macro as pragma)"
