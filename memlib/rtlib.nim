#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import macros, locks, strutils
import winim/lean
import private/sharedseq

var
  rtLibs: SharedSeq[HMODULE]
  gLock: Lock

proc globalInit() =
  gLock.initLock()
  rtLibs = newSharedSeq[HMODULE]()

once:
  globalInit()

proc `[]`[T](x: T, U: typedesc): U =
  ## syntax sugar for cast
  cast[U](x)

proc `{}`[T](x: T, U: typedesc): U =
  ## syntax sugar for zero extends cast
  when sizeof(x) == 1: x[uint8][U]
  elif sizeof(x) == 2: x[uint16][U]
  elif sizeof(x) == 4: x[uint32][U]
  elif sizeof(x) == 8: x[uint64][U]
  else: {.fatal.}

proc symErrorMessage(sym: LPCSTR): string {.raises: [].} =
  let msg = if HIWORD(sym{uint}) == 0: "ordinal " & $(sym{uint}) else: "symbol " & $sym
  result = "Could not find " & msg

template rtlibLookup(callPtr: ptr pointer, name: string, sym: LPCSTR, errorLib, errorSym: untyped) =
  var handle = LoadLibrary(name)
  if handle == 0:
    errorLib

  else:
    withLock(gLock):
      var found = false
      for i in 0 ..< rtLibs.len:
        if rtLibs[i] == handle:
          found = true
          break

      if found:
        FreeLibrary(handle) # decrease reference count only

      else:
        rtLibs.add handle

  callPtr[] = GetProcAddress(handle, sym)
  if callPtr[] == nil:
    errorSym

proc checkedRtlibLookup*(callPtr: ptr pointer, name: string, sym: LPCSTR) {.raises: [LibraryError].} =
  ## A helper used by `rtlib` macro.
  rtlibLookup(callPtr, name, sym) do:
    raise newException(LibraryError, "Could not load " & name)
  do:
    raise newException(LibraryError, symErrorMessage(sym))

proc rtlibLookup*(callPtr: ptr pointer, name: string, sym: LPCSTR) {.raises: [].} =
  ## A helper used by `rtlib` macro.
  rtlibLookup(callPtr, name, sym) do:
    return
  do:
    return

proc rewritePragma(def: NimNode, hasRaises: bool): (NimNode, NimNode) =
  var
    sym = def.name.toStrLit
    newPragma = newTree(nnkPragma)
    typPragma = newTree(nnkPragma)
    procty = newTree(nnkProcTy, def.params, typPragma)

  # Procs imported from Dll implies gcsafe and raises: []
  typPragma.add ident("gcsafe")
  newPragma.add ident("gcsafe")

  typPragma.add newColonExpr(ident("raises"), newNimNode(nnkBracket))
  typPragma.add newColonExpr(ident("tags"), newNimNode(nnkBracket))
  if not hasRaises:
    newPragma.add newColonExpr(ident("raises"), newNimNode(nnkBracket))
    newPragma.add newColonExpr(ident("tags"), newNimNode(nnkBracket))

  for node in def.pragma:
    # ignore single importc
    if node.kind == nnkIdent and $node == "importc":
      continue

    # ignore importc: symbol, but copy the symbol
    if node.kind == nnkExprColonExpr and $node[0] == "importc":
      sym = node[1]
      if sym.kind == nnkStrLit:
        sym.strVal = sym.strVal.multiReplace(("$$", "$"), ("$1", $def[0]))
      continue

    # only procDef accept discardable
    if node.kind == nnkIdent and $node == "discardable":
      newPragma.add node
      continue

    newPragma.add node
    typPragma.add node

  def.pragma = newPragma
  return (sym, procty)

proc addParams(def: NimNode) =
  for node in def.params:
    if node.kind == nnkIdentDefs:
      for i in 0 ..< node.len - 2:
        assert def.body[^1].kind == nnkCall
        def.body[^1].add node[i]

proc compose(dll, def: NimNode, hasRaises: bool): NimNode =
  var
    (sym, procty) = def.rewritePragma(hasRaises)
    rtLookup = ident(if `hasRaises`: "checkedRtlibLookup" else: "rtlibLookup")

  def.body = quote do:
    var
      call {.global.}: `procty`
      sym: LPCSTR

    when `sym` is string:
      sym = cstring `sym`
    elif `sym` is SomeInteger:
      sym = `sym`.int[LPCSTR]
    else:
      {.fatal: "importc only allows string or integer".}

    if call.isNil:
      {.gcsafe.}:
        when `dll` is string: # Load dll at runtime
          `rtLookup`(call.addr[ptr pointer], `dll`, sym)

        else:
          {.fatal: "memlib only accepts string".}

    call()

  def.addParams()
  result = def

macro checkedRtlib*(dll, def: untyped): untyped =
  ## `dynlib` pragma replacement to load DLL at runtime.
  ## Raise `LibraryError` if error occurred.
  ## See `memlib` for details.
  def.expectKind(nnkProcDef)
  result = compose(dll, def, hasRaises = true)

macro rtlib*(dll, def: untyped): untyped =
  ## `dynlib` pragma replacement to load DLL at runtime.
  ## Accepts a `string` only.
  ## ============  ============================================================
  ## Parameter     Meaning
  ## ============  ============================================================
  ## string        Loads the DLL at runtime by system API.
  ## ============  ============================================================

  runnableExamples:
    proc libversion(): cstring {.cdecl, rtlib: "sqlite3_64.dll", importc: "sqlite3_libversion".}
    echo libversion()

  def.expectKind(nnkProcDef)
  result = compose(dll, def, hasRaises = false)
