#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                  (c) Copyright 2021 Ward
#
#====================================================================

import locks, algorithm
export algorithm

when not declared(reallocShared0):
  import locks
  var heapLock: Lock
  heapLock.initLock()

  proc reallocShared0(p: pointer, oldSize, newSize: Natural): pointer =
    acquire(heapLock)
    result = reallocShared(p, newSize)
    if newSize > oldSize:
      zeroMem(cast[pointer](cast[uint](result) + uint(oldSize)), newSize - oldSize)
    release(heapLock)

type
  SharedSeqObj[T] = object
    buffer: ptr UncheckedArray[T]
    lock: Lock
    size: int
    cap: int

  SharedSeq*[T] = ptr SharedSeqObj[T]

proc resize(old: int): int {.inline.} =
  if old <= 0: result = 4
  elif old < 65536: result = old * 2
  else: result = old * 3 div 2 # for large arrays * 3/2 is better

proc ok*[T](s: SharedSeq[T]): bool {.inline.} =
  result = s != nil and s.buffer != nil

template withLock[T](s: SharedSeq[T], body: untyped) =
  assert s.ok
  acquire(s.lock)
  try:
    body
  finally:
    release(s.lock)

proc newSharedSeq*[T](size: Natural = 0): SharedSeq[T] =
  result = createShared(SharedSeqObj[T])

  let cap = resize(size)
  result.buffer = cast[ptr UncheckedArray[T]](createShared(T, cap))
  assert result.ok

  result.lock.initLock()
  result.size = size
  result.cap = cap

proc newSharedSeqOfCap*[T](cap: Natural): SharedSeq[T] =
  result.buffer = cast[ptr UncheckedArray[T]](createShared(T, cap))
  assert result.ok

  result.lock.initLock()
  result.size = 0
  result.cap = cap

proc newSharedSeq*[T](data: openarray[T]): SharedSeq[T] =
  result = newSharedSeq[T](data.len)
  for i in 0 ..< data.len:
    result.buffer[i] = data[i]

proc dealloc*[T](s: SharedSeq[T]) =
  if s != nil:
    if s.buffer != nil:
      deallocShared(s.buffer)
    deallocShared(s)

proc ensure[T](s: SharedSeq[T], cap: int) =
  if s.cap < cap:
    let newCap = max(resize(s.cap), cap)
    s.buffer = cast[ptr UncheckedArray[T]](reallocShared0(s.buffer, sizeof(T) * s.cap, sizeof(T) * newCap))
    s.cap = newCap
    assert s.ok

proc setLen*[T](s: SharedSeq[T], size: int) =
  withLock(s):
    s.ensure(size)
    s.size = size

proc add*[T](s: SharedSeq[T], data: T) =
  withLock(s):
    s.ensure(s.size + 1)
    s.buffer[s.size] = data
    s.size.inc

proc add*[T](s: SharedSeq[T], data: openarray[T]) =
  withLock(s):
    s.ensure(s.size + data.len)
    for i in 0 ..< data.len:
      s.buffer[s.size] = data[i]
      s.size.inc

proc add*[T](s: SharedSeq[T], t: SharedSeq[T]) =
  withLock(s): withLock(t):
    s.ensure(s.size + t.size)
    for i in 0 ..< t.size:
      s.buffer[s.size] = t.buffer[i]
      s.size.inc

proc pop*[T](s: SharedSeq[T]): T =
  withLock(s):
    assert s.size >= 1
    s.size.dec
    result = s.buffer[s.size]

proc del*[T](s: SharedSeq[T], index: Natural) =
  withLock(s):
    assert s.size >= 1 and index < s.size
    s.size.dec
    s.buffer[index] = s.buffer[s.size]

proc delete*[T](s: SharedSeq[T], index: Natural) =
  withLock(s):
    assert s.size >= 1 and index < s.size
    s.size.dec
    for i in index.int .. (s.size - 1):
      s.buffer[i] = s.buffer[i + 1]

proc len*[T](s: SharedSeq[T]): int {.inline.} =
  withLock(s):
    result = s.size

proc high*[T](s: SharedSeq[T]): int {.inline.} =
  withLock(s):
    result = s.size - 1

proc `[]`*[T](s: SharedSeq[T], i: Natural): T {.inline.} =
  withLock(s):
    assert i < s.size
    result = s.buffer[i]

proc `[]=`*[T](s: SharedSeq[T], i: Natural, x: T) {.inline.} =
  withLock(s):
    assert i < s.size
    s.buffer[i] = x

proc `@`*[T](s: SharedSeq[T]): seq[T] =
  withLock(s):
    result.setLen(s.size)
    for i in 0 ..< s.size:
      result[i] = s.buffer[i]

iterator items*[T](s: SharedSeq[T]): T =
  withLock(s):
    for i in 0 ..< s.size:
      yield s[i]

iterator mitems*[T](s: SharedSeq[T]): var T =
  withLock(s):
    for i in 0 ..< s.size:
      yield cast[var T](addr s.buffer[i])

iterator pairs*[T](s: SharedSeq[T]): (int, T) =
  withLock(s):
    for i in 0 ..< s.size:
      yield (i, s[i])

iterator mpairs*[T](s: SharedSeq[T]): (int, var T) =
  withLock(s):
    for i in 0 ..< s.size:
      yield (i, cast[var T](addr s.buffer[i]))

proc sort*[T](s: SharedSeq[T], order = SortOrder.Ascending) =
  withLock(s):
    sort(toOpenArray(s.buffer, 0, s.size - 1), order)

proc sort*[T](s: SharedSeq[T], cmp: proc (x, y: T): int, order = SortOrder.Ascending) =
  withLock(s):
    sort(toOpenArray(s.buffer, 0, s.size - 1), cmp, order)

proc binarySearch*[T, K](s: SharedSeq[T], key: K, cmp: proc (x: T; y: K): int): int =
  withLock(s):
    result = binarySearch(toOpenArray(s.buffer, 0, s.size - 1), key, cmp)

proc binarySearch*[T](s: SharedSeq[T], key: T): int =
  withLock(s):
    result = binarySearch(toOpenArray(s.buffer, 0, s.size - 1), key)

proc `$`*[T](s: SharedSeq[T]): string =
  withLock(s):
    result.add "@@["
    for i in 0 ..< s.size:
      result.add $s.buffer[i]
      if i < s.size - 1: result.add ", "

    result.add "]"

when isMainModule:
  import random

  var s = newSharedSeq[int]()
  for i in 1..100:
    s.add rand(1000)

  s.sort
  echo s
  echo s.binarySearch(996)
