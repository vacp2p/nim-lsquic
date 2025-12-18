const fast {.booldefine.}: bool = false

proc isFast*(): bool =
  return fast
