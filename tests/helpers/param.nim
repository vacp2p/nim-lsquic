
const fast {.strdefine.} = ""

proc isFast*(): bool =
  return fast == "true"