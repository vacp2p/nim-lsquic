when not defined(windows):
  # use the C++ linker profile because it's a C++ library
  when defined(macosx):
    switch("clang.linkerexe", "clang++")
  else:
    switch("gcc.linkerexe", "g++")

--styleCheck:
  usages
--styleCheck:
  error
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
