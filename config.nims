when not defined(windows):
  switch("clang.cpp.options.always", "-std=c++17")
  switch("gcc.cpp.options.always", "-std=c++17")

  # use the C++ linker profile because it's a C++ library
  when defined(macosx):
    switch("clang.linkerexe", "clang++")
  else:
    switch("gcc.linkerexe", "g++")

switch("warningAsError", "UnusedImport:on")
switch("warningAsError", "UseBase:on")

--styleCheck:
  usages
--styleCheck:
  error
