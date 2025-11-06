#!/bin/bash
root=$(dirname "$0")
sources=${root}/libs

rm -f lsquic_ffi.nim

# assemble list of C files to be compiled
toCompile=(
  # "${sources}/path/to/file.c"
)

# futhark is required by generate_lsquic_ffi.nim
nimble install futhark@0.15.0

nim c --maxLoopIterationsVM:100000000 generate_lsquic_ffi.nim

cat "${root}/prelude.nim" > lsquic_ffi.nim

echo >> lsquic_ffi.nim # linebreak

for file in "${toCompile[@]}"; do
    echo "{.compile: \"$file\".}" >> lsquic_ffi.nim
done

cat tmp_lsquic_ffi.nim >> lsquic_ffi.nim

echo >> lsquic_ffi.nim # linebreak

cat "${root}/extras.nim" >> lsquic_ffi.nim

rm -f tmp_lsquic_ffi.nim