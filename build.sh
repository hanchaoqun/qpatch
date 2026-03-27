#! /bin/bash

set -e

DISTORM_LIB=""
if [ -d "./distorm64-v1.7.30/build/linux/" ]; then
  # compile distorm64.a
  PWDIR=`pwd`
  cd ./distorm64-v1.7.30/build/linux/
  make clean
  make clib
  cd $PWDIR
  if [ -f "./distorm64-v1.7.30/distorm64.a" ]; then
    DISTORM_LIB="./distorm64-v1.7.30/distorm64.a"
  fi
else
  echo "WARN: distorm64 sources not found, build will use opcode fallback."
fi

#compile qpatch
echo "make qpatch..."
gcc -g arch/arch.c arch/x86_64/arch_x86_64.c arch/aarch64/arch_aarch64.c ptrace.c symbol.c define.c linkable.c opcode.c qpatch.c -Wall -Werror -o qpatch.bin $DISTORM_LIB
gcc libqpatch.c -fPIC -shared -o qpatch.so
echo "make qpatch...ok"

chmod 755 qpatch.bin
chmod 755 qpatch.so

#compile gotrace
echo "make gotrace..."
gcc -g arch/arch.c arch/x86_64/arch_x86_64.c arch/aarch64/arch_aarch64.c ptrace.c symbol.c define.c linkable.c opcode.c hashmap.c/hashmap.c gotrace.c -Wall -Werror -o gotrace.bin -lstdc++ $DISTORM_LIB
echo "make gotrace...ok"

chmod 755 gotrace.bin
