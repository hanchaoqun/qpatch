#! /bin/bash

#compile distorm64.a
PWDIR=`pwd`
cd ./distorm64-v1.7.30/build/linux/
make clean
make clib
cd $PWDIR

#compile qpatch
echo "make qpatch..."
gcc -g ptrace.c symbol.c define.c linkable.c opcode.c qpatch.c -Wall -Werror -o qpatch.bin ./distorm64-v1.7.30/distorm64.a
gcc libqpatch.c -fPIC -shared -o qpatch.so
echo "make qpatch...ok"

chmod 755 qpatch.bin
chmod 755 qpatch.so

#compile gotrace
echo "make gotrace..."
gcc -g ptrace.c symbol.c define.c linkable.c opcode.c hashmap.c/hashmap.c gotrace.c -Wall -Werror -o gotrace.bin -lstdc++ ./distorm64-v1.7.30/distorm64.a
echo "make gotrace...ok"

chmod 755 gotrace.bin
