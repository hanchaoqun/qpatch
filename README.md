## qpatch: Hot patching for user-space processes in LINUX.
#### It is for hot patching user-space processes in LINUX. Pure user-space C language development, supports c++ obj, does not need to modify the kernel additionally, and does not rely on any other tools.
1. Achieve the effect of dynamically patching any user-space program developed in C, C++ (no need to restart the process, no need for the source code of the process).
2. Support function HOOK, including glibc library functions. (Convenient for function stubbing).
3. Support patch initialization function (convenient for unit testing).

## gotrace: Track and print all function calls of a Golang program.
#### The gotrace tool can print out all function calls during the execution of a Golang program, as well as the input parameters and return values (unresolved).

## Compilation and usage method:
1. Download the code from **[https://github.com/hanchaoqun/distorm64](https://github.com/hanchaoqun/distorm64)** to the "distorm64-v1.7.30" directory.
2. Download the code from **[https://github.com/hanchaoqun/hashmap.c](https://github.com/hanchaoqun/hashmap.c)** to the "hashmap.c" directory.
3. Run build.sh to compile.
4. Two files for qpatch: qpatch.bin and qpatch.so, are generated.
5. One file for gotrace: gotrace.bin is generated.


## qpatch: 对LINUX下的用户态进程进行热补丁。
#### 对LINUX下的用户态进程进行热补丁。纯用户态c语言开发，支持c++的obj，不需要额外修改内核，不依赖任何其他工具。
1. 达到随意给任何c,c++开发的用户态程序动态打补丁的效果（无需重启进程，无需该进程的源码）。
2. 支持函数HOOK，包括glibc库函数。（方便进行函数打桩）。
3. 支持补丁初始化函数（方便进行单元测试）。

## gotrace: 跟踪并打印golang程序的所有函数调用。
#### 使用gotrace工具可以打印出golang程序执行过程中的所有函数调用，以及入参和返回值（未解析）。

## 编译及使用方法：
1. 下载 **[https://github.com/hanchaoqun/distorm64](https://github.com/hanchaoqun/distorm64)** 代码到"distorm64-v1.7.30"目录。
2. 下载 **[https://github.com/hanchaoqun/hashmap.c](https://github.com/hanchaoqun/hashmap.c)** 代码到"hashmap.c"目录。
3. 运行build.sh进行编译。
4. qpatch: 生成两个文件qpatch.bin和qpatch.so。
5. gorace: 生成一个文件gotrace.bin。
