## qpatch: Hot patching for user-space processes in LINUX.
#### It is for hot patching user-space processes in LINUX. Pure user-space C language development, supports c++ obj, does not need to modify the kernel additionally, and does not rely on any other tools.
1. Achieve the effect of dynamically patching any user-space program developed in C, C++ (no need to restart the process, no need for the source code of the process).
2. Support function HOOK, including glibc library functions. (Convenient for function stubbing).
3. Support patch initialization function (convenient for unit testing).

#### How to use
##### Use Case 1: Patch functions in the running progress
1. Make this example the target of patch (You can choose any other process as a target):
   ````c
    #include <stdio.h>
    #include <unistd.h>
    int main() 
    { 
      while(1) {
    	sleep(5);
    	printf("c test\n");
      }
    }
   ````
   Compile it into an executable file named `cmain` via `gcc cmain.c -o cmain`.
3. Run through `./cmain`. You can see it prints `test` every 5 seconds
   ```
   test
   test
   test
   test
   ...
   ```
   Just keep it running, and open another terminal.
5. Write your patch code, here we assume you want to patch the `sleep` function so that it does not sleep and only prints `sleep called!`, following is the patch code:
   ```c
   #include <stdio.h>
   void sleep(int i) {
     printf("sleep called!\n");
   }
   ```
6. Let's compile it to a ***OBJ*** file named `cpatch.o` via `gcc -c cpatch.c -o cpatch.o`.
   ```
   The advantage of OBJ files is that compilation does not require all the code of the target process, so it can be compiled independently from the source code of the target process.
   ```
7. Load & Active this `cpatch.o` into `cmain` via run the following 2 commands:
   ```
   ./qpatch.bin -o ./cpatch.o -p `pidof cmain` -l
   ./qpatch.bin -o ./cpatch.o -p `pidof cmain` -a
   ```
8. Then go back to check the terminal which running the `cmain`, you will see it keep printing `sleep called!` and `c test`.
   ```
    c test
    sleep called!
    c test
    sleep called!
    c test
    sleep called!
   ```
9. Run the command `./qpatch.bin -o ./cpatch.o -p `pidof cmain` -r`, to rollback the patch, the print come back to:
   ```
   test
   test
   test
   test
   ...
   ```
##### Use Case 2: Hook functions in the running progress
0. ***What if I don’t want to destroy sleep’s functionality and add more capabilities to it, such as the ability to print logs?***
1. Let's build on the previous cmain example  (You can choose any other process as a target):
   ````c
    #include <stdio.h>
    #include <unistd.h>
    int main() 
    { 
      while(1) {
    	sleep(5);
    	printf("c test\n");
      }
    }
   ````
   Compile it into an executable file named `cmain` via `gcc cmain.c -o cmain`.
2. Run through `./cmain`. You can see it prints `test` every 5 seconds
   ```
   test
   test
   test
   test
   ...
   ```
   Just keep it running, and open another terminal.
5. Write your patch code, here we assume you want to hook the `sleep` function so that it has additional log before actuall call the `sleep`, following is the hook code:
   ```c
    #include <stdio.h>
    
    void sleep(int i);
    
    void _qpatch_hookfun_sleep(int i) {
    	printf("before sleep called!\n");
    	sleep(i);
    	printf("after sleep called!\n");
    }
   ```
   ***_qpatch_hookfun_*** is the keyword, which can be processed by this tool.
6. Let's compile it to a ***OBJ*** file named `chook.o` via `gcc -c chook.c -o chook.o`.
   ```
   The advantage of OBJ files is that compilation does not require all the code of the target process, so it can be compiled independently from the source code of the target process.
   ```
7. Load & Active this `cpatch.o` into `cmain` via run the following 2 commands:
   ```
   ./qpatch.bin -o ./cpatch.o -p `pidof cmain` -l
   ./qpatch.bin -o ./cpatch.o -p `pidof cmain` -a
   ```
8. Then go back to check the terminal which running the `cmain`, you will see it keep printing:
   ```
    after sleep called!
    c test
    before sleep called!
   ```
9. Run the command `./qpatch.bin -o ./cpatch.o -p `pidof cmain` -r`, to rollback the patch, the print come back to:
   ```
   test
   test
   test
   test
   ...
   ```
   
## gotrace: Track and print all function calls of a Golang program.
#### The gotrace tool can print out all function calls during the execution of a Golang program, as well as the input parameters and return values (unresolved).

#### How to use:
##### Use Case 1: 
1. For example you have a go project like this:
   ```go
    package main

    import "fmt"
    import "time"
    
    func main() {
        for true  {
            fmt.Printf("test\n");
    		time.Sleep(5 * time.Second);
        }
    }
   ```
   Compiled it to `gomain`.
3. Run `./gotrace.bin ./gomain` to run, you will see every function call:
   ```
    mid[00009747] goid[000000]: [0x442160] runtime.check <-( 0x52cb80, 0x2100800, 0x52c820, 0x1002, 0x52cc10, 0x1ff, 0xf, 0x7fe50f6e0860, 0x212, ... )
    mid[00009747] goid[000000]: [0x441f60] runtime.testAtomic64 <-( 0xffffffff, 0x2100800, 0x1, 0x1002, 0x3b9aca00, 0x1ff, 0xf, 0x7fe50f6e0860, 0x212, ... )
    mid[00009747] goid[000000]: [0x441c80] runtime.args <-( 0x1, 0x7ffe17513338, 0xb, 0x1002, 0x800, 0x1ff, 0xf, 0x7fe50f6e0860, 0x212, ... )
    mid[00009747] goid[000000]: [0x42e460] runtime.sysauxv <-( 0x7ffe17513428, 0x10000000, 0x10000000, 0x1002, 0x0, 0x1ff, 0xf, 0x7fe50f6e0860, 0x212, ... )
    mid[00009747] goid[000000]: [0x4578e0] runtime.vdsoInitFromSysinfoEhdr <-( 0x7ffe17512dd0, 0x7ffe17527000, 0x0, 0x7ffe17512e40, 0x7ffe17527000, 0x1ff, 0xf, 0x7fe50f6e0860, 0x212, ... )
    mid[00009747] goid[000000]: [0x457d60] runtime.vdsoFindVersion <-( 0x7ffe17512dd0, 0x525290, 0x7ffe1752718c, 0x7ffe175273a0, 0x7ffe17527180, 0xffffffffffffffff, 0xfffffffffff9, 0x7ffe17527120, 0x3fffffffffff, ... )
    mid[00009747] goid[000000]: [0x458240] runtime.vdsoParseSymbols.func1 <-( 0x2, 0x49b9eb, 0x13, 0x315ca59, 0xb01bca00, 0x55b270, 0x458240, 0xb01bca00, 0x13, ... )
    mid[00009747] goid[000000]: [0x458240] runtime.vdsoParseSymbols.func1 <-( 0x8, 0x49be31, 0x14, 0xd35ec75, 0x6e43a318, 0x55b268, 0x458240, 0x6e43a319, 0x14, ... )
    mid[00009747] goid[000000]: [0x42e6c0] runtime.osinit <-( 0x13, 0x10000000, 0x0, 0x7ffe17527309, 0x10000000, 0x7ffe17513569, 0x2, 0x18, 0x7ffe1752727e, ... )
    mid[00009747] goid[000000]: [0x42e580] runtime.getHugePageSize <-( 0xc, 0x0, 0x1, 0x0, 0x0, 0x7ffe17513569, 0x2, 0x18, 0x246, ... )
    mid[00009747] goid[000000]: [0x435060] runtime.schedinit <-( 0x200000, 0x1, 0x1fffff, 0x200000, 0xffffffffffe00000, 0x1999999999999999, 0xfffff, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x40a820] runtime.mallocinit <-( 0x23, 0x482634, 0x22, 0x4b9150, 0x0, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x423bc0] runtime.(*mheap).init <-( 0x544680, 0x200000, 0x15, 0x4b9150, 0x0, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x415f00] runtime.(*fixalloc).init <-( 0x55aec0, 0x88, 0x4a1c60, 0x544680, 0x55d520, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x415f00] runtime.(*fixalloc).init <-( 0x55af08, 0x4b0, 0x0, 0x0, 0x55d528, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x415f00] runtime.(*fixalloc).init <-( 0x55af50, 0x30, 0x0, 0x0, 0x55d540, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x415f00] runtime.(*fixalloc).init <-( 0x55af98, 0x18, 0x0, 0x0, 0x55d540, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
    mid[00009747] goid[000000]: [0x415f00] runtime.(*fixalloc).init <-( 0x55afe0, 0x18, 0x0, 0x0, 0x55d540, 0x58f, 0x4f7ad8, 0x0, 0x206, ... )
   ```

##### Use Case 2: Attach to a running progress
1. For example you have a go project like this:
   ```go
    package main

    import "fmt"
    import "time"
    
    func main() {
        for true  {
            fmt.Printf("test\n");
    		time.Sleep(5 * time.Second);
        }
    }
   ```
   Compiled it to `gomain`.
2. Run it via `./gomain`. Just keep it running, and open another terminal.
3. Attach to the running `gomain` via `./gotrace.bin -p `pidof gomain`.
4. You will see the following output:
   ```
    mid[00009759] goid[000000]: [0x409fe0] runtime.lock2 <-( 0x52cf98, 0x52cb80, 0x0, 0x3, 0x7fff5d6c4638, 0x0, 0x7fff5d77e090, 0x1387, 0x246, ... )
    mid[00009759] goid[000000]: [0x4405e0] runtime.pidleget <-( 0x1059e5e97a0f60, 0x52cb80, 0x0, 0x3, 0x1, 0x0, 0x7fff5d77e090, 0x1387, 0x246, ... )
    mid[00009759] goid[000000]: [0x419a00] runtime.(*limiterEvent).stop <-( 0xc000029228, 0x4, 0x1059e5e97a0f60, 0x52cfd8, 0xc000029228, 0xfffffffe, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x40a1c0] runtime.unlock2 <-( 0x52cf98, 0x1059e5e97a0f60, 0x0, 0x1059e5e97a8b98, 0x1059e5e97a0f60, 0xffffff01, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x43e800] runtime.acquirep <-( 0xc000028000, 0x1059e5e97a0f60, 0x0, 0x1059e5e97a8b98, 0x1059e5e97a0f60, 0xffffff01, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x413d00] runtime.(*mcache).prepareForSweep <-( 0x7ff183216108, 0x1059e5e97a0f60, 0xc000028000, 0x1059e5e97a8b98, 0x1059e5e97a0f60, 0xffffff01, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x43a7c0] runtime.checkTimers <-( 0xc000028000, 0x0, 0x52c820, 0x1059e5e97a8b98, 0x1059e5e97a0f60, 0xffffff01, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x439a20] runtime.stealWork <-( 0x0, 0x52cfdc, 0x0, 0x1, 0x1, 0xb, 0x0, 0x0, 0x246, ... )
    mid[00009759] goid[000000]: [0x43a7c0] runtime.checkTimers <-( 0xc00002ca00, 0x0, 0x3, 0x0, 0x0, 0xc00002ca00, 0x1, 0xa0761d6478bd642f, 0xc000016080, ... )
    mid[00009759] goid[000000]: [0x409fe0] runtime.lock2 <-( 0x52cf98, 0xc, 0xc000026000, 0x1, 0xc00001607c, 0x1, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x43e980] runtime.releasep <-( 0xc000028000, 0xc, 0xc000026000, 0x1, 0x1, 0x1, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x440440] runtime.pidleput <-( 0xc000028000, 0x1059e6f9d806a4, 0xc000028000, 0x1, 0x1, 0x1, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x440340] runtime.updateTimerPMask <-( 0xc000028000, 0x1059e6f9d806a4, 0x2, 0x2, 0x0, 0x1, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x409fe0] runtime.lock2 <-( 0xc00002a280, 0x1059e6f9d806a4, 0xc00002a280, 0x2, 0x0, 0x1, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x40a1c0] runtime.unlock2 <-( 0xc00002a280, 0xc000016080, 0xc000016080, 0xffffffff, 0xfffffffe, 0x0, 0xc000016080, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x40a1c0] runtime.unlock2 <-( 0x52cf98, 0xc000028000, 0xc000028000, 0x0, 0x52cfd8, 0x0, 0x1, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x439da0] runtime.checkRunqsNoP <-( 0xc000026000, 0xc, 0xc, 0xc00001607c, 0x1, 0x1, 0x52cfdc, 0x1, 0x1, ... )
    mid[00009759] goid[000000]: [0x439f80] runtime.checkIdleGCNoP <-( 0x0, 0xc, 0xc, 0xc00001607c, 0x1, 0xb, 0xfff, 0x1, 0x1, ... )
    mid[00009760] goid[000000]: [0x409fe0] runtime.lock2 <-( 0x52cf98, 0xc00004c000, 0x0, 0x1, 0xc00005bea0, 0x7fff5d77e080, 0x7fff5d77e090, 0x51d7900, 0x463a50, ... )
    mid[00009759] goid[000000]: [0x409fe0] runtime.lock2 <-( 0x52cf98, 0x52cb80, 0x0, 0x3, 0x7fff5d6c4638, 0x0, 0x7fff5d77e090, 0x1ad, 0x246, ... )
    mid[00009760] goid[000000]: [0x40a1c0] runtime.unlock2 <-( 0x52cf98, 0xc00004c000, 0x38, 0x1, 0x1, 0x7fff5d77e080, 0x7fff5d77e090, 0x51d7900, 0x463a50, ... )
   ```

## How to build:
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
