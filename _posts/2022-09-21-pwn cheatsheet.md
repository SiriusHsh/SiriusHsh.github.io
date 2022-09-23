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



# 0x01 ROPgadget命令

`ROPgadget --binary ./elf --string "/bin/sh"`

`ROPgadget --binary ./elf --only "pop|ret" | grep rdi`

# 0x02 gcc编译指定libc版本

`gcc example.c -o example2.23 -Wl,-rpath='./libc-2.23/' -Wl,-dynamic-linker='./libc-2.23/ld-2.23.so'`

# 0x03 gcc安全编译选项

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

# 0x04 system("$0") == system("/bin/sh")

system("$0") == system("/bin/sh")



顺便提一下system("aaaaaaaa;sh;bbbbb") 也是等于system("sh") , 分好在shell中就是命令分隔符

system("aaaaaaaa")执行错误，不影响执行后续的system("sh")

https://youtu.be/_ZnnGZygnzE?t=4522



# 0x05 pwndbg中查看状态寄存器

```bash
i r eflags 查看状态寄存器
```



# 0x06 一些汇编指令

1、test与jne、je搭配时，test判断两个操作数是否相同

jne如果不相同则跳转

je如果相同则跳转



2、RAX = 高32位 + EAX

EAX = 高16位 + AX

AX = AH + AL









