---
title: Pwn入门(2):Stack Overflow实战小结
date: 2021-12-26 14:09:00 +0800
author: sirius
categories: [CTF]
tags: [CTF, pwn]
math: false
typora-root-url: ../../SiriusHsh.github.io
typora-copy-images-to: ../assets/img/2022
---

接着上一篇Pwn基础知识，这篇写一下栈溢出的实验小结，分成两个大部分：

- NTUSTISC视频中留的练习题
- CTF WIKI上的stack overflow部分题目





#  #1 NTUSTISC Lab

Lab0 的 pwntools上手题

![image-20211227225123600](/assets/img/2022/image-20211227225123600.png)

## 0x01 Return to Text 

### Lab1

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void y0u_c4n7_533_m3()
{
  execve("/bin/sh", (char *[]){0}, (char *[]){0});
}

int main()
{
  char buf[16];
  puts("This is your first bof challenge ;)");
  fflush(stdout);
  read(0, buf, 0x30);
  return 0;
}
```



![image-20211227225905877](/assets/img/2022/image-20211227225905877.png)

> 没有栈保护，代码15行读取0x30字节，buffer overflow，覆盖返回地址为y0u_c4n7_533_m3()函数地址即可。
>
> `objdump -d bof`:
>
> ![image-20211227232815402](/assets/img/2022/image-20211227232815402.png)



![image-20211227230813864](/assets/img/2022/image-20211227230813864.png)



### Lab2

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void y0u_c4n7_533_m3()
{
  int allow = 0;
  if (allow) {
    execve("/bin/sh", 0, 0);
  }
  else {
    puts("Oh no~~~!");
    exit(0);
  }
}

int main()
{
  char buf[16];
  puts("This is your second bof challenge ;)");
  fflush(stdout);
  read(0, buf, 0x30);
  if (strlen(buf) >= 16) {
    puts("Bye bye~~");
    exit(0);
  }
  return 0;
}
```


![image-20211227233212607](/assets/img/2022/image-20211227233212607.png)

> 和第一个基本一样，控制程序执行流return到`execve("/bin/sh", 0, 0);`这一行即可。
>
> 第24行的bypass：strlen判断结束为接收到'\0'位置，所以直接传`\x00`就可以bypass

![image-20211227235502065](/assets/img/2022/image-20211227235502065.png)

![image-20211228000202164](/assets/img/2022/image-20211228000202164.png){: .normal}

strlen 精准bypass，但是没必要。直接全传`\x00`不香🐴  ，都不用算长度


## 0x02 Return to Shellcode

### Lab3

123123

## 0x03 GOT Hijacking

### Lab4



## 0x04 ROP base

### Lab5



## 0x05 Return to PLT

### Lab6



## 0x06 Return to libc

### Lab7







#  #2 CTF wiki

## 0x01 基本ROP

### ret2text



### ret2shellcode



## 0x02 中级ROP



## 0x03 高级ROP

