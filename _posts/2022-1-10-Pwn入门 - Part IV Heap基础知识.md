---
title: Pwn入门 - Part IV Heap基础知识
date: 2022-1-10 14:09:00 +0800
author: sirius
categories: [CTF]
tags: [CTF, pwn]
math: false
typora-root-url: ../../SiriusHsh.github.io
typora-copy-images-to: ../assets/img/2022
---



**本文只是学习过程中的笔记记录，方便后续查找。并非是知识点总结**





## 一些命令记录

```
pwngdb插件命令：
- heapinfo: 查看bins的链表
- parseheap: 查看chunk
- tls: 查看canary
```



## NTUSTISC slide

---

## ptmalloc

![image-20220110220146507](/assets/img/2022/image-20220110220146507.png)

![image-20220110220211538](/assets/img/2022/image-20220110220211538.png)



## chunk

![image-20220110220238003](/assets/img/2022/image-20220110220238003.png)

### Allocated Chunk

![image-20220110220945472](/assets/img/2022/image-20220110220945472.png)

> 这里提到的都是临近的上一个Chunk，指的真的是贴在一起的两个Chunk，而不是链表链接起来的Chunk。

chunk大小计算：

![image-20220110222240424](/assets/img/2022/image-20220110222240424.png)

按照上述的计算方法：从0x30转变到0x40的转变点就是  `x+0x8+0xf = 0x40 => x = 0x29` , 也就是`malloc(0x29)`时

![image-20220110222652232](/assets/img/2022/image-20220110222652232.png)

![image-20220110223246859](/assets/img/2022/image-20220110223246859.png)

![image-20220110223311581](/assets/img/2022/image-20220110223311581.png)

![image-20220110223320034](/assets/img/2022/image-20220110223320034.png)

![image-20220110223329589](/assets/img/2022/image-20220110223329589.png)



再增加，就要扩大chunk的size了。看从0x28到0x29的变化

![image-20220110223406111](/assets/img/2022/image-20220110223406111.png)



### Free Chunk

![image-20220110223500370](/assets/img/2022/image-20220110223500370.png)

![image-20220110223807830](/assets/img/2022/image-20220110223807830.png)



### Top Chunk

![image-20220110223823865](/assets/img/2022/image-20220110223823865.png)



## Fastbin

![image-20220116221505016](/assets/img/2022/image-20220116221505016.png)

连续free掉3个chunk后，bins长这样：

![image-20220110224318960](/assets/img/2022/image-20220110224318960.png)

如果后续malloc了一个0x30大小的chunk（不是malloc(0x30)，有区别的）：

![image-20220110224521265](/assets/img/2022/image-20220110224521265.png)

![image-20220110224558300](/assets/img/2022/image-20220110224558300.png)



## Tcache

![image-20220117220820885](/assets/img/2022/image-20220117220820885.png)

>  malloc过程

![image-20220117220954292](/assets/img/2022/image-20220117220954292.png)

>  free过程

![image-20220117221516233](/assets/img/2022/image-20220117221516233.png)

![image-20220117221624142](/assets/img/2022/image-20220117221624142.png)

![image-20220117221634913](/assets/img/2022/image-20220117221634913.png)

> 总结

![image-20220117221828128](/assets/img/2022/image-20220117221828128.png)

## example

```python
#include<stdio.h>
#include<stdlib.h>

int main(){
    char *ptr1 = malloc(0x20);
    char *ptr2 = malloc(0x20);
    char *ptr3 = malloc(0x20);

    memset(ptr1, 'A', 0x20);

    free(ptr1);
    free(ptr2);
    free(ptr3);

    char *ptr4 = malloc(0x20);
    char *ptr5 = malloc(0x200);
    return 0;
}
```

编了两个版本libc2.27和libc2.23，2.27来看tcache，2.23看fastbin

![image-20220117223037305](/assets/img/2022/image-20220117223037305.png)

自定义libc版本编译的命令：`gcc example.c -o example2.23 -Wl,-rpath='./libc-2.23/' -Wl,-dynamic-linker='./libc-2.23/ld-2.23.so'`

libc的各个版本可以通过[glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)获取。

### 先来看2.23的版本

- 第一次malloc前，没有heap段

![image-20220123132841179](/assets/img/2022/image-20220123132841179.png)

- malloc后：

![image-20220123133247388](/assets/img/2022/image-20220123133247388.png)

 `parseheap`显示第一块chunk的address，chunk head地址为0x555555756000。

> 同时注意看rax，malloc函数申请内存后，将chunk **data**的地址作为返回值，返回值存入rax寄存器中。`mov    QWORD PTR [rbp-0x28],rax`这一句汇编呢，对应的就是源码里的`char *ptr1 = malloc(0x20);`赋值操作了，说明ptr1位于`rbp-0x28`，这块内存中存储的值为chunk data的地址（0x555555756010），也就是说ptr1这个指针指向了刚申请的chunk的data部分。随后，就可以操作ptr1指针，来对内存读写操作。

- malloc三次之后

![image-20220123134200872](/assets/img/2022/image-20220123134200872.png)

- 写入0x20个A

  ![image-20220123134233447](/assets/img/2022/image-20220123134233447.png)

- free一次

![image-20220123134559840](/assets/img/2022/image-20220123134559840.png)

- free三次

![image-20220123134650673](/assets/img/2022/image-20220123134650673.png)

> fastbin链表fd指向的都是chunk head
>
> ![image-20220123134856522](/assets/img/2022/image-20220123134856522.png)

- Malloc(0x20)

Malloc 0x20会分配一个0x30大小的chunk ，所以会把最近的一个chunk分配出去。

![image-20220123135224865](/assets/img/2022/image-20220123135224865.png)

- Malloc 0x200

![image-20220123135313252](/assets/img/2022/image-20220123135313252.png)

### 再看下2.27的版本

只写区别的地方

- 第一次malloc后

![image-20220123135444680](/assets/img/2022/image-20220123135444680.png)

除了chunk上面还有一个tcache_perthread_struct

![image-20220123135721921](/assets/img/2022/image-20220123135721921.png)

- 第一次free后

![image-20220123140625740](/assets/img/2022/image-20220123140625740.png)

> 有好几个需要注意的地方：
>
> - Fd指向的都是chunk data
>
>   ![image-20220123140916688](/assets/img/2022/image-20220123140916688.png)
>
> - bk里的值等于tcache，代表key，用作安全检查
>
>   ![image-20220123141030567](/assets/img/2022/image-20220123141030567.png)
>
> - free后tcache_perthread_struct记录每种大小chunk的个数（cnt)， 以及存放一个指向chunk的指针（entry）



- free三次后

![image-20220123141443478](/assets/img/2022/image-20220123141443478.png)

- malloc(0x20)

![image-20220123141645835](/assets/img/2022/image-20220123141645835.png)

