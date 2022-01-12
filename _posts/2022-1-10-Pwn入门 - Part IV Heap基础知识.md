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

按照上述的计算方法：从0x30转变到0x40的转变点就是   `x+0x8+0xf = 0x40 => x = 0x29` , 也就是`malloc(0x29)`时

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

![image-20220110224240311](/assets/img/2022/image-20220110224240311.png)

连续free掉3个chunk后，bins长这样：

![image-20220110224318960](/assets/img/2022/image-20220110224318960.png)

如果后续malloc了一个0x30大小的chunk（不是malloc(0x30)，有区别的）：

![image-20220110224521265](/assets/img/2022/image-20220110224521265.png)

![image-20220110224558300](/assets/img/2022/image-20220110224558300.png)