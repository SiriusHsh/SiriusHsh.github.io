---
layout: post
title:  sublime text 3 出现license key no longer valid and has been removed
categories: 问题解决
tags: 日常
author: HSH
mathjax: true
---

* content
{:toc}










1. 在hosts中添加下面内容：

   ```
   #sublime text 3
   0.0.0.0 license.sublimehq.com
   0.0.0.0 45.55.255.55
   0.0.0.0 45.55.41.223
   ```

   其中Ubuntu的hosts文件在`/etc/hosts` 
   Windows `C:\Windows\System32\drivers\etc` 
   Mac `/Private/etc`



2. 填入License

   ```
   —– BEGIN LICENSE —–
   TwitterInc
   200 User License
   EA7E-890007
   1D77F72E 390CDD93 4DCBA022 FAF60790
   61AA12C0 A37081C5 D0316412 4584D136
   94D7F7D4 95BC8C1C 527DA828 560BB037
   D1EDDD8C AE7B379F 50C9D69D B35179EF
   2FE898C4 8E4277A8 555CE714 E1FB0E43
   D5D52613 C3D12E98 BC49967F 7652EED2
   9D2D2E61 67610860 6D338B72 5CF95C69
   E36B85CC 84991F19 7575D828 470A92AB
   —— END LICENSE ——
   ```

   ​