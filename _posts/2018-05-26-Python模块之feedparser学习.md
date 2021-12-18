---
title:  Python模块之feedparser学习
categories: 学习笔记
tags: Python
---





今天看《集体智慧编程》的时候看到了一个不认识的Python模块——feedparser，本文简略记录下该模块的用途。

feedparser可轻松地实现从任何 RSS 或 Atom 订阅源得到标题、链接和文章的条目。

**parse()方法**

>feedparser 最为核心的函数自然是 parse() 解析 URL 地址的函数。
>我们知道，每个RSS和Atom订阅源都包含一个标题（d.feed.title）和一组文章条目(d.entries)
>通常每个文章条目都有一段摘要（d.entries[i].summary）,或者是包含了条目中实际文本的描述性标签（d.entries[i].description）

```python
>>>import feedparser
>>>d = feedparser.parse('https://siriushsh.github.io/feed') #d是一个字典
>>>d.keys()
dict_keys(['namespaces', 'bozo', 'updated', 'version', 'updated_parsed', 'href', 'headers', 'encoding', 'feed', 'entries', 'status'])
```

**d.feed**

```python
>>> d['feed']['title']
'SiriusHsh'
>>> d.feed.title  #通过属性的方式访问
'SiriusHsh'
>>> d.feed.subtitle
'问题解决、学习笔记、心得分享'
```

**d.entires**

```python
>>>type(d.entries)  #类型为列表
#<class 'list'>
>>>len(d.entries)   #一共20篇文章
20
>>>[e.title for e in d.entries][:5]         #列出前5篇文章的标题
```







