---
layout: post
title:  Python iter操作
categories: 学习笔记
tags: Python
author: HSH
mathjax: true
---

* content
{:toc}








今天刷LeetCode的时候，在别人的答案中学到了一招。

问题求解大致过程是，在一个二叉树的问题中，列表q记录了所有最深的节点，然后通过记录了孩子-父亲关系的字典，将q逐层替换为父亲节点，直到该（最小）子树包含了所有最深节点。

所以最终q是一个单个元素（root）组成的列表，**问题要求返回这个子树的所有节点。**

关键来了，通过`next(iter(q))`，就可以生成所有q的孩子节点。~~不知道后台是怎么处理的~~

