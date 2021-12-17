---
title: leetcode NO.53 Kadane's algorithm
categories: 学习笔记
tags: Python
---



> 题目描述：
>
> 给定一个整数数组 `nums` ，找到一个具有最大和的连续子数组（子数组最少包含一个元素），返回其最大和。
>
> ```
> 输入: [-2,1,-3,4,-1,2,1,-5,4],
> 输出: 6
> 解释: 连续子数组 [4,-1,2,1] 的和最大，为 6。
> ```



第一眼一看，这个不就是算法作业里的题嘛，用分治写的，于是立马写了个分治算法：

```python
class Solution:
    def maxSubArray(self, nums):
        """
        :type nums: List[int]
        :rtype: int
        """
        if len(nums) == 1: 
            return nums[0]
        mid = len(nums) // 2
        left_max = self.maxSubArray(nums[0: mid])  
        right_max = self.maxSubArray(nums[mid:])
        left_part = nums[mid-1]
        left_part_max = left_part
        for i in range(mid-2, -1, -1):
            left_part += nums[i]
            if left_part > left_part_max:
                left_part_max = left_part
        right_part = nums[mid]
        right_part_max = right_part
        for i in range(mid+1, len(nums)):
            right_part += nums[i]
            if right_part > right_part_max:
                right_part_max = right_part
        mid_max = left_part_max + right_part_max
        return max(right_max, left_max, mid_max)
```

时间复杂度：O(nlogn)，老长一段提交一看，心拔凉拔凉，战胜了2.9%的记录。。。

![](http://octtw77pk.bkt.clouddn.com/WX20180705-161108@2x.png)



在题目中也提到了有O(n)的算法，于是在discuss里了解到这题用的是Kadane's algorithm。

算法记录两个值，**一个是从当前位置开始，往前计算最大的后缀，算法里用max_ending_here表示**，**还有一个是记录到当前位置为止，最大的子串加和，算法用max_so_far表示**



Kadane's algorithm算法描述：

```python
def max_subarray(A):
    max_ending_here = max_so_far = A[0]
    for x in A[1:]:
        max_ending_here = max(x, max_ending_here + x)  #前面的值加上x后大，还是单独x大，如果单独一个x还大点，那就从x开始记录，前面的都不要了
        max_so_far = max(max_so_far, max_ending_here)  #一直记录最大的片段加和
    return max_so_far
```

这回速度：

![](http://octtw77pk.bkt.clouddn.com/WX20180705-164625@2x.png)