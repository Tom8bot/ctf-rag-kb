# Pwn二进制安全模板

```markdown
---
title: Pwn题型或利用技术名称
category: Pwn
tags: [Pwn, 架构, 保护机制, 利用技术]
aliases: [ret2libc, ROP, ORW, 中文别名]
difficulty: 入门/中等/困难
updated: YYYY-MM-DD
source_type: 个人经验/比赛WP/理论整理
verified: true/false
---

# Pwn题型或利用技术名称

## 一句话摘要

说明该利用技术解决什么问题，以及在什么保护机制组合下常用。

## 适用场景

- 架构：
- 操作系统：
- libc版本：
- 保护机制：
- 漏洞类型：

## 不适用条件

- 哪些保护机制会阻止该路线：
- 哪些输入限制会导致该路线失败：
- 远程环境可能存在的差异：

## 关键词

`checksec` `Canary` `NX` `PIE` `RELRO` `ROP` `glibc版本` `gadget`

## 初始分析流程

```bash
file ./pwn
checksec ./pwn
strings ./pwn
```

## 漏洞点判断

1. 输入点：
2. 缓冲区大小：
3. 可控范围：
4. 崩溃位置：
5. 可泄露信息：

## 利用路线

1. 信息泄露：
2. 基址计算：
3. 控制流劫持：
4. payload构造：
5. 远程交互：

## 关键payload结构

```python
from pwn import *

# 这里放payload骨架，不放无解释的完整脚本。
```

## 调试方法

```bash
gdb ./pwn
cyclic 200
cyclic -l 崩溃值
```

## 常见失败原因

- 偏移错误：
- 栈未对齐：
- libc版本不一致：
- 泄露地址不稳定：
- one_gadget约束不满足：
- seccomp限制导致getshell失败：

## 远程环境注意事项

- libc确认方式：
- 输入输出同步：
- 超时和换行：
- 地址随机化：

## 示例问题

```text
这里写一个包含保护机制、漏洞点和限制条件的典型提问。
```

## 参考资料

- WP：
- 工具文档：
- 个人复盘：

## 更新记录

- YYYY-MM-DD：创建文档。
```

## 填写说明

Pwn类文档要把保护机制和利用路线绑定起来。小模型容易忽略Canary、PIE、RELRO、seccomp和glibc版本，所以模板中必须明确“适用条件”和“不适用条件”。
