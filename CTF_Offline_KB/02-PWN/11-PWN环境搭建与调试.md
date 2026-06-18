---
category: "环境搭建"
tags: ["patchelf", "glibc", "Docker", "调试", "GDB", "pwntools", "环境隔离"]
difficulty: "入门"
---

# PWN环境搭建与调试：patchelf/glibc多版本/Docker隔离

## 1. 概述

CTF断网离线场景对PWN环境搭建有极高的要求。题目的libc版本可能各不相同，本地glibc版本不一致会导致偏移计算错误。正确搭建与题目完全一致的运行环境是成功利用的前提。

本文覆盖离线环境下patchelf动态链接器修改、glibc多版本管理、Docker容器隔离、以及GDB调试工作流。

## 2. 核心原理

### 2.1 动态链接过程

```
1. execve() 加载 ELF
2. 内核读取 .interp section，找到动态链接器路径 (如 /lib64/ld-linux-x86-64.so.2)
3. 动态链接器加载所需的共享库 (根据 .dynamic 中的 NEEDED 条目)
4. 解析符号 -> 重定位 -> 执行 main

关键: 我们可以通过修改 .interp 和 RPATH/RUNPATH 来使用自定义的 ld.so 和 libc.so
```

### 2.2 glibc版本不匹配问题

```
症状:
- 本地 exploit 成功，远程失败
- 函数偏移计算完全不对
- 程序启动即 segfault

原因:
- 本地 glibc 版本与题目不同
- 动态链接器版本不匹配
- libc 内函数偏移差异
```

## 3. 关键技巧/检测方法

### 3.1 patchelf 修改链接

```bash
# 查看当前链接信息
readelf -l ./binary | grep INTERP
patchelf --print-interpreter ./binary
ldd ./binary  # 查看依赖 (注意: 可能显示系统libc)

# 修改动态链接器
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./binary

# 修改 RPATH (共享库搜索路径)
patchelf --set-rpath ./ ./binary  # 优先从当前目录加载 .so

# 验证
patchelf --print-rpath ./binary
readelf -d ./binary | grep RPATH
```

### 3.2 glibc多版本管理

```bash
# 目录结构设计
~/glibc-all/
├── 2.23-0ubuntu11.3_amd64/
│   ├── libc-2.23.so
│   └── ld-2.23.so
├── 2.27-3ubuntu1.6_amd64/
│   ├── libc-2.27.so
│   └── ld-2.27.so
├── 2.31-0ubuntu9.16_amd64/
│   ├── libc-2.31.so
│   └── ld-2.31.so
├── 2.35-0ubuntu3.8_amd64/
│   ├── libc-2.35.so
│   └── ld-2.35.so
└── libc-database/         # libc 偏移数据库
    └── db/
```

### 3.3 获取题目libc的方法

```bash
# 方法1: 题目直接提供
# 通常附件包含: binary, libc-2.31.so, ld-2.31.so

# 方法2: 通过泄露的函数地址匹配 (离线用libc-database)
# 已知 puts 泄露地址 = 0x7f1234567890 (低12位=0x890)
# 用 libc-database 查找:
./find puts 890
# 可能输出多个匹配的libc版本

# 方法3: Docker中运行，从容器内提取
docker pull ubuntu:18.04
docker run -it ubuntu:18.04 bash
# cp /lib/x86_64-linux-gnu/libc-2.27.so /tmp/
# docker cp ...

# 方法4: Ubuntu 包管理下载 (离线不适用)
# apt download libc6:amd64
```

### 3.4 libc-database 离线使用

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libc-database 离线使用脚本
通过已知函数名和泄露低12位匹配libc版本
"""
import os
import struct
from pwn import *

class LibcSearcher:
    """简化的本地libc搜索器"""

    def __init__(self, db_path='./libc-database/db'):
        self.db_path = db_path
        self.libc_list = {}

    def add_libc(self, name, libc_path):
        """注册一个libc文件"""
        libc = ELF(libc_path)
        self.libc_list[name] = {
            'elf': libc,
            'symbols': {
                'puts': libc.symbols.get('puts'),
                'system': libc.symbols.get('system'),
                '__libc_start_main': libc.symbols.get('__libc_start_main'),
                '__malloc_hook': libc.symbols.get('__malloc_hook'),
            },
            'search': {
                '/bin/sh': next(libc.search(b'/bin/sh')),
            }
        }

    def find_by_symbol(self, symbol_name, low12_bits):
        """通过符号名的低12位匹配libc"""
        matches = []
        for name, info in self.libc_list.items():
            addr = info['symbols'].get(symbol_name)
            if addr and (addr & 0xFFF) == (low12_bits & 0xFFF):
                matches.append((name, addr))
        return matches

    def find_by_multiple(self, constraints):
        """
        通过多个约束匹配
        constraints: [(symbol_name, leaked_value, mask), ...]
        """
        matches = []
        for name, info in self.libc_list.items():
            match = True
            for sym, leaked, mask in constraints:
                addr = info['symbols'].get(sym)
                if not addr or (addr & mask) != (leaked & mask):
                    match = False
                    break
            if match:
                matches.append(name)
        return matches

# 使用示例
searcher = LibcSearcher()
searcher.add_libc('2.27', './libc-2.27.so')
searcher.add_libc('2.31', './libc-2.31.so')

# 泄露 puts 地址为 0x7f1234567890
matches = searcher.find_by_symbol('puts', 0x890 & 0xFFF)
log.info(f'Matches: {matches}')
```

## 4. 常见误区与注意事项

1. **ld.so必须匹配libc**：不同版本的ld无法加载不同版本的libc
2. **LD_PRELOAD坑**：`LD_PRELOAD=./libc.so.6 ./binary`只覆盖libc，不覆盖ld
3. **patchelf对PIE无效**：PIE二进制需要先打补丁禁用PIE
4. **libc符号版本**：GLIBC_2.34+中`__malloc_hook`等功能被废弃
5. **多架构支持**：i386和amd64的libc不同，注意区分
6. **QEMU user模式**：`qemu-x86_64 -L ./libs/ ./binary`可模拟非本地架构

## 5. 实战示例

### 5.1 patchelf完整工作流

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patchelf 工作流脚本
自动化处理二进制+libc环境切换
"""
from pwn import *
import subprocess
import os

context.arch = 'amd64'
context.log_level = 'info'

def setup_binary(binary_path, libc_path=None, ld_path=None, output_path=None):
    """
    配置二进制文件使用指定的libc和动态链接器
    返回配置后的二进制路径
    """
    if output_path is None:
        output_path = binary_path + '_patched'

    # 复制二进制
    if not os.path.exists(output_path):
        subprocess.run(['cp', binary_path, output_path])

    # 修改动态链接器
    if ld_path:
        subprocess.run(['patchelf', '--set-interpreter', ld_path, output_path])

    # 修改RPATH (使ld优先从当前目录找libc)
    if libc_path:
        libc_dir = os.path.dirname(libc_path) or '.'
        subprocess.run(['patchelf', '--set-rpath', libc_dir, output_path])
        # 或者直接用 --replace-needed
        # subprocess.run(['patchelf', '--replace-needed', 'libc.so.6', libc_path, output_path])

    # 确保执行权限
    os.chmod(output_path, 0o755)

    # 验证
    result = subprocess.run(['patchelf', '--print-interpreter', output_path],
                            capture_output=True, text=True)
    log.info(f'Interpreter: {result.stdout.strip()}')

    result = subprocess.run(['patchelf', '--print-rpath', output_path],
                            capture_output=True, text=True)
    log.info(f'RPATH: {result.stdout.strip()}')

    return output_path

# ---- 使用示例 ----
# 题目提供了 binary, libc-2.31.so, ld-2.31.so
binary = './vuln'
libc = './libc-2.31.so'
ld = './ld-2.31.so'

patched = setup_binary(binary, libc, ld)
elf = ELF(patched)
libc_elf = ELF(libc)

# 验证 libc 地址正确
log.info(f'puts@libc offset: {hex(libc_elf.symbols["puts"])}')
log.info(f'system@libc offset: {hex(libc_elf.symbols["system"])}')
log.info(f'/bin/sh offset: {hex(next(libc_elf.search(b"/bin/sh")))}')

# 现在可以正常使用 process() 运行
p = process(patched)

# ---- 或者使用 LD_PRELOAD 方式（不需修改二进制） ----
def run_with_libc(binary, libc_path, ld_path):
    """使用 LD_PRELOAD 运行（无需修改二进制）"""
    env = os.environ.copy()
    env['LD_PRELOAD'] = os.path.abspath(libc_path)

    # 直接用 ld 加载
    # ld_path --library-path ./ binary
    p = process([ld_path, '--library-path', '.', binary], env=env)
    return p

# 或直接用pwntools的 env 参数
p = process(patched, env={'LD_PRELOAD': './libc-2.31.so'})
```

### 5.2 Docker隔离环境

```dockerfile
# Dockerfile
# 使用方法: docker build -t pwn-env-ubuntu18 .
#   docker run -it --rm -v $(pwd):/pwn pwn-env-ubuntu18 bash

FROM ubuntu:18.04

# 安装PWN工具
RUN apt-get update && apt-get install -y \
    gdb \
    python3-pip \
    git \
    vim \
    gcc \
    gcc-multilib \
    netcat \
    socat \
    strace \
    ltrace \
    patchelf \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# 安装pwntools
RUN pip3 install pwntools

# 安装pwndbg
RUN git clone https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh

# 设置工作目录
WORKDIR /pwn

# 配置GDB
RUN echo "set disable-randomization on" >> /root/.gdbinit \
    && echo "source /opt/pwndbg/gdbinit.py" >> /root/.gdbinit

CMD ["/bin/bash"]
```

### 5.3 自动化Docker利用脚本

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线环境下的Docker自动化利用流程
1. 根据提供的libc版本选择对应Docker镜像
2. 运行exploit
3. 收集输出
"""
from pwn import *
import subprocess
import json

class DockerPWN:
    """离线Docker PWN环境管理器"""

    # libc版本 -> Docker镜像映射
    IMAGE_MAP = {
        '2.23': 'ubuntu:16.04',
        '2.27': 'ubuntu:18.04',
        '2.31': 'ubuntu:20.04',
        '2.35': 'ubuntu:22.04',
    }

    def __init__(self, binary_path, libc_path, ld_path=None):
        self.binary = binary_path
        self.libc = libc_path
        self.ld = ld_path
        self.libc_version = self._detect_libc_version()
        self.container_name = f'pwn_{os.path.basename(binary_path)}_{os.getpid()}'

    def _detect_libc_version(self):
        """检测libc版本"""
        try:
            result = subprocess.run(['strings', self.libc],
                                    capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.startswith('GNU C Library'):
                    log.info(f'Detected: {line}')
                    # Extract version "2.31"
                    import re
                    m = re.search(r'(\d+\.\d+)', line)
                    if m:
                        return m.group(1)
            return 'unknown'
        except:
            return 'unknown'

    def prepare_exploit(self):
        """准备利用环境"""

        # 创建临时目录
        workdir = f'/tmp/pwn_docker_{os.getpid()}'
        os.makedirs(workdir, exist_ok=True)

        # 复制文件
        for f in [self.binary, self.libc]:
            if f:
                subprocess.run(['cp', f, workdir])

        if self.ld:
            subprocess.run(['cp', self.ld, workdir])

        # patchelf 修改
        binary_name = os.path.basename(self.binary)
        patched_bin = os.path.join(workdir, binary_name)

        local_ld = os.path.join(workdir, os.path.basename(self.ld or ''))
        if self.ld:
            subprocess.run(['patchelf', '--set-interpreter', local_ld, patched_bin])
            subprocess.run(['patchelf', '--set-rpath', '.', patched_bin])  # 修这里: workdir -> .

        return workdir

    def run_in_docker(self, exploit_cmd):
        """在Docker中运行利用脚本"""
        image = self.IMAGE_MAP.get(self.libc_version[:4], 'ubuntu:20.04')
        workdir = self.prepare_exploit()

        docker_cmd = [
            'docker', 'run', '--rm',
            '--name', self.container_name,
            '-v', f'{workdir}:/pwn',
            '-w', '/pwn',
            '--network', 'host',  # 如果远程利用需要网络
            image,
            'bash', '-c', exploit_cmd
        ]

        log.info(f'Running in Docker ({image}): {exploit_cmd}')
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
        return result.stdout, result.stderr

    def cleanup(self):
        """清理临时文件"""
        subprocess.run(['docker', 'rm', '-f', self.container_name],
                       capture_output=True)

# ---- 使用示例 ----
def main():
    # 假设题目文件
    binary = './challenge'
    libc = './libc-2.31.so'
    ld = './ld-2.31.so'

    docker_pwn = DockerPWN(binary, libc, ld)

    # Python exploit 脚本内容
    exploit_script = """
cd /pwn
python3 -c "
from pwn import *
context.arch = 'amd64'
p = process('./challenge_patched')
elf = ELF('./challenge_patched')
libc = ELF('./libc-2.31.so')
log.info(f'system: {hex(libc.symbols[\\\"system\\\"])}')
log.info(f'puts: {hex(libc.symbols[\\\"puts\\\"])}')
log.info(f'str_bin_sh: {hex(next(libc.search(b\\\"/bin/sh\\\")))}')
print('=== Environment OK ===')
p.close()
"
"""
    stdout, stderr = docker_pwn.run_in_docker(exploit_script)
    log.info(f'Output: {stdout}')

    # 如果有真正 exploit 脚本
    # exploit_path = './solve.py'
    # exploit_cmd = f'python3 {exploit_path}'
    # stdout, stderr = docker_pwn.run_in_docker(exploit_cmd)

    docker_pwn.cleanup()

if __name__ == '__main__':
    main()
```

### 5.4 GDB调试工作流

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线GDB调试工作流
结合 pwntools gdb 模块
"""
from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']  # 或 ['gnome-terminal', '--']

def debug_pwn(binary_path, libc_path=None, ld_path=None):
    """调试PWN题的完整设置"""

    # 1. 用patchelf配置
    if ld_path:
        patched = binary_path + '_debug'
        os.system(f'cp {binary_path} {patched}')
        os.system(f'patchelf --set-interpreter {ld_path} {patched}')
        os.system(f'patchelf --set-rpath . {patched}')
        binary_path = patched

    # 2. 设置环境变量
    env = {}
    if libc_path:
        env['LD_PRELOAD'] = os.path.abspath(libc_path)

    # 3. 启动进程
    p = process(binary_path, env=env)

    # 4. 附加GDB
    gdb_commands = """
    # 关键断点
    b *main
    b *0x401234
    # 格式化字符串偏移探测
    # b printf
    # 查看栈
    # stack 30

    # 继续执行
    c
    """

    gdb.attach(p, gdbscript=gdb_commands)

    return p

# ---- 常用GDB命令备忘 ----
GDB_CHEATSHEET = {
    # 栈溢出
    '断点入口': 'b *main',
    '查看栈': 'stack 30',
    '查看寄存器': 'info registers',
    '查看内存': 'x/10gx $rsp',
    '搜索gadget': 'ropper --search "pop rdi"',

    # 堆分析
    '查看堆块': 'vis_heap_chunks',
    '查看bins': 'bins',
    '查看tcache': 'tcache',
    '跟踪malloc': 'b *__libc_malloc',

    # 格式化字符串
    '断点printf': 'b *printf',
    '查看栈内容': 'telescope $rsp 30',

    # 通用
    '单步执行': 'ni (next instruction)',
    '进入函数': 'si (step instruction)',
    '继续执行': 'c (continue)',
    '查看符号': 'info functions',
}

# ---- 远程调试 ----
def debug_remote(host, port):
    """远程调试（需要目标运行 gdbserver）"""
    # gdbserver :1234 ./binary
    p = remote(host, port)
    gdb.attach(('host', 1234))
    return p
```

## 6. 相关知识点

- **栈溢出基础**：ret2libc等利用依赖正确libc版本，见 01-栈溢出基础.md
- **堆利用**：不同glibc版本heap管理机制不同，见 04-堆利用基础.md
- **pwntools**：核心工具库，`ELF`, `process`, `remote`, `gdb`, `ROP`
- **libc-database**：gihub.com/niklasb/libc-database 离线同步方法
- **glibc源码索引**：`malloc.c`, `libio.h`, `dl-runtime.c` 等关键文件
