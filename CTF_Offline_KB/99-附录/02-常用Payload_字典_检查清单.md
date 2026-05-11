# 常用 Payload / 字典 / 检查清单

> 目标不是穷举 payload，而是给出高命中“起手式”。

---

## 1. Web 起手式

### 1.1 SQLi
```text
'
")
' and 1=1 --+
' and 1=2 --+
order by 1
order by 999
union select null
```

### 1.2 SSTI
```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

### 1.3 XSS
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><svg/onload=alert(1)>
```

### 1.4 文件上传
- 改后缀：`.php`, `.phtml`, `.php5`, `.phar`, `.user.ini`
- 改文件名大小写、双后缀、点空格、NTFS 流（Windows 场景）
- MIME / boundary / filename 参数抓包改
- 图片马 / polyglot / 压缩包套娃

### 1.5 SSRF
- 探测：`http://127.0.0.1/`, `http://localhost/`, `http://[::1]/`
- 探测元数据：云环境地址、管理接口、内部面板
- 探测协议支持：`file://`, `gopher://`, `dict://`, `ftp://`

---

## 2. Pwn 起手式
- `file`, `checksec`, `strings`, `ldd`
- cyclic 定位偏移
- 先 leak，后 exploit
- `ROPgadget --binary`
- 先打通本地，再接远程

### 常问自己
- 控制了什么：返回地址？函数指针？GOT？堆指针？
- 缺什么：libc 基址？栈地址？canary？PIE 基址？
- 保护怎么绕：ROP / partial overwrite / leak / fmt / heap

---

## 3. RE 起手式
- `strings -a -n 4`
- 查导入函数：`strcmp`, `memcmp`, `md5`, `AES`, `RSA`, `ptrace`
- 查关键常量：`0x9e3779b9`, AES sbox, MD5 初始向量, RC4 KSA/PRGA
- 先 main，再关键校验函数，再数据区

---

## 4. Crypto 起手式
- 先识别编码：hex/base64/base32/base58
- 看长度：是否是 16/24/32 字节块
- 看字符集：是否全可打印 / 全十六进制 / 大写字母数字
- 想已知前缀：`flag{`, `ctf{`, `0x`, `http`, PNG/PDF/ZIP 头
- 异或先试：单字节、重复 key、已知前缀拖拽

---

## 5. Misc 起手式
- 图片：`file`, `strings`, `exiftool`, `zsteg`, `binwalk`
- 压缩包：`zipinfo`, `7z l`, `binwalk`, CRC, 伪加密
- pcap：协议统计、HTTP/FTP/DNS/SMB，导出对象
- Office/PDF：元数据、对象流、宏、隐藏文本

---

## 6. 小字典

### 6.1 常见参数名
```text
id uid user role admin q s search page sort order file path dir url next redirect callback data debug cmd token key sign api jwt
```

### 6.2 常见敏感文件
```text
/.git/config
/.env
/.DS_Store
/robots.txt
/sitemap.xml
/config.php
/config.yaml
/application.properties
/WEB-INF/web.xml
/.svn/entries
```

### 6.3 常见默认口令（CTF 常见）
```text
admin:admin
admin:123456
root:root
root:toor
test:test
guest:guest
```

---

## 7. 通用检查清单
- [ ] 是否看过源码、注释、JS、robots.txt
- [ ] 是否记录所有参数和鉴权头
- [ ] 是否比较过正常/异常响应长度
- [ ] 是否考虑过二次触发
- [ ] 是否尝试过非预期 content-type / header / cookie
- [ ] 是否考虑过大小写、编码、双写、分块传输
- [ ] 是否有后台任务、导入导出、日志、缓存
- [ ] 是否先泄露再利用
- [ ] 是否保存了脚本与有效 payload
