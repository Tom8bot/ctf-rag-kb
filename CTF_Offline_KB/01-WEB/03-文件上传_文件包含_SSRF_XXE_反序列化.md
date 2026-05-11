# 文件上传 / 文件包含 / SSRF / XXE / 反序列化

---

## 1. 文件上传

## 1.1 识别
- 有上传点、头像、导入、附件、压缩包、图片处理
- 前端检查后缀/MIME，但后端逻辑未知
- 上传成功后返回路径、文件名、ID 或下载地址

## 1.2 目标类型
1. 直接 WebShell / 脚本执行
2. 上传后被包含
3. 上传后被解析（二次处理、图片库、压缩解包）
4. 覆盖配置文件
5. 构造 polyglot / phar / zip 套路

## 1.3 绕过总纲
### 不要只记“某后缀被过滤怎么办”，要按校验层分类
1. **前端校验**：抓包改包即可
2. **后缀校验**：双后缀、大小写、替代后缀、尾点、空格、NTFS 特性（Windows）
3. **MIME 校验**：改 `Content-Type`
4. **内容校验**：加合法文件头、图片马、polyglot
5. **路径校验**：目录穿越、文件名覆盖、竞争条件
6. **访问限制**：换解析路径、下载点、包含点、日志点触发

## 1.4 常见后缀思路
- PHP：`.php`, `.phtml`, `.php5`, `.phar`, `.user.ini`
- JSP：`.jsp`, `.jspx`
- ASP：`.asp`, `.aspx`, `.cer`

## 1.5 典型利用路线
### 路线 A：直接执行
上传脚本文件 -> 找到访问路径 -> 触发执行

### 路线 B：配置覆盖
上传 `.user.ini` / `.htaccess` / 应用配置文件 -> 改解释器或 auto_prepend_file

### 路线 C：上传后包含
上传文本/图片马 -> 通过 LFI/include 读取并执行

### 路线 D：解压 / 预处理
上传 zip/tar/image -> 服务端解压或图像处理时触发目录穿越 / 命令执行 / XML 解析

## 1.6 常见排障
- 上传成功但访问 404：路径不对、CDN/对象存储、重命名
- 访问下载而非执行：目录只做静态托管，需找包含点
- 文件内容被改写：图片处理、杀毒、转码
- 小马不执行：PHP 短标签/引擎关闭、脚本解释器不同

---

## 2. 文件包含 / 路径遍历 / 任意文件读

## 2.1 识别
- `file=`, `path=`, `page=`, `template=`, `lang=`
- 页面功能像“加载模板/下载文件/预览日志”
- 输入像文件名、主题名、语言包、模块名

## 2.2 类型
- LFI：本地文件包含
- RFI：远程文件包含（老题常见）
- 路径遍历：`../`
- 任意文件读：下载接口直接读路径

## 2.3 常见目标
- `/etc/passwd`
- Web 源码
- 配置文件、数据库密码
- 日志文件
- session 文件
- 环境变量、容器挂载目录

## 2.4 利用升级思路
### 从 LFI 到 RCE
1. 包含日志（日志投毒）
2. 包含 session
3. 包含上传文件
4. 包含 `/proc/self/environ`
5. PHP 包装器：`php://filter`, `php://input`, `data://`, `zip://`, `phar://`

### PHP 包装器高频
- 源码读取：
```text
php://filter/convert.base64-encode/resource=index.php
```
- POST 体执行（旧题型/特定 include 场景）：`php://input`
- data 伪协议直接注入内容：`data://text/plain,<?php ...?>`

## 2.5 路径穿越绕过总纲
- URL 编码 / 双编码
- 多层目录嵌套
- 点点斜杠变形
- 绝对路径
- Windows 盘符与反斜杠
- 截断老技巧（历史题）

### 通用思维
不是记某个固定 `....//`，而是：
- 看后端如何标准化路径
- 看是否先过滤再拼接
- 看是否只替换一次

---

## 3. SSRF

## 3.1 识别
- 功能会“代表你去访问某 URL”
- 常见点：头像抓取、Webhook、站点截图、PDF 生成、富文本导入、图片代理、分享预览

## 3.2 最短验证
- `http://127.0.0.1/`
- `http://localhost/`
- `http://[::1]/`
- 一个你可控的本地监听或伪目标（CTF 环境）

## 3.3 SSRF 利用总图
```text
确认可回连
-> 识别支持协议
-> 探测本机/内网/管理接口
-> 判断是否可读响应
-> 若可控原始请求，再尝试 gopher 等高级协议
```

## 3.4 常见目标
- 本机管理面板
- 内网 web / redis / memcached / docker / metadata
- 仅内网开放的 flag 服务

## 3.5 绕过思路
### 地址绕过
- 127.0.0.1 / localhost / IPv6 / 十进制 / 八进制 / 十六进制 / 短地址
- 域名解析到内网
- 重定向跳内网
- DNS rebinding（题目允许时）

### 协议绕过
- `http`, `https`, `file`, `gopher`, `dict`, `ftp`
- 某些题只过滤了 `http://127.0.0.1` 这种字面值

### 验证要点
- 是否跟随 30x
- 是否回显响应体
- 是否限制端口
- 是否限制 Host/header

## 3.6 gopher 思维（高频 CTF）
- 若可以发原始 TCP 文本，则可打 Redis、FastCGI、HTTP 原始包
- 关键不是背整串 payload，而是理解：
  - `gopher://host:port/_<urlencoded_raw_bytes>`
  - 你要自己构造底层协议内容

---

## 4. XXE

## 4.1 识别
- 接口接受 XML / SVG / Office 文档 / SOAP
- 报错含 parser、doctype、entity
- 文件导入、图片处理、配置导入很常见

## 4.2 最短验证
```xml
<?xml version="1.0"?>
<!DOCTYPE a [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<a>&xxe;</a>
```

## 4.3 利用方向
- 读本地文件
- 内网探测（外部实体请求）
- OOB 外带
- 配合特定解析器打 SSRF / DOS

## 4.4 绕过与变体
- 参数实体 `%xxe;`
- 外部 DTD
- SVG / DOCX / XLSX / PPTX / xsl 间接触发
- 若禁止 DOCTYPE，看是否有 XInclude

## 4.5 XInclude
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## 5. 反序列化

## 5.1 识别
- 参数长得像序列化对象：PHP `O:`, Java base64 blob, Python pickle 字节串
- 提示词里出现 session、rememberMe、cache、queue、signed cookie
- 有 `unserialize`, `readObject`, `pickle.loads`, `yaml.load`, `jsonpickle.decode`

## 5.2 利用核心
### 不要只背 gadget 链，要先判断三件事
1. **格式是什么**：PHP / Java / Python / Ruby / Node
2. **对象是否可控**
3. **有没有可达危险方法**：析构、唤醒、字符串化、比较、模板渲染、命令执行

## 5.3 PHP 反序列化
### 高频魔术方法
- `__wakeup`
- `__destruct`
- `__toString`
- `__call`
- `__invoke`

### 解题思路
- 看源码中的类
- 找魔术方法
- 找属性可控链
- 拼对象图触发到危险 sink

### 常见 sink
- `eval`, `system`, `include`, `file_put_contents`, `unlink`, `assert`

## 5.4 PHAR 反序列化
### 条件
- 服务端对用户可控文件执行文件函数：`file_exists`, `is_file`, `exif_imagetype`, `getimagesize`, `fopen` 等
- 路径可以是 `phar://...`

### 思路
上传带 metadata 的 phar/polyglot -> 某文件操作函数触发 metadata 反序列化

## 5.5 Java 反序列化
- `readObject`, `XMLDecoder`, Hessian, Fastjson/Jackson 某些链
- 重点看依赖与已知 gadget；CTF 通常会给可利用依赖或自定义类

## 5.6 Python / Pickle / YAML
- `pickle.loads` 基本高危
- `yaml.load` 老版本危险
- `__reduce__` 是关键点

## 5.7 常见排障
- 你构造的对象类在目标环境不存在
- 触发方法不是当前调用路径会走到的
- 有签名 / HMAC / 加密保护
- 只有反序列化，没有回显；需要副作用型利用

---

## 6. 一题多链思维
很多 Web 题并不是单漏洞，而是：
- 上传 + LFI
- SSRF + Redis/FastCGI
- XXE + 文件读
- 反序列化 + 文件写 + 包含
- 日志投毒 + LFI
- phar + 文件函数触发

### 优先找“闭环”
```text
输入点 -> 可落地载荷 -> 触发点 -> 回显点
```

---

## 7. 最短作战模板

```text
上传：先确认校验层，再判断执行/包含/配置覆盖哪条路最短
包含：先读源码和配置，再考虑日志/session/上传联动转 RCE
SSRF：先本机与内网，再协议与重定向，再原始请求能力
XXE：先 file 读取，再看是否能 OOB / XInclude
反序列化：先找格式、类、魔术方法、sink，再谈 gadget
```
