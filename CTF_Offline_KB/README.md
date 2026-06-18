# CTF 离线知识库 (CTF Offline Knowledge Base)

> **专为 CTF 断网/受限场景设计 · 面向小参数模型增强 · RAG 就绪格式**

---

## 1. 项目概述

本知识库是一套**结构化、模块化、可检索**的 CTF（Capture The Flag）竞赛专业知识体系，共包含 **98 个 RAG 格式知识文件**，总计 **51,800+ 行**，覆盖 CTF 竞赛八大核心方向（含漏洞POC专项库）。

### 1.1 构建背景与目的

在实际 CTF 竞赛（尤其是线下赛、攻防演练、红蓝对抗）中，参赛者常面临以下挑战：

| 挑战 | 传统解决方案 | 本知识库方案 |
|------|-------------|------------|
| **断网/离线环境** | 依赖在线文档和搜索引擎 | 本地离线结构化知识库 |
| **小参数模型能力不足** | 使用云端大模型 API | RAG 增强检索，降低推理门槛 |
| **知识碎片化** | 散落在博客/Writeup/GitHub | 统一格式、系统化整理 |
| **时间压力** | 临场搜索效率低 | 按主题+难度预索引，快速定位 |
| **工具缺失** | 需联网安装 | 涵盖离线工具链及安装策略 |

**核心目标**：构建一个在断网受限条件下，可通过本地 RAG（Retrieval-Augmented Generation）系统注入小参数模型，从而显著提升模型专业解题能力的专业知识库。

### 1.2 适用场景

- **线下 CTF 竞赛（AWD / Jeopardy）**：快速检索漏洞 Payload 和利用模板
- **红蓝对抗演练**：渗透方法论和提权技术参考
- **安全教学与培训**：系统化学习 CTF 各方向知识
- **AI 辅助解题系统**：作为 RAG 知识源，提升本地小模型（3B-7B）的专业问答质量

---

## 2. 知识库结构

```
CTF_Offline_KB/
├── README.md                         ← 本文件
├── 00-方法论/           (12 文件)     ← CTF 通用方法论与工具链
├── 01-WEB/              (12 文件)     ← Web 安全
├── 02-PWN/              (12 文件)     ← 二进制漏洞利用
├── 03-RE/               (12 文件)     ← 逆向工程
├── 04-CRYPTO/            (12 文件)     ← 密码学
├── 05-MISC/              (12 文件)     ← 杂项安全
├── 06-渗透与网络/        (12 文件)     ← 渗透测试与网络攻防
└── 07-漏洞POC/           (14 文件)     ← 已知高危漏洞POC库
```

---

## 3. 各模块详情

### 3.1 `00-方法论` — CTF 通用方法论与基础设施 (12 文件, 8,801 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | CTF竞赛类型与解题思维框架 | 入门 | Jeopardy/AWD/红蓝对抗赛制、五步解题法、决策树 |
| 02 | 离线环境搭建与工具预装策略 | 中级 | Kali/Docker/Python/Node 离线包制作、U盘部署、完整性验证 |
| 03 | 信息收集与侦察方法论 | 入门 | 分阶段扫描策略、指纹识别、JS端点发现 |
| 04 | 给AI小模型的提示词工程 | 中级 | 小模型行为特点、5种Prompt模板、输出质量评估 |
| 05 | Linux命令行速查与高级技巧 | 入门 | grep/sed/awk三剑客、管道组合、curl/nc/socat |
| 06 | Python脚本模板与常用库 | 中级 | pwntools/requests/Crypto模板、Web/Pwn/CRYPTO四类脚本 |
| 07 | 调试与故障排除方法论 | 中级 | strace/ltrace/gdb/pdb四层体系、Pwn调试工作流 |
| 08 | 版本控制与解题笔记管理 | 入门 | Git分支策略、笔记模板、Writeup规范 |
| 09 | 时间管理与题目优先级策略 | 入门 | 决策矩阵、24h规划、时间陷阱 |
| 10 | 编码与进制转换速查 | 入门 | Base家族/URL/Hex/Morse工具类、多层嵌套解码 |
| 11 | 网络协议基础与抓包分析 | 中级 | Wireshark过滤语法、Scapy分析脚本、USB键盘分析 |
| 12 | 密码学数学基础速查 | 中级 | 模运算/欧拉定理/CRT、RSA攻击集合、SageMath/Sympy速查 |

### 3.2 `01-WEB` — Web 安全 (12 文件, 4,245 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | SQL注入全解 | 入门→高级 | 联合查询/布尔盲注/时间盲注/报错注入/堆叠注入/二阶注入 |
| 02 | XSS与前端漏洞 | 中级 | 反射/存储/DOM型/CSP绕过/PostMessage/原型链污染/CSRF |
| 03 | 服务端模板注入SSTI | 中级 | Jinja2/Flask/Twig/Smarty/FreeMarker/Node.js模板引擎 |
| 04 | 文件上传漏洞 | 中级 | 前端/后端绕过/.htaccess/条件竞争/图片马/解析漏洞 |
| 05 | 文件包含与路径穿越 | 中级 | LFI/RFI/php伪协议/Session包含/log注入/proc利用 |
| 06 | 反序列化漏洞 | 高级 | PHP POP链/Java ysoserial/Fastjson/Python pickle/Node.js |
| 07 | SSRF与XXE注入 | 中级 | 内网探测/云元数据/gopher-dict协议/Blind XXE OOB |
| 08 | 命令注入与代码注入 | 中级 | 空格/关键词绕过/DNS-HTTP外带/disable_functions突破 |
| 09 | 认证鉴权与逻辑漏洞 | 中级 | JWT攻击/OAuth/IDOR/Session Fixation/条件竞争 |
| 10 | 框架与中间件漏洞 | 高级 | Struts2/Spring/ThinkPHP/Shiro/Log4j/Nginx/Tomcat CVE |
| 11 | Node.js与JavaScript原型链污染 | 高级 | 原型链原理/EJS-Pug-RCE/lodash利用/vm沙箱逃逸 |
| 12 | WAF绕过技术汇总 | 高级 | 分块传输/HTTP走私/编码绕过/参数污染 48种绕过 |

### 3.3 `02-PWN` — 二进制漏洞利用 (12 文件, 4,406 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | 栈溢出基础 | 入门 | ret2text/ret2shellcode/ret2libc/32位vs64位调用约定 |
| 02 | ROP链构造技术 | 中级 | ROPgadget/ret2syscall/栈迁移pivot/csu万能gadget |
| 03 | 格式化字符串漏洞 | 中级 | printf泄露/任意地址写/GOT覆写/%n技术 |
| 04 | 堆利用基础 | 中级 | ptmalloc/fastbin/tcache/unsorted_bin |
| 05 | 堆利用进阶 | 高级 | House of Force/Spirit/Orange/Einherjar/tcache stashing |
| 06 | 整数溢出与off-by-one | 中级 | 整数溢出类型/null byte poisoning/堆结合利用 |
| 07 | SROP与SigreturnFrame利用 | 高级 | SigreturnFrame/SROP链/32-64位对比 |
| 08 | 沙箱绕过与ORW | 高级 | seccomp分析/open-read-write/sendfile替代 |
| 09 | IO_FILE利用 | 高级 | FSOP/House of Orange/vtable劫持/House of Apple |
| 10 | 内核PWN基础 | 高级 | LKM/ret2usr/KPTI绕过/modprobe_path |
| 11 | PWN环境搭建与调试 | 入门 | patchelf/glibc多版本/Docker隔离/GDB调试 |
| 12 | 保护机制与绕过 | 中级 | ASLR/PIE/NX/Canary/RELRO/FORTIFY全集 |

### 3.4 `03-RE` — 逆向工程 (12 文件, 4,698 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | 逆向工程总纲与工具链 | 入门 | IDA/Ghidra/x64dbg/r2离线安装与核心用法 |
| 02 | C/C++程序逆向基础 | 入门 | 调用约定/控制流恢复/数据结构识别/编译器优化模式 |
| 03 | 静态分析技术与IDA高级技巧 | 中级 | FLIRT签名/IDAPython/交叉引用/类型恢复/微码分析 |
| 04 | 动态调试技术 | 中级 | x64dbg/gdb/Frida/硬件断点/条件断点/Trace分析 |
| 05 | 反调试与反逆向技术对抗 | 高级 | PEB检测/API检测/时间检测/TLS/Linux ptrace/ScyllaHide |
| 06 | 常见算法逆向与识别 | 中级 | AES/DES/RC4/TEA/ChaCha20/SM4/MD5/SHA256/压缩算法特征 |
| 07 | Python与.NET逆向 | 中级 | pyc反编译/PyInstaller/dnSpy/de4dot/混淆对抗 |
| 08 | Go与Rust二进制逆向 | 高级 | Go运行时/pclntab符号恢复/Rust名称修饰/数据结构特征 |
| 09 | 加壳与脱壳技术 | 中级 | OEP查找(ESP/内存/API断点)/Scylla/IAT修复/各壳特征 |
| 10 | 虚拟机保护与混淆 | 高级 | Ollvm控制流平坦化/VM保护/Unicorn模拟/去混淆策略 |
| 11 | 安卓逆向基础 | 中级 | APK结构/Smali/Frida/Objection/Native SO/ARM64指令 |
| 12 | 符号执行与约束求解 | 高级 | angr模板/Z3约束求解/SimProcedure/Veritesting |

### 3.5 `04-CRYPTO` — 密码学 (12 文件, 6,040 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | 古典密码与编码 | 入门 | 凯撒/维吉尼亚/栅栏/培根/Base家族/弗里德曼检验 |
| 02 | 现代密码学基础与SageMath环境 | 入门 | 数论基础/SageMath离线安装/有限域/CRT/Hensel提升 |
| 03 | RSA攻击全解 | 中级 | 因式分解/共模/低指数/维纳/Coppersmith/Franklin-Reiter 9种攻击 |
| 04 | 离散对数与椭圆曲线密码 | 高级 | ECC/Pohlig-Hellman/ECDSA nonce重用/无效曲线攻击 |
| 05 | 分组密码与模式攻击 | 中级 | AES ECB/CBC/CTR/Padding Oracle/字节翻转/CBC-MAC篡改 |
| 06 | 流密码与随机数生成器 | 中级 | LCG/MT19937克隆/RC4偏差/LFSR/BM算法/OTP重用 |
| 07 | 哈希攻击 | 中级 | 长度扩展/Magic Hash/生日攻击/HMAC绕过 |
| 08 | 格密码基础与LLL算法 | 高级 | 背包密码/LLL攻击/Babai CVP/隐藏数问题/NTRU |
| 09 | XOR与数学构造题 | 中级 | XOR分析/Z3约束求解/差分分布表/S-Box逆向 |
| 10 | 侧信道与非常规攻击 | 高级 | 时序攻击/缓存攻击/DPA/模板攻击/AES DFA |
| 11 | 多方计算与同态加密入门 | 高级 | Shamir秘密共享/OT/Paillier/混淆电路 |
| 12 | 量子与后量子密码基础 | 高级 | Shor/Grover算法/BB84/LWE/NTRU/PQC标准化 |

### 3.6 `05-MISC` — 杂项安全 (12 文件, 5,454 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | 图片隐写全解 | 入门→中级 | LSB/EXIF/IHDR/PNG结构/JPEG DCT/BMP/GIF帧分离 |
| 02 | 音频与视频隐写 | 中级 | 频谱隐写/MP3/波形分析/DTMF/SSTV慢扫描电视 |
| 03 | 压缩包与文件格式分析 | 中级 | ZIP结构/伪加密/明文攻击/CRC碰撞/7z/RAR |
| 04 | 流量分析 | 中级 | Wireshark/USB流量/HTTPS解密/协议还原/无线流量 |
| 05 | 内存取证 | 中级 | Volatility/进程分析/注册表/文件提取/hibfile |
| 06 | 磁盘取证与文件恢复 | 中级 | MBR/GPT/文件系统/数据恢复/FAT32/NTFS/Ext4 |
| 07 | 编码与解码大全 | 入门 | Base家族/Morse/ASCII/Unicode/URL/HTML实体/Punycode |
| 08 | OSINT开源情报搜集 | 入门 | 社交媒体/图像地理位置/域名WHOIS/Google Dork |
| 09 | 二维码与条码技术 | 入门 | QR Code/Data Matrix/PDF417/损坏修复/手绘识别 |
| 10 | 日志分析与电子取证 | 中级 | Windows事件日志/Linux syslog/APT攻击痕迹 |
| 11 | 非常规隐写技术 | 高级 | Base64隐写/空格TAB隐写/零宽字符/Unicode隐写 |
| 12 | 游戏与PWN-MISC交叉 | 中级 | 游戏存档篡改/Cheat Engine/Unity/存档解密 |

### 3.7 `06-渗透与网络` — 渗透测试与网络攻防 (12 文件, 7,798 行)

| 编号 | 文件 | 难度 | 核心内容 |
|------|------|------|----------|
| 01 | 渗透测试方法论与MITRE ATT&CK | 中级 | PTES/OSSTMM/ATT&CK框架映射/CTF适配 |
| 02 | 信息收集与侦察 | 入门 | Nmap高级用法/Masscan/DNS枚举/被动信息收集 |
| 03 | Web应用渗透 | 中级 | gobuster/ffuf/Burp/SQL/文件包含/SSTI |
| 04 | 常见服务漏洞利用 | 中级 | SMB/FTP/SSH/Redis/MySQL/MongoDB/NFS/SNMP |
| 05 | Linux权限提升 | 高级 | SUID/Capabilities/Cron/内核漏洞/sudo/GTFOBins |
| 06 | Windows权限提升 | 高级 | 服务提权/令牌窃取/UAC绕过/PrintSpoofer/Potato |
| 07 | 内网横向移动 | 高级 | PsExec/WMI/哈希传递/票据传递/Chisel代理/隧道 |
| 08 | 域渗透基础 | 高级 | LDAP/BloodHound/Kerberos/Golden Ticket/DCSync |
| 09 | 后渗透与持久化 | 高级 | C2框架/持久化(Linux+Windows)/免杀基础 |
| 10 | 密码攻击与凭证收集 | 中级 | Hashcat/John/Mimikatz/LSAMdump/DPAPI/凭证收集 |
| 11 | 网络协议攻击 | 中级 | ARP欺骗/DNS投毒/LLMNR/DHCPv6/Responder/NTLM中继 |
| 12 | 应急响应与日志清除 | 中级 | Windows/Linux痕迹清理/应急响应/A/D防守加固 |

### 3.8 `07-漏洞POC` — 已知高危漏洞POC库 (14 文件, 10,394 行)

| 编号 | 文件 | CVE | 难度 | 核心内容 |
|------|------|-----|------|----------|
| 01 | Log4j-JNDI注入 | CVE-2021-44228 | 中级 | Log4Shell、JNDI/LDAP/RMI链、离线检测脚本 |
| 02 | Spring-Framework-RCE | CVE-2022-22965 | 高级 | Spring4Shell、BeanWrapper利用、WAR部署 |
| 03 | Apache-Shiro-RememberMe | CVE-2016-4437 | 高级 | Shiro-550/721、AES-CBC/GCM、无依赖利用链 |
| 04 | Fastjson反序列化 | 多CVE (1.2.24~1.2.80) | 高级 | autotype绕过史、JNDI/JDBC RCE、dnslog检测 |
| 05 | Confluence-OGNL注入 | CVE-2022-26134 | 中级 | OGNL沙箱绕过、无认证RCE、各版本检测 |
| 06 | Exchange-ProxyShell | CVE-2021-34473等 | 高级 | SSRF→EWS→RCE链、邮箱服务器利用 |
| 07 | Apache-APISIX-RCE | CVE-2022-24112 | 中级 | Admin API JWT绕过、批处理路由注入 |
| 08 | GitLab-RCE | CVE-2021-22205 | 高级 | ExifTool-DjVu链、文件上传触发RCE |
| 09 | F5-BIG-IP-iControl | CVE-2022-1388 | 中级 | X-F5-Auth-Token绕过、Bash命令注入 |
| 10 | ThinkPHP多版本RCE | 多CVE (5.0/5.1/6.x) | 中级 | invokeFunction/Request链、中国CTF高频 |
| 11 | Weblogic-T3-IIOP | CVE-2020-2555等 | 高级 | T3/IIOP协议、Coherence链、7个CVE覆盖 |
| 12 | CICD漏洞集合 | Zabbix/Jenkins/Nexus | 中级 | 采样命令注入、Script Console利用、仓库投毒 |
| 13 | SpringCloud生态 | Nacos/Seata/Gateway | 中级 | 微服务认证绕过、JWT密钥硬编码、配置中心 |
| 14 | Grafana文件读取 | CVE-2021-43798 | 入门 | 路径穿越读/etc/passwd、Token泄露、插件漏洞 |

---

## 4. RAG 知识文档格式规范

每个知识文件遵循统一的结构化格式，便于 RAG 系统解析和检索：

```yaml
---
category: "知识子类"          # 细粒度分类
tags: ["标签1", "标签2"]     # 多标签，便于交叉检索
difficulty: "入门/中级/高级"  # 难度分级
---
```

### 正文六大模块

| 模块 | 说明 |
|------|------|
| **1. 概述** | 知识点定义、适用场景、在 CTF 中的定位 |
| **2. 核心原理** | 底层机制、数学基础、协议规范 |
| **3. 关键技巧/检测方法** | 可操作命令、PayLoad 模板、Python脚本、工具使用 |
| **4. 常见误区与注意事项** | 易错点、坑位、规避方法 |
| **5. 实战示例** | 1-2 个完整场景操作示例（含代码/命令） |
| **6. 相关知识点** | 交叉引用本知识库内其他相关文件 |

---

## 5. 使用指南

### 5.1 直接查阅

按目录结构打开对应方向的 Markdown 文件，利用编辑器的全文搜索功能快速定位。

### 5.2 RAG 系统集成

本知识库设计时已考虑与 RAG 系统的对接，推荐工作流：

```
用户提问 → RAG检索器(chunk-level) → 召回Top-K相关片段 → 
LLM推理(7B以下本地模型) → 生成专业答案
```

**推荐检索参数**：
- Chunk Size: 256-512 tokens（匹配每个文件的章节粒度）
- Embedding Model: BGE-M3 / text2vec-large-chinese（中文语义适配）
- Top-K: 5-8（覆盖多维度信息）
- 检索策略: Hybrid Search (BM25 + Dense)

### 5.3 小模型增强策略

针对 3B-7B 参数规模的模型，建议：

1. **Prompt 前缀注入**：在 System Prompt 中加入 "你是CTF竞赛解题专家..." 角色设定
2. **Chain-of-Thought 引导**：要求模型 "先分析题目类型，再给出利用步骤，最后提供Payload"
3. **Few-Shot 示例库**：从本知识库中提取2-3个典型示例作为上下文
4. **多轮交互**：首轮检索获取宏观方向，次轮细化到具体利用方式

### 5.4 离线环境部署

```bash
# 1. 将整个知识库目录复制到离线设备
cp -r CTF_Offline_KB/ /target/offline_machine/

# 2. 离线环境下使用 grep 快速检索
grep -r "SQL注入" CTF_Offline_KB/ --include="*.md" -l

# 3. 配合终端 Markdown 阅读器查看
mdcat CTF_Offline_KB/01-WEB/01-SQL注入全解.md
```

---

## 6. 技术指标

| 指标 | 数值 |
|------|------|
| **总文件数** | 98 |
| **总行数** | 51,836 |
| **覆盖方向** | 8 大 CTF 核心领域 |
| **细分子主题** | 98 个 |
| **语言** | 简体中文 |
| **格式** | Markdown + YAML Front Matter |
| **代码示例** | 300+ 可运行脚本/命令 |
| **难度分布** | 入门 30% / 中级 45% / 高级 25% |

---

## 7. 版本与维护

- **版本**: v1.1 (2026-06-18)
- **构建方式**: 多 Agent 并行构建，每模块由独立 Agent 负责
- **更新策略**: 随 CTF 竞赛技术演进持续更新
- **贡献方式**: 按 RAG 格式规范新增或修订知识文件

---

## 8. 许可证

本知识库内容仅供安全学习、教学和合法 CTF 竞赛使用。任何未授权的恶意攻击行为均与本项目无关。

---

> **Built with ❤️ for CTF Players & AI Researcher**
> 
> *"在断网的世界里，知识就是你最强的武器。"*
