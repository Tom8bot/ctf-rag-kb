# Linux 提权 / 内网 / AD / API

---

## 1. Linux 提权

## 1.1 开局检查
- 当前用户是谁
- `sudo -l`
- SUID/SGID
- cron
- PATH 劫持
- 环境变量
- 可写脚本/服务文件
- 内核版本（仅 CTF/靶场考虑内核洞）

### 高频命令
```bash
id
whoami
sudo -l
find / -perm -4000 2>/dev/null
crontab -l
cat /etc/crontab
ps aux
ss -tunlp
```

## 1.2 常见提权点
- SUID 程序可利用
- sudo 指定命令可逃逸
- cron 执行可写脚本
- 服务配置可写
- PATH 劫持
- NFS/no_root_squash
- docker 组
- 凭据复用：history、config、ssh key

## 1.3 思维
提权不是只找提权洞，而是找：
```text
高权限进程/任务会读取或执行哪些我可控内容？
```

---

## 2. 内网横向

## 2.1 信息收集
- 网段
- 主机列表
- 凭据
- 共享目录
- 远程管理服务

## 2.2 常见路线
- 一台机上的配置/密码 -> 登录另一台
- 共享目录 -> 脚本/密钥
- 计划任务/登录脚本
- 数据库连接串 / API 密钥

---

## 3. AD 最小知识（CTF 版）

### 3.1 目标
- 枚举域用户/组/机器
- 找高权限账户
- 找可复用凭据或错误委派配置

### 3.2 高频方向
- SMB 共享
- Kerberos 凭据误用
- LDAP 枚举
- WinRM/SMB/PSExec 横向（题目给条件时）

### 3.3 小模型记忆点
AD 题先回答：
1. 我有哪些凭据？
2. 我能访问哪些主机/共享？
3. 哪个账户权限最高？
4. 是否存在“能代表别人认证”的配置错误？

---

## 4. API 安全（CTF 高频）

### 4.1 常见漏洞
- 未授权
- 越权
- JWT 错误
- 参数污染
- mass assignment
- GraphQL introspection
- 调试接口
- 速率限制缺失

### 4.2 Mass Assignment
如果后端把 JSON 自动映射到对象：
```json
{"username":"a","role":"admin"}
```
可能越权写入敏感字段。

### 4.3 参数污染
- 同名参数多个值
- query + body 同名
- JSON 嵌套与扁平参数冲突

---

## 5. 最短作战模板

```text
Linux：先 sudo/SUID/cron/PATH/可写服务/凭据
内网：先找共享、配置、密码、密钥，再横向
AD：先凭据，再枚举域对象，再找高权限关系
API：先未授权/越权/JWT，再看 mass assignment 和参数污染
```
