# SSTI / XSS / 模板与前端漏洞

---

## 1. SSTI（服务端模板注入）

## 1.1 识别
### 高频信号
- 输入内容被“渲染”而不是原样输出
- 出现 `{{ }}`, `${ }`, `<%= %>`, `#{ }`, `{% %}` 这类语法
- 报错中出现 `jinja2`, `twig`, `freemarker`, `velocity`, `erb`, `smarty`

### 最短验证
```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```
- 49 / 计算结果出现，说明表达式被执行

---

## 1.2 常见模板引擎速查
- Python：Jinja2, Tornado, Mako
- PHP：Twig, Smarty
- Java：Freemarker, Velocity, Thymeleaf, Pebble
- Node：EJS, Handlebars, Pug（部分是模板渲染，不一定可直接执行）
- Ruby：ERB

---

## 1.3 利用总纲

```text
指纹识别
-> 确认是否代码执行 or 只允许表达式求值
-> 获取对象/内建/全局变量
-> 访问敏感属性/类/方法
-> 读文件 / 命令执行 / 内存对象搜索
```

### 小模型必须先判断
- 这是 **表达式注入** 还是 **完整代码块注入**？
- 是否有沙箱？
- 能否访问对象属性？
- 结果是否可回显？

---

## 1.4 Jinja2 重点

### 基础探测
```jinja2
{{7*7}}
{{config}}
{{request}}
{{self}}
```

### 常见利用链思路
1. 从已知对象拿类：`obj.__class__`
2. 向上到基类：`.__mro__` / `.__base__`
3. 找子类：`.__subclasses__()`
4. 找可用类/函数后读文件或执行命令

### 通用思维
不是死记某一条固定链，而是：
- **拿对象** → **拿类** → **拿所有类** → **找 file/process/import 能力**

### 常见目标能力
- 文件读：`open`, file class
- 命令执行：`os`, `subprocess`, `popen`
- 模块导入：`__import__`

### 如果 `.`、`_`、`[]`、`{}` 被过滤怎么办？
不要一项项对抗，优先用“通用绕过框架”：
1. **属性访问替代**：`attr()` / `get()` / 过滤器管道
2. **危险 token 外置**：把属性名、模块名放进 GET/POST/header/cookie 里，再通过模板读取
3. **字符串拼接**：`join`, `format`, 字符编码、乘法拼接
4. **从现有对象出发**：`request`, `config`, `url_for`, `cycler`, `namespace` 等
5. **两阶段执行**：先构造字符串，再喂给可执行对象

### 一个通用型绕过思想（比穷举单字符更值钱）
```text
输入点 A：放“危险名字”
模板点 B：仅做属性读取/拼接/调用
```
例如：
- GET 参数里放 `__class__`
- 模板里通过 `attr(request.args.k)` 取属性
- 再层层拼接到目标对象

这类“危险 token 外置”比死记某个单一 payload 更稳。

---

## 1.5 Twig / Smarty / Freemarker / Velocity 速记

### Twig
- `{{7*7}}`
- 看是否能调过滤器、函数、注册扩展

### Smarty
- `{php}` 老版本危险
- 看 `{include}`、`string:`、修饰器、对象方法

### Freemarker
- `${7*7}`
- 高危点：`?new`, `Execute`, `freemarker.template.utility`

### Velocity
- `#set($x=7*7) $x`
- 关注 classloader、反射、工具类

### ERB / EJS
- `<%= 7*7 %>` 常用作探测
- 若能进入代码块，往往可直接 RCE

---

## 1.6 SSTI 常见目标
- 直接读 flag 文件
- 读源码、配置、环境变量
- 执行命令获取 flag
- SSRF / 内网请求（某些模板函数可发请求）
- 沙箱逃逸

---

## 1.7 SSTI 故障排查
- 模板语法不匹配引擎
- 结果被 HTML 转义，看起来没执行
- 进入的是前端模板，不是服务端模板
- 只允许变量替换，不允许表达式求值
- 有黑名单，需要改成属性访问替代 / token 外置 / 字符串拼接

---

## 2. XSS

## 2.1 分类
- 反射型
- 存储型
- DOM 型
- Self-XSS（CTF 中偶尔会伪装）
- Mutation XSS / 模板注入转 XSS

## 2.2 上下文识别
XSS 不要只记 payload，要先判断你在哪个上下文：
1. HTML 文本节点
2. HTML 属性值
3. JS 字符串
4. JS 表达式
5. URL 上下文
6. CSS 上下文

### 最短验证起手式
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><svg/onload=alert(1)>
```

---

## 2.3 常见 sink
### 服务端输出到前端
- innerHTML
- outerHTML
- document.write
- eval / setTimeout(string)
- location / hash / search 直接拼进 HTML / JS
- iframe srcdoc
- dangerouslySetInnerHTML
- jQuery html(), append(), after()

---

## 2.4 DOM XSS 解题法
1. 找 source：`location`, `document.URL`, `document.cookie`, `postMessage`, storage
2. 找 sink：`innerHTML`, `eval`, `Function`, `document.write`
3. 找中间变换：decodeURIComponent / replace / regex
4. 构造适合当前上下文的 payload

---

## 2.5 过滤绕过总纲

### 不要穷举字符过滤，而要按层处理
1. **换上下文**：从文本节点切到属性，或从属性切到标签闭合
2. **换事件**：`onerror/onload/onfocus/onclick/onanimationstart`
3. **换标签**：`svg`, `img`, `math`, `iframe`, `details`
4. **换触发机制**：自动触发 / 用户触发 / DOM 重组触发
5. **编码变换**：HTML entity、URL 编码、双编码、大小写混淆
6. **利用浏览器解析差异**：不规范闭合、容错解析、协议处理

### 如果 `<script>` 被过滤
- 走事件处理器
- 走 SVG/IMG
- 走 `javascript:`（上下文允许时）
- 走 DOM sink，构造字符串拼接执行

### 如果引号被过滤
- 找无引号属性写法
- 切换到标签体
- 用模板字符串或转义方式进入 JS

### 如果尖括号被过滤
- 说明可能不是 HTML 上下文，而是 JS/URL/CSS
- 优先打断当前上下文而不是硬插标签

---

## 2.6 常见利用目标（CTF）
- 直接 alert 拿分
- 读管理员 cookie / localStorage（题目允许时）
- 伪造管理员操作
- 配合 CSRF / SSRF / 缓存投毒
- 打后台 bot 访问拿 flag

### Bot 场景重点
- 题目通常会给一个“管理员访问”或 report bot
- 你的目标可能不是弹窗，而是：
  - 让 bot 请求你指定路径
  - 读取页面中隐藏 flag
  - 把内容发回你的接收端或同源接口

---

## 2.7 CSP 绕过思维
### 先看 CSP 允许什么
- `script-src 'self'`
- nonce/hash
- 是否允许 inline、data、blob、unsafe-eval

### 常见路线
- JSONP / 同源脚本复用
- 已存在函数调用链
- DOM XSS 不依赖内联脚本
- 上传文件到同源再加载

---

## 3. CSRF / Clickjacking / 前端逻辑漏洞

## 3.1 CSRF
### 条件
- 浏览器自动带认证
- 目标接口无 token / token 可预测 / token 不校验源

### 关注点
- GET 改状态
- POST 但 token 漏检
- JSON 接口是否可通过表单 / 特殊 content-type 打到

## 3.2 Clickjacking
- 页面未设置 `X-Frame-Options` / `frame-ancestors`
- 可诱导点击敏感按钮

## 3.3 前端鉴权
- 按钮隐藏不代表后端鉴权
- JS 里写 role / admin 只是展示控制
- 修改前端状态、localStorage、接口参数常有收获

---

## 4. 原型链污染（前端 / Node）

### 信号
- 合并对象、深拷贝、`Object.assign`, `merge`, `lodash`
- 传入 JSON 中的 `__proto__`, `constructor`, `prototype`

### 效果
- 污染全局对象属性
- 影响鉴权、模板渲染、XSS、RCE（Node 场景）

### 验证
```json
{"__proto__":{"isAdmin":true}}
```
- 看后续对象是否出现意外属性

---

## 5. GraphQL / 前端接口泄露
- schema introspection
- 未鉴权字段
- debug 接口
- source map 暴露源码
- JS 里泄露 API key、路由、管理员接口、对象结构

---

## 6. 最短作战模板

```text
1. 先判断是服务端模板还是前端渲染
2. SSTI 先测算术；XSS 先判断上下文
3. 若被过滤，不逐字符死磕，改走“属性替代 / token 外置 / 字符串拼接 / 上下文切换”
4. 成功执行后优先拿源码、配置、flag，而不是追求复杂链条
5. 若是 bot 题，目标改为“让 bot 帮你取值或触发接口”
```
