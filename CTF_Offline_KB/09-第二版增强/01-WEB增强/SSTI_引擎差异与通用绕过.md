# SSTI 引擎差异与通用绕过

> 目标：把 SSTI 从“会几条 payload”升级为“能快速识别引擎、能在过滤条件下构造稳定利用链”。

---

## 1. 题型识别

### 常见现象
- 页面回显模板表达式结果：`{{7*7}} -> 49`
- 报错中出现模板引擎名：Jinja2、Twig、Smarty、Freemarker、Velocity、Thymeleaf
- 某个参数被拼进页面、邮件模板、PDF 模板、CMS 模板
- 表达式、标签、占位符风格明显：
  - `{{ ... }}`：Jinja2/Twig/Vue/Angular/Handlebars 等
  - `${ ... }}` / `${ ... }`：Freemarker / EL / Thymeleaf / Spring
  - `<#assign ...>`：Freemarker
  - `#{ ... }`：部分 EL / Spring / Thymeleaf 变体

### 与 XSS 的区别
- XSS 常出现在浏览器端执行 JS
- SSTI 是服务端模板先解析后返回结果
- 如果 `{{7*7}}` 直接显示为原文，多半不是服务端求值
- 如果返回 `49`、报模板错、对象属性值，则优先 SSTI

---

## 2. 最短识别流程

### 通用探测顺序
1. 算数：`{{7*7}}`、`${7*7}`、`<%= 7*7 %>`
2. 报错：构造不闭合表达式观察异常页
3. 对象探测：`{{config}}`、`{{request}}`、`${T(java.lang.Runtime)}`
4. 模板专属语法：
   - Jinja2: `{{cycler}}`
   - Twig: `{{_self}}`
   - Freemarker: `<#assign x=1>${x}`
   - Velocity: `#set($x=1)$x`

### 快速判断引擎

| 特征 | 倾向引擎 |
|---|---|
| `{{7*7}}=49` 且 Python 对象风格 | Jinja2/Tornado |
| `${7*7}=49` 且 Java 报错栈 | EL / Freemarker / Thymeleaf |
| `{{_self}}` 有意义 | Twig |
| `<#list>` / `<#assign>` 可执行 | Freemarker |
| `#set($x=1)` 可执行 | Velocity |

---

## 3. 按引擎的核心利用思路

## 3.1 Jinja2 / Flask

### 基本思路
Jinja2 最核心的利用不是死记子类下标，而是：

**从模板上下文对象 -> Python 对象系统 -> `__globals__` / `__builtins__` / `os` / `subprocess` -> 文件读写或命令执行。**

### 稳定利用骨架
1. 进入对象系统
2. 找到函数对象
3. 取 `__globals__`
4. 访问 `os` 或 `__builtins__`
5. 调 `popen` / `open`

### 常见目标对象
- `config`
- `request`
- `url_for`
- `get_flashed_messages`
- `cycler`
- `joiner`
- `namespace`
- `self`

### 通用思路比死背 payload 更重要
例如：
- 从 `request.application` 往 Flask app 走
- 从函数对象进入 `__globals__`
- 从类层级进入 `__mro__` / `__subclasses__`

### 版本不稳定点
- `__subclasses__()[index]` 的下标跨环境变化很大
- 因此优先：
  - 用名字找对象
  - 用全局对象找模块
  - 用函数 `__globals__` 进 `os`

### 过滤绕过总思路
目标不是一项一项枚举被过滤字符，而是找**替代表达能力**：

#### 如果 `.` 被过滤
- 用 `[]`
- 用 `attr()`
- 用过滤器链

#### 如果 `[]` 被过滤
- 用 `attr()`
- 用 `|map(attribute=...)`
- 用 request 参数拼接

#### 如果 `_` 被过滤
- 不直接写双下划线，改为：
  - 编码/拼接/格式化生成属性名
  - 通过请求参数传输敏感字符串
  - 利用模板内置对象的已有能力绕过

#### 如果 `{{` / `}}` 被过滤
- 尝试控制块、行语句、其他模板入口
- 寻找二次渲染
- 寻找 `{% include %}`、邮件模板、错误页模板、管理端模板

### 通用高鲁棒性思路
比起记住某个具体 payload，更应该掌握下面的套路：

1. **参数外带敏感名字**
   - 模板里只负责拼接和索引
   - 敏感字符串如 `__class__`、`__globals__`、`os`、`popen` 从 GET/POST/header/cookie 带入

2. **多跳属性访问替代直接写链**
   - 一步只取一个对象
   - 避免长链被 WAF 特征命中

3. **以文件读为第一目标**
   - 先读 flag、配置、源码
   - 命令执行往往不是第一需要

4. **利用错误回显做枚举**
   - 看看哪些对象存在
   - 看哪些过滤器可用
   - 看表达式求值范围

### Jinja2 通用利用优先级
1. 文件读
2. 读配置/secret key
3. session 伪造
4. SSTI 到任意 Python 代码执行
5. 横向找源码、数据库配置、内网地址

---

## 3.2 Twig / PHP

### 核心思路
- 看是否能访问 `_self`、环境对象、扩展函数
- 看是否能调用已注册函数、filter、include
- 看是否有 sandbox 配置缺陷
- 看能否结合 PHP 本身危险函数或框架 gadget

### 优先点
- `dump`、`include`、`source`
- `registerUndefinedFilterCallback`
- 模板加载器路径操控
- 本地文件读取与模板包含

---

## 3.3 Freemarker / Java

### 常见强利用点
- `Execute`、`ObjectWrapper`、`?new`
- Spring 环境中的 Bean 获取
- 类加载、反射、命令执行

### 识别特征
- `${...}`
- `<#assign ...>`
- Java 报错栈
- `freemarker.template` 字样

### 利用优先级
1. 对象泄露
2. 类反射
3. 获取 Runtime / ProcessBuilder
4. 文件读写 / 命令执行

---

## 3.4 Velocity

### 关键点
- `#set`、`$class`、反射
- 工具类暴露时可直接利用
- Java 反射链与 Runtime 获取是重点

---

## 3.5 Thymeleaf / Spring EL

### 关键点
- `__${...}__`、`${...}`、`*{...}`
- Spring 环境中常可借 `T(java.lang.Runtime)` 等方式
- 模板表达式有时在 URL、header、fragment、参数绑定中触发

### 优先目标
- 环境变量泄露
- Bean 访问
- Runtime/ProcessBuilder
- 读取配置和源码

---

## 4. 通用绕过框架

## 4.1 过滤绕过不是“字符对抗”，而是“表达能力重建”

当题目过滤了 `.`、`_`、`[`、`]`、`{{`、`}}`、`class`、`os`、`import` 等，优先这样思考：

1. 有没有**替代语法**访问属性
2. 有没有**外部输入**可帮我拼接敏感字符串
3. 有没有**现成对象**能直达危险能力
4. 有没有**二次解析**/二次模板渲染
5. 有没有**文件读**代替 RCE

## 4.2 五类高价值绕过策略

### A. 拼接
- 字符串连接
- request 参数拼接
- header/cookie/value 分段重组

### B. 编码
- hex / unicode / URL 编码
- 字符函数构造
- join/format/replace 组合

### C. 间接访问
- `attr()`、过滤器、map/select
- 对象方法返回对象
- 函数全局变量

### D. 入口迁移
- 从正文注入转移到邮件模板、后台模板、错误模板、导出模板
- 从显式模板注入转移到二次渲染

### E. 目标降级
- 拿不到 RCE 就先文件读
- 拿不到文件读就先对象/环境变量泄露
- 拿不到泄露就先确认引擎和可达对象

---

## 5. 比赛中最实用的操作顺序

1. 算数确认是否 SSTI
2. 判断引擎
3. 枚举上下文对象
4. 先做文件读
5. 再看是否需要 RCE
6. 遇 WAF 就改走：拼接 / 间接访问 / 参数外带 / 二次渲染
7. 如果链太长，改为脚本自动枚举对象和属性

---

## 6. 自动化思路

### 6.1 自动识别模板引擎
- 维护一组探测表达式
- 根据响应变化和报错关键词打分

### 6.2 自动对象枚举
- 枚举常见上下文名
- 枚举过滤器/函数可用性
- 对异常页做关键词抽取

### 6.3 自动构造敏感属性名
- 对 `__class__`、`__globals__`、`__builtins__`、`__mro__`、`__subclasses__` 做多种拼接策略

---

## 7. 常见误区

- 死背 `__subclasses__()[40]` 一类固定下标
- 上来就追求 RCE，不先拿文件读和源码
- 没有区分前端模板和后端模板
- 只会在 `{{...}}` 里打，不会寻找二次渲染入口
- 把过滤绕过理解成“一个字符一个字符对抗”而不是“换语义表达”

---

## 8. 速查结论

### Jinja2
- 最稳思路：**上下文对象 -> 函数全局 -> builtins/os -> 文件读/命令执行**
- 最稳绕过：**参数外带敏感名字 + 分段取属性 + 优先文件读**

### Java 模板
- 最稳思路：**表达式 -> 反射/类访问 -> Runtime/ProcessBuilder**
- 最稳绕过：**先对象泄露，再找类能力，再命令执行**

### PHP 模板
- 最稳思路：**模板函数 / include / source / sandbox 缺陷 / 框架链**

---

## 9. 赛中提问模板

- `这是 Jinja2，能执行算数，过滤了 .,_,[,],{{,}}，目标读 /flag，优先给通用绕过框架，不要固定下标。`
- `这是 Freemarker，有 <#assign>，给出从对象泄露到 Runtime 的最短路线。`
- `这是 Twig，报 sandbox 错，应该优先看哪些对象和函数。`
