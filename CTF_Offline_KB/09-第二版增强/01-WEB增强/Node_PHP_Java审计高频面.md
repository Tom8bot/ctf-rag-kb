# Node / PHP / Java 审计高频面

> 目标：把 Web 审计从“漏洞名词”转成“按语言生态找危险边界”。

---

## 1. Node.js

## 1.1 高频危险面
- 原型链污染
- 模板引擎（EJS/Pug/Handlebars/Nunjucks）
- `child_process` 相关命令执行
- 文件上传与路径拼接
- NoSQL 注入（Mongo）
- SSRF / URL 解析差异
- 反序列化 / unsafe merge

## 1.2 一眼该看的地方
- `Object.assign`, `merge`, `lodash.merge`, 深拷贝
- `eval`, `Function`, `vm`
- `exec`, `execSync`, `spawn`, `fork`
- `res.render`, `compile`, `template`
- `JSON.parse` 之后直接 merge 到配置/对象

## 1.3 题中高频模型
### A. 原型链污染 -> 配置污染 -> RCE/鉴权绕过
### B. 模板渲染 -> SSTI
### C. 文件路径拼接 -> 任意文件读
### D. Mongo 查询对象可控 -> NoSQL 注入

---

## 2. PHP

## 2.1 高频危险面
- 文件包含 / 伪协议
- 反序列化 / 魔术方法
- 弱类型比较
- 文件上传
- 命令执行
- session / Phar / 自动加载
- 框架 gadget 链

## 2.2 一眼该看的函数/机制
- `include`, `require`, `include_once`
- `unserialize`
- `eval`, `assert`, `preg_replace /e`（老版本）
- `system`, `exec`, `passthru`, 反引号
- `file_get_contents`, `fopen`, `move_uploaded_file`
- `__wakeup`, `__destruct`, `__toString`, `__call`, `__invoke`

## 2.3 高频题型
### A. 反序列化 + POP 链
### B. 文件包含 + 伪协议 + 日志/session/上传文件包含
### C. 弱比较 `==` / hash magic
### D. Phar 反序列化侧触发

---

## 3. Java

## 3.1 高频危险面
- 反序列化
- EL / SSTI
- Spring/Spring Boot 配置和路由
- SpEL
- 文件上传、路径穿越
- JDBC / SQL 注入
- Jackson / Fastjson 风险点（题里常被简化）

## 3.2 一眼该看的类和功能
- Controller / RequestMapping
- 模板引擎：Thymeleaf / Freemarker / Velocity
- `Runtime.exec`, `ProcessBuilder`
- 反射和类加载
- `ObjectInputStream`
- `JdbcTemplate`, ORM 拼接查询

## 3.3 高频题型
### A. SpEL / SSTI 到 RCE
### B. 反序列化 gadget
### C. 路径穿越与任意文件读
### D. Spring 误配置导致 Actuator / debug 泄露

---

## 4. 审计统一框架

### 先找四类边界
1. 输入进入点
2. 解释执行边界（模板、脚本、表达式、序列化）
3. 文件系统边界
4. 系统命令 / 网络请求 / 数据库边界

### 然后问四个问题
1. 用户输入是否能改变对象结构
2. 用户输入是否能改变解释器语义
3. 用户输入是否能控制路径/主机/命令
4. 用户输入是否能跨越身份或资源边界

---

## 5. 赛中速查
- Node：优先看原型链、模板、命令执行、NoSQL
- PHP：优先看反序列化、包含、弱类型、上传
- Java：优先看 SpEL/SSTI、反序列化、Spring 配置、路径问题
