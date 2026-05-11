# 格式化字符串 / 整数溢出 / IO_FILE / 内核基础

---

## 1. 格式化字符串

## 1.1 识别
- `printf(buf)`、`fprintf(stream, buf)` 这类直接把用户输入当格式串
- 输入 `%p` `%x` `%s` `%n` 有效果

## 1.2 能力
- 任意地址读：`%s`, `%p`, 指定参数位
- 任意地址写：`%n`, `%hn`, `%hhn`
- 泄露 canary / libc / 栈 / PIE

## 1.3 最短验证
```text
%p.%p.%p.%p
```
- 若输出多个地址，说明成立

## 1.4 找偏移
```python
for i in range(1, 30):
    payload = f'%{i}$p'.encode()
```
- 找到你的输入在第几个参数位

## 1.5 任意读
### 思路
把目标地址放到 payload 里，再用 `%n$s` 读取。

### 例
```python
payload = flat(target_addr) + b'%7$s'
```

## 1.6 任意写
### 思路
使用 `%n/%hn/%hhn` 写已输出字符数到指定地址。

### pwntools
```python
payload = fmtstr_payload(offset, {addr: value})
```

### 常见目标
- GOT 表
- `__free_hook`
- 返回地址
- `.fini_array`
- 全局标志位 `is_admin`

## 1.7 分段写
- 大值常拆成 2 字节或 1 字节写
- 注意输出字节数递增问题

---

## 2. 整数漏洞

## 2.1 类型
- signed/unsigned 转换
- 整数溢出/下溢
- 截断（int -> short / char）
- 长度计算错误

## 2.2 常见利用方式
- 绕过长度检查导致堆/栈溢出
- 负数变超大正数
- `malloc(size)` 分配过小，后续读写过大
- 数组索引越界

## 2.3 识别点
- `if (len < 0x100)` 但后面类型变化
- `read(fd, buf, user_len)` 与分配长度不一致
- `count * size` 乘法溢出

### 通用思维
不要只盯“这里能溢出”，要看 **整数是否最终影响了内存大小、索引、次数或权限判断**。

---

## 3. IO_FILE / FSOP 基础

## 3.1 适用场景
- libc 较老或题目特意给了相关结构
- 已有任意写 / 堆溢出 / chunk overlap
- 传统 hook 不能用时

## 3.2 关键对象
- `_IO_FILE`
- `_IO_list_all`
- vtable
- `_IO_2_1_stdin_`, `_IO_2_1_stdout_`, `_IO_2_1_stderr_`

## 3.3 常见目标
- 劫持 stdout 泄露
- 伪造 FILE 结构，触发执行链
- 配合 `overflow`, `xsputn`, `finish` 等虚表函数

## 3.4 小模型记忆重点
不强行背每个版本结构偏移，而记：
1. 先确认 libc 版本
2. 看是否能控制 FILE 结构体关键字段
3. 看触发点：`puts/printf/exit/flush`
4. 选择泄露型或执行型利用

---

## 4. 栈上格式串 + 栈溢出联动
- 格式化先 leak canary / libc / PIE
- 再栈溢出做 ret2libc

### 这是非常高频的组合题路线
```text
fmt -> leak
bof -> pwn
```

---

## 5. Partial RELRO 下 GOT 劫持

### 常见链
- 改 `printf@got -> system`
- 再输入 `/bin/sh`

### 条件
- Partial RELRO
- 可任意写
- 程序后续会调用被改的函数

### 注意
- Full RELRO 下 GOT 常不可写

---

## 6. 栈迁移到格式串写返回地址
- fmt 可直接写返回地址
- 或先写某全局指针，再触发间接调用
- 若写 8 字节困难，则拆成 `%hn/%hhn`

---

## 7. 内核 Pwn 基础观念（CTF 入门级）

> 这里只做 CTF 视角的最小知识，重点是识别题型，不展开复杂真实内核细节。

## 7.1 常见题型
- 越界读写 kernel object
- UAF
- tty/seq_operations/pipe_buffer 等对象覆写
- userfaultfd race
- modprobe_path
- cred 提权

## 7.2 核心目标
- 泄露内核基址（KASLR）
- 任意读写
- 覆盖函数指针 / ROP
- `commit_creds(prepare_kernel_cred(0))`
- 或覆写 `modprobe_path`

## 7.3 必备知识点
- SMEP：内核不能执行用户态代码
- SMAP：内核不能随便访问用户态内存
- KPTI：用户态/内核态页表隔离，返回用户态需要处理 `swapgs_restore_regs_and_return_to_usermode`

### 小模型要点
看到 kernel pwn，不要慌，先回答：
1. 泄露点是什么？
2. 任意写/读怎么实现？
3. 走 cred 链还是 modprobe_path？
4. 是否要考虑 SMEP/SMAP/KPTI？

---

## 8. 竞争条件 / race 基础

### 常见场景
- 双线程同时 free / open / rename / check-use
- userfaultfd 卡住页错误制造时间窗

### 思维
- TOCTOU：检查和使用之间可被修改
- 多次触发同一路径，观察对象状态错乱

---

## 9. 最小利用策略总结

### 格式串题
```text
先找偏移 -> leak -> 看是否可写 -> 改 GOT/返回地址/标志位
```

### 整数题
```text
找类型转换 -> 看影响大小/索引/次数 -> 转成 OOB/UAF/Overflow
```

### IO_FILE 题
```text
确认 libc 版本 -> 能控哪些 FILE 字段 -> 看触发点 -> 泄露或执行
```

### 内核题
```text
先 leak KASLR -> 任意写/ROP -> 提权或改 modprobe_path -> 安全返回用户态
```

---

## 10. 故障排查
- `%n` 写失败：地址含坏字节、偏移不对、输出字节数没算对
- `%s` 读取崩溃：目标地址不可读
- GOT 改了没效果：函数没再调用 / Full RELRO
- kernel 提权后仍失败：返回用户态姿势错、SMEP/SMAP 未处理
