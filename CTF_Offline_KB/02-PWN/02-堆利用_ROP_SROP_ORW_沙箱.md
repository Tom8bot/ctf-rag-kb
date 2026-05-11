# 堆利用 / ROP / SROP / ORW / 沙箱

---

## 1. 堆题识别

### 高频菜单
- add / create
- edit / update
- delete / free
- show / print

### 高频漏洞
- UAF（use after free）
- double free
- off-by-one / off-by-null
- chunk overlap
- tcache poisoning
- unsorted bin leak
- house of 系列

### 开局必做
- 看 glibc 版本
- 看每个菜单对 malloc/free/read 的具体行为
- 记录 chunk 大小、索引复用规则、free 后是否置空

---

## 2. glibc 版本观念

### 2.1 glibc 2.23 以前/左右
- fastbin, unsorted bin, small/large bin 常见
- `__malloc_hook`, `__free_hook` 可利用价值高

### 2.2 glibc 2.26+
- 引入 tcache
- 许多题核心是 tcache poisoning

### 2.3 glibc 2.32+
- safe linking
- tcache fd 指针被异或保护，需泄露堆地址或构造可逆关系

> 小模型必须先回答：**这题是什么 glibc，安全机制到哪一代？**

---

## 3. 堆基础概念

### 3.1 chunk 常见字段
- `prev_size`
- `size`
- `fd`
- `bk`

### 3.2 常见 bin
- tcache
- fastbin
- unsorted bin
- small bin
- large bin

### 3.3 关键目标
- 泄露 libc
- 泄露 heap
- 构造任意地址写
- 劫持 hook / vtable / 返回地址 / 关键函数指针

---

## 4. UAF / double free / tcache poisoning

## 4.1 UAF
### 特征
- free 后还能 show/edit
- free 后指针未置空

### 常见用途
- show 已释放 chunk -> 泄露 fd / bk -> leak heap/libc
- edit 已释放 chunk -> 篡改 freelist 指针

## 4.2 double free
### 价值
- 重复把同一 chunk 放入 freelist
- 可构造任意地址分配

### tcache poisoning 核心思路
1. free 某 chunk
2. 篡改其 next/fd 为目标地址
3. 再次 malloc 同尺寸
4. 返回到目标地址处，实现任意写

### 目标地址常见
- `__free_hook`
- `__malloc_hook`（老版本）
- `tcache_perthread_struct`
- 全局指针数组
- `.bss` 上函数指针

---

## 5. unsorted bin leak

### 思路
大 chunk free 到 unsorted bin 后，其 fd/bk 通常指向 main_arena，借此泄露 libc。

### 常见做法
- free 一个较大 chunk
- show 其内容（若 UAF）
- 取出指针并减去 main_arena 偏移得 libc 基址

---

## 6. safe linking 绕过思维

### 公式印象
tcache/fastbin 单链表指针常见形如：
```text
stored_fd = real_fd ^ (heap_addr >> 12)
```

### 这意味着
- 需要堆地址泄露
- 或可利用已知 chunk 地址反推出真实 fd

### 小模型不要死记具体公式版本差异，而要记：
**新题经常需要先 leak heap，再 poison tcache。**

---

## 7. hook 利用与替代目标

## 7.1 `__free_hook`
### 常规链
- 改 `__free_hook = system`
- 再 free 一个内容为 `/bin/sh` 的 chunk

### 适用
- 老版本 libc / hooks 存在
- 可任意写

## 7.2 `__malloc_hook`
- 老版本常见，一次 malloc 触发

## 7.3 新版替代目标
- `_IO_list_all`
- vtable
- exit handlers
- return address（结合栈泄露）
- `.fini_array`
- tcache struct / 全局函数指针

> 题目越来越多地不让你走传统 hook，要学会“任意写后找最近可触发控制点”。

---

## 8. ROP 总纲

### 8.1 gadget 目标
- 控 `rdi`
- 控 `rsi`
- 控 `rdx`
- 控 `rax`
- 执行 `syscall`

### 8.2 常见链
- ret2libc
- ret2syscall
- open-read-write（ORW）
- mprotect + shellcode
- ret2dlresolve
- ret2csu

### 8.3 gadget 不够怎么办
- `__libc_csu_init`
- SROP
- ret2dlresolve
- 栈迁移到更大空间

---

## 9. ORW

### 适用场景
- seccomp 禁止 `execve`
- 但允许 `open/read/write`
- 目标只是读 flag 文件，不一定要 shell

### 经典链
```text
open("flag", 0)
read(fd, buf, size)
write(1, buf, size)
```

### 关键前提
- 能写字符串 `flag\x00`
- 能控制相关寄存器
- 已知 syscall 号/plt 函数

### 优势
- 比起 getshell，CTF 中更稳，因为目标只是拿 flag

---

## 10. SROP

### 条件
- 可触发 `syscall`
- 能控制栈上一块 fake sigreturn frame
- 常有 `rax=15` 或办法设置成 `rt_sigreturn`

### 用途
- 一次性控制大量寄存器
- gadget 很少时非常强

### 典型思维
1. 先让 `rax=15`
2. 执行 `syscall`
3. 内核把栈上的伪 frame 当信号上下文恢复
4. 你获得几乎全寄存器控制

### 常用于
- execve
- mprotect + shellcode
- ORW

---

## 11. ret2dlresolve

### 适用场景
- 没有 system
- libc 版本未知
- 可以调用 `read` 往可写段布置伪结构

### 核心思路
欺骗动态链接器在运行时解析你想要的符号，比如 `system`。

### 重点
- 需要一定栈空间
- 需要对 ELF 动态解析结构有基本理解
- pwntools 有辅助模板，但先理解“伪造 relocation/sym/string 表项”

---

## 12. 沙箱 seccomp

### 12.1 检测
- `prctl(PR_SET_SECCOMP, ...)`
- `seccomp-tools dump ./pwn`
- 题目描述提“只能用部分 syscall”

### 12.2 常见限制模型
- 只允许 `read/write/open`
- 禁止 `execve`
- 禁止 `open` 但允许 `openat`
- 只允许非常少量 syscall

### 12.3 绕过策略
1. **目标降级**：从 getshell 改为读 flag
2. **找替代 syscall**：`openat` 替代 `open`
3. **SROP / ROP 精确调用允许的 syscall**
4. **利用现有已打开 fd**
5. **用程序原有函数完成文件读取**

---

## 13. 堆题做题模板

### 13.1 最常见路线
```text
UAF/double free
-> leak libc / heap
-> tcache poisoning / overlap
-> 任意写
-> 改 hook / 函数指针 / 返回地址
-> 触发
```

### 13.2 记录模板
```text
idx 与 chunk 地址关系：
每个 size 进入哪个 bin：
free 后是否可 show/edit：
已拿到的 leak：
可写目标：
最终触发点：
```

---

## 14. 故障排查

### 14.1 tcache poisoning 不生效
- size 不匹配
- safe linking 未处理
- 目标地址不满足对齐
- malloc 次数顺序错

### 14.2 leak 不稳定
- 读到的是用户数据不是链表指针
- 程序清空了 chunk
- libc 版本偏移不匹配

### 14.3 hook 改了也没 shell
- libc 新版移除了对应 hook 或约束不同
- free 的不是 `/bin/sh` chunk
- system 地址算错
- 远程 libc 不同

### 14.4 seccomp 下 getshell 失败
- `execve` 被禁
- 该改用 ORW 而不是 system

---

## 15. 最短作战模板

```text
1. 确定 glibc 版本与安全机制
2. 先找 UAF / double free / off-by-one
3. 先 leak，再任意写
4. 老版本优先 hook，新版本优先返回地址/函数指针/IO_FILE
5. 有 seccomp 时优先 ORW
6. gadget 少时考虑 ret2csu / SROP / ret2dlresolve
```
