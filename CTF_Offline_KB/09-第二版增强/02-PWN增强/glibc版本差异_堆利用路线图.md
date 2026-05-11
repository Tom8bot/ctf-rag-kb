# glibc 版本差异与堆利用路线图

> 目标：解决一个常见问题：会很多堆漏洞名词，但比赛里一旦换 glibc 版本就不会选路线。本文把“漏洞原语 -> 版本特性 -> 候选打法”串起来。

---

## 1. 先不要急着打，先判定这 5 件事

1. glibc 版本大致是多少
2. 有哪些原语：UAF / double free / off-by-one / overflow / arbitrary free / edit after free
3. 有没有泄露：heap / libc / stack / PIE
4. 能否申请到大 chunk、小 chunk、可控次数
5. 程序有没有额外限制：
   - 只能分配固定大小
   - 只能 free 一次
   - show 截断
   - null byte 限制
   - seccomp / sandbox

---

## 2. 版本分段记忆

## 2.1 glibc 2.23 及以前
### 特征
- fastbin / unsorted bin 经典时代
- 没有 tcache
- unlink、fastbin attack、house of spirit 等思路更常见

### 高优先级打法
1. unsorted bin 泄露 libc
2. fastbin dup
3. unlink / consolidate 相关
4. house of force / top chunk 相关
5. IO_FILE 在某些题里仍然很强

## 2.2 glibc 2.26 - 2.31
### 特征
- 引入 tcache
- 小块分配/释放优先走 tcache
- 很多老题会变成 tcache poisoning / tcache dup

### 高优先级打法
1. tcache 泄露/投毒
2. 结合 unsorted bin 拿 libc
3. 再考虑 fastbin/largebin 辅助
4. 有 UAF 时先想 tcache entry 篡改

## 2.3 glibc 2.32+
### 特征
- safe-linking 出现
- 单链表指针异或保护
- 直接 tcache poisoning 门槛提高

### 高优先级打法
1. 先拿 heap leak
2. 再解 safe-linking
3. 继续做 tcache/fastbin 投毒
4. 或转向 unsorted/largebin / 其他元数据利用

## 2.4 glibc 2.34+
### 特征
- hook 类目标减少，传统 `__malloc_hook` / `__free_hook` 路线弱化甚至不可用
- 需要更多考虑：
  - FSOP / IO_FILE
  - exit handlers
  - ROP
  - setcontext / ORW
  - 栈迁移

---

## 3. 以“漏洞原语”选路线

## 3.1 UAF
### 最优先问自己
- free 后还能 edit 吗
- free 后还能 show 吗
- free 后能否再次 alloc 到同一块

### 典型用途
- 泄露 tcache/fd 指针
- 改写 freelist 指针
- 改写 chunk size / next 指针
- 构造重叠块

### 路线优先级
1. show after free -> 泄露
2. edit after free -> poisoning
3. UAF + 可控申请大小 -> 重叠 / 劫持目标指针

## 3.2 double free
### 旧版本
- 直接 fastbin dup / tcache dup 很强

### 新版本
- 要关注重复释放检查、key 检查、安全链
- 常需要借助 UAF 修改 key 或做更复杂堆布局

## 3.3 off-by-one / null byte overflow
### 关键用途
- 改 size
- 清 prev_inuse
- 伪造合并条件
- 打造 overlap

### 题中高频价值
不是“立刻 getshell”，而是**制造重叠块和可控读写**。

## 3.4 arbitrary free
### 用途
- 把任意地址送入 bin 体系
- 配合伪 chunk、伪 arena、伪 metadata
- 某些题里可直接转向控制全局对象或栈附近结构

---

## 4. 泄露优先级

## 4.1 libc 泄露
### 常见来源
- unsorted bin bk/fd
- main_arena 附近
- GOT / puts 回显
- FILE 结构

## 4.2 heap 泄露
### 为什么越来越重要
- safe-linking 后，很多链必须先知道 heap 基址
- 题中常通过 UAF show、打印 chunk 内容、tcache 指针泄露获得

## 4.3 stack 泄露
### 作用
- ROP
- 栈迁移
- 覆盖返回地址或保存寄存器附近结构

---

## 5. 目标不再只盯 hook

很多选手一看到 libc base 就只想 `__free_hook=system`。这是旧思路。

### 现代题更常见目标
1. `__free_hook` / `__malloc_hook`（老版本可用时）
2. `setcontext` 相关控制流转移
3. `_IO_FILE` / FSOP
4. rtld / exit handlers
5. 栈地址 + ROP / ORW
6. 程序函数指针 / vtable / 全局对象

---

## 6. seccomp / sandbox 下的思路

### 如果不能 `execve`
优先转成：
- ORW（open/read/write）
- `openat`, `read`, `write`, `sendfile`
- 直接读 flag 文件并回显

### 如果系统调用受限
- 先用 `seccomp-tools` 或题面推断允许 syscall
- 看能否借已有 fd
- 看能否通过 `/proc/self/fd`、标准输入输出旁路

---

## 7. 一张比赛路线图

### 场景 A：glibc 2.31 + UAF + show
1. 泄露 heap/libc
2. tcache poisoning
3. 劫持可写目标
4. 若 hook 可用，尝试 hook
5. 若 hook 不稳，转 ROP / setcontext / FSOP

### 场景 B：glibc 2.35 + UAF + safe-linking
1. 先 heap leak
2. 解链指针
3. 做 tcache poisoning 或 overlap
4. 目标优先考虑栈 / FILE / 退出流程

### 场景 C：只有 off-by-one
1. 打 size
2. 造 overlap
3. 做任意读写
4. 再求 libc / stack leak
5. 最后控流

---

## 8. 常见误区
- 不先确认版本就套打法
- 一有 libc 就机械打 `__free_hook`
- safe-linking 环境下还把旧版 tcache poisoning 当默认路线
- 不重视 heap leak
- 不把“做 overlap”当作核心中间目标

---

## 9. 赛中提问模板

- `glibc 2.31，菜单堆题，有 UAF+show，如何按优先级选择 tcache/unsorted/hook/ROP 路线？`
- `glibc 2.35，有 safe-linking，只有 edit-after-free，优先如何拿 heap leak 并继续？`
- `只有 off-by-one null byte，没有直接泄露，如何先造 overlap？`
