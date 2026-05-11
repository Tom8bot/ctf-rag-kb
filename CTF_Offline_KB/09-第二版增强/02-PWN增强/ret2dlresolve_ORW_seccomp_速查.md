# ret2dlresolve / ORW / seccomp 速查

> 目标：补齐“ROP 不只 system('/bin/sh')”这一块，尤其适用于开启 seccomp、无现成 system、无 easy gadget 的题。

---

## 1. ORW 思想

### 什么时候优先 ORW
- seccomp 禁止 `execve`
- 题目只需要读 flag 并输出
- libc 不稳 / one_gadget 不稳 / system 不可用

### 核心调用链
- `open/openat`
- `read`
- `write`

### 关键问题
1. flag 路径放哪
2. fd 从哪来
3. 寄存器怎么布置
4. 有没有现成 syscall gadget 或 libc 调用链

---

## 2. seccomp 题的处理顺序

1. 判断是否有 seccomp
2. 判断允许哪些 syscall
3. 若 `execve` 不允许，直接转 ORW
4. 若 `open` 不允许，看 `openat` 或已有 fd
5. 若 `read/write` 受限，看 `sendfile`, `writev` 等替代

### 统一原则
**不要执着起 shell，目标是拿 flag。**

---

## 3. ret2dlresolve

### 什么时候想
- 没有 system
- 没有足够 libc 泄露
- 程序是动态链接
- 可控栈与若干 ROP gadget 足够

### 本质
伪造动态解析所需结构，让动态链接器帮你解析一个原本没直接导入的符号。

### 适合场景
- 32 位经典题非常常见
- 64 位也会出，但实现细节更复杂

### 解题顺序
1. 确认程序动态链接
2. 确认有 plt0 / reloc / symtab 等结构可借用
3. 伪造 relocation / symbol / string
4. 让解析流程跳到你想要的函数

---

## 4. setcontext / 栈迁移

### 为什么重要
当 hook 不可用、gadget 不整齐、需要大规模布置寄存器时，`setcontext` 或栈迁移非常强。

### 适用场景
- 有任意写
- 可控制某个指针到伪造上下文
- 需要一次性恢复大量寄存器

---

## 5. 比赛优先级

### 情况 A：有 libc、无 seccomp
- 常规 ROP / system / one_gadget

### 情况 B：有 seccomp
- 先 ORW

### 情况 C：无 libc 泄露但动态链接
- 看 ret2dlresolve

### 情况 D：有大块任意写
- 看 setcontext / 栈迁移 / SROP

---

## 6. 常见误区
- 看到 pwn 就只想 `system('/bin/sh')`
- seccomp 题里还在硬凑 shell
- ret2dlresolve 不会就完全放弃无 libc 泄露题
- 不把 ORW 当默认备胎
