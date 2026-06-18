---
category: "密码学"
tags: ["SageMath", "现代密码学", "数学基础", "Python密码学", "离线工具", "数论", "有限域", "CTF环境"]
difficulty: "入门"
---

# 现代密码学基础与 SageMath 离线环境

## 1. 概述

现代密码学建立在坚实的数学基础之上，核心依赖数论、代数、概率论等分支。CTF 密码学题目中，熟练掌握数学工具是解题的关键。SageMath（原名 Sage）是一个集成了 GAP、PARI/GP、Singular、NTL 等数十个开源数学库的 Python 风格系统，是密码学 CTF 选手最重要的离线工具。

本章重点：
- 现代密码学所需的数学基础知识
- SageMath 离线环境搭建与核心 API
- Python 原生密码学库的使用
- 断网环境下的解题工作流

## 2. 核心原理（含数学推导）

### 2.1 群论基础

群 (G, *) 满足：封闭性、结合律、单位元、逆元。

密码学中常见的群：
- **(Z_n, +mod n)**：模 n 加法群
- **(Z_n^*, xmod n)**：模 n 乘法群（n 的缩剩余系）
- **椭圆曲线群 (ECC)**：点加群

群的阶 (order) 和元素的阶对于 Pohlig-Hellman 攻击至关重要。

### 2.2 环与域

- **环 (Ring)**：带两个运算的代数结构
- **域 (Field)**：非零元都有乘法逆的交换环
- **有限域 GF(p^n)**：元素个数为素数幂的域

有限域上的多项式运算在 AES、椭圆曲线中无处不在：
`GF(2^8) = GF(2)[x]/(x^8 + x^4 + x^3 + x + 1)`

### 2.3 数论核心定理

**欧拉定理**：若 gcd(a, n) = 1，则 a^{phi(n)} = 1 (mod n)

**费马小定理**（欧拉定理特例）：若 p 为素数，则 a^{p-1} = 1 (mod p)

**中国剩余定理 (CRT)**：
给定两两互素的模数 n1, n2, ..., nk，同余方程组 x = ai (mod ni) 在 mod N = prod(ni) 下有唯一解：
`x = sum(ai * Mi * yi) mod N`
其中 Mi = N/ni，yi = Mi^{-1} mod ni

**二次剩余**：若存在 x 使 x^2 = a (mod p)，则 a 是 mod p 的二次剩余。
Legendre 符号 `(a/p) = a^{(p-1)/2} mod p`，值为 1 表示剩余，-1 表示非剩余，0 表示 a | p。

### 2.4 模运算关键概念

- **模逆**：`a^{-1} mod n` 存在当且仅当 gcd(a,n)=1，用扩展欧几里得求
- **原根**：生成整个 Z_p^* 的元素 g
- **离散对数**：给定 g^a = h mod p，求 a（困难问题，ECC 安全性基于此）

## 3. 关键技巧/攻击方法（含 Python 代码）

### 3.1 SageMath 离线环境搭建

**Windows 离线安装**：
1. 在有网络环境下载 [SageMath Installer](https://www.sagemath.org/download.html)
2. 复制安装包到离线环境
3. 安装后将 `sage` 命令加入 PATH
4. 验证：`sage -c "print(123^456)"`

**Linux 离线安装**：
```bash
# 方法1：使用 AppImage（推荐）
chmod +x sage-*.AppImage
./sage-*.AppImage

# 方法2：从 conda 安装
conda create -n sage sage -c conda-forge
conda activate sage
```

**核心第三方 Python 库**（断网前预装）：
```bash
pip install pycryptodome gmpy2 sympy z3-solver
```

### 3.2 SageMath 核心 API 速查

```python
# ==== 基本数论 ====
factor(123456789)                    # 因数分解
is_prime(2^127-1)                    # 质数检测
next_prime(10^20)                    # 下一个质数
gcd(123, 456)                        # 最大公因数
lcm(12, 18)                          # 最小公倍数
euler_phi(100)                       # 欧拉 phi 函数
divisors(100)                        # 所有因子

# ==== 模运算 ====
inverse_mod(7, 26)                   # 模逆 7^(-1) mod 26
Mod(2^100, 101)                      # 快速模幂
crt([1,2,3], [2,3,5])              # 中国剩余定理
primitive_root(7)                    # 原根
discrete_log(Mod(5, 23), Mod(2, 23)) # 离散对数

# ==== 矩阵 ====
A = Matrix([[1,2],[3,4]])
A.inverse()                          # 矩阵逆
A.rref()                             # 行简化阶梯形
A.det()                              # 行列式
A.charpoly()                         # 特征多项式

# ==== 多项式 ====
R.<x> = PolynomialRing(GF(2))        # GF(2) 上的多项式环
f = x^7 + x^3 + 1
f.factor()                           # 因式分解
f.roots()                            # 求根

# ==== 椭圆曲线 ====
E = EllipticCurve(GF(p), [a, b])     # 定义椭圆曲线 y^2 = x^3 + ax + b
ord = E.order()                      # 曲线阶
G = E.gens()[0]                      # 生成元
Q = k * G                            # 点乘
```

### 3.3 使用 Python + gmpy2 实现核心运算

```python
import gmpy2
from gmpy2 import mpz, is_prime, next_prime, invert, gcd, lcm

def crt_solve(residues, moduli):
    """Python 实现中国剩余定理"""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for ai, mi in zip(residues, moduli):
        Mi = M // mi
        xi = invert(Mi, mi)  # Mi^(-1) mod mi
        x = (x + ai * Mi * xi) % M
    return x

# 示例
print(crt_solve([2, 3, 2], [3, 5, 7]))  # 输出 23

def hensel_lifting(f, p, k):
    """Hensel 提升：从 mod p 的解提升到 mod p^k"""
    # f 为多项式，p 为素数，k 为目标指数
    solutions = []
    # 先找 mod p 的解
    for x0 in range(p):
        if f(x0) % p == 0:
            # 逐次提升
            x = mpz(x0)
            pk = mpz(1)
            for i in range(1, k):
                pk *= p
                # d = -f(x) / (f'(x) * p^i) mod p
                fx = f(x) % (pk * p)
                df = (f(x + pk) - fx) // pk  # 近似导数
                if df % p != 0:
                    t = (-fx // pk) * invert(df, p) % p
                    x = (x + t * pk) % (pk * p)
            solutions.append(x)
    return solutions

# 示例：解 x^2 = 2 mod 7^3
f = lambda x: x*x - 2
sols = hensel_lifting(f, 7, 3)
print(f"[+] x^2 ≡ 2 mod 7^3 的解: {sols}")
```

### 3.4 利用 SageMath 解决 CTF 常见数学问题

```python
# 问题1：已知 n = p*q，且 p 和 q 的二进制中只有 1 bit 不同
def find_close_primes(n, bit_diff=1):
    """通过尝试寻找相邻的素数"""
    sqrt_n = int(gmpy2.isqrt(n))
    p = mpz(sqrt_n)
    while True:
        if n % p == 0:
            return p, n // p
        p = gmpy2.next_prime(p - 1000)
        if p > sqrt_n + 10000:
            p = gmpy2.next_prime(sqrt_n - 10000)

# 问题2：解线性丢番图方程
def solve_diophantine(a, b, c):
    """解 ax + by = c 的整数解"""
    g = gcd(a, b)
    if c % g != 0:
        return None
    # 扩展欧几里得
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        x1, y1, d = egcd(b, a % b)
        return (y1, x1 - (a // b) * y1, d)
    x0, y0, _ = egcd(a, b)
    factor = c // g
    return (x0 * factor, y0 * factor)

# 问题3：模意义下的快速幂（处理大数）
def pow_mod(base, exp, mod):
    """模幂运算，处理超大指数"""
    return gmpy2.powmod(base, exp, mod)

# 问题4：Miller-Rabin 素数判定
def miller_rabin(n, k=40):
    """k 轮 Miller-Rabin 检验"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # 写 n-1 = 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = gmpy2.mpz_random(gmpy2.random_state(), n - 3) + 2
        x = gmpy2.powmod(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = gmpy2.powmod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
```

### 3.5 Z3 约束求解器在密码学中的应用

```python
from z3 import *

def solve_with_z3():
    """使用 Z3 求解密码学约束"""
    s = Solver()

    # 定义 bit 向量变量
    a = BitVec('a', 32)
    b = BitVec('b', 32)

    # 添加约束
    s.add(a ^ b == 0xDEADBEEF)
    s.add(a + b == 0x1234567890)
    s.add(a > 100)
    s.add(b < 0xFFFFFFFF)

    # 求解
    if s.check() == sat:
        m = s.model()
        print(f"[+] a = {m[a]}, b = {m[b]}")
        return m[a].as_long(), m[b].as_long()
    return None

solve_with_z3()
```

### 3.6 SageMath 离线脚本模板

```python
#!/usr/bin/env sage
# -*- coding: utf-8 -*-
"""
CTF 密码学 SageMath 解题模板
使用方法：sage template.sage
"""
import sys
sys.setrecursionlimit(10000)

def solve():
    # 在这里编写解题代码
    n = 1234567890123456789
    print(f"[*] Factoring n = {n}")
    print(f"[+] Factors: {factor(n)}")

if __name__ == "__main__":
    solve()
```

### 3.7 有限域上的运算（AES 的 GF(2^8)）

```python
def gf_mult(a, b, poly=0x11B):
    """GF(2^8) 乘法（AES 用）"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= poly
        b >>= 1
    return p & 0xFF

def gf_inv(a, poly=0x11B):
    """GF(2^8) 逆元（扩展欧几里得）"""
    if a == 0:
        return 0
    # 使用费马小定理推广：a^{254} ≡ a^{-1} mod poly
    result = 1
    base = a
    exp = 254
    while exp > 0:
        if exp & 1:
            result = gf_mult(result, base, poly)
        base = gf_mult(base, base, poly)
        exp >>= 1
    return result

# 验证
assert gf_mult(0x57, gf_inv(0x57)) == 1
print("[+] GF(2^8) 运算验证通过")
```

## 4. 常见误区与注意事项

1. **Python int 无限精度 vs 模运算溢出**：Python 不会自动取模，大数运算需手动 mod。
2. **SageMath 变量污染**：`var()` 定义的符号变量会污染命名空间，建议使用多项式环 `R.<x> = ...`。
3. **gmpy2 vs sympy**：gmpy2 快但功能少，sympy 功能全但慢，计算密集型用 gmpy2，符号计算用 sympy。
4. **离散对数求解**：`discrete_log()` 默认使用较慢的算法，对于大群可能需要指定 `algorithm='PohligHellman'` 等。
5. **有限域类型**：`GF(p)` 和 `GF(p^n)` 不同，前者是素数域，后者是扩展域。
6. **CRT 组合**：RSA 解密中 CRT 加速和 CRT 攻击（Hastad）是两回事，需区分。
7. **随机数生成**：断网后无法使用 `/dev/urandom`，但 Python 的 `random` 模块仍可用（非密码学安全）。

## 5. 实战示例

**场景**：题目给出 n = 935291...，e = 65537，已知 p 和 q 相差很小（|p-q| < 2^16）。

```python
import gmpy2

def fermat_factor(n):
    """费马分解法：当 |p-q| 很小时有效"""
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = gmpy2.isqrt(b2)
        if b * b == b2:
            return int(a - b), int(a + b)
        a += 1

n = gmpy2.mpz(9352914676672849971662125403315896629152648453653341234600682297004007170483765641935749353662221896647591178238671824253540374986847353070598907223035687)

p, q = fermat_factor(n)
print(f"[+] p = {p}")
print(f"[+] q = {q}")
assert p * q == n
print("[+] Fermat factorization successful!")
```

## 6. 相关知识点

- **Python 密码学库**：pycryptodome、cryptography、Crypto.Util.number
- **数学软件**：SageMath、Magma、Maple、Mathematica（离线需预装）
- **数论在线资源**：OEIS（整数序列百科）、FactorDB
- **多项式工具**：SageMath PolyRing、NTL
- **格基约简**：SageMath 内置 LLL、BKZ 算法
- **符号计算**：sympy（纯 Python，适合轻量使用）
- **多精度运算**：gmpy2（GMP 的 Python 绑定）、mpmath
- **p-adic 数**：Hensel 提升、p-adic 对数（超椭圆曲线攻击时会用到）
- **Groebner 基**：SageMath 的 Singular 接口，多项式方程组求解
- **CTF 常用**：factor()、discrete_log()、CRT、PolynomialRing、Matrix
