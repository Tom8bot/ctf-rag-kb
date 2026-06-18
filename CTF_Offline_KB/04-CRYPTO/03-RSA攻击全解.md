---
category: "密码学"
tags: ["RSA", "因数分解", "共模攻击", "低加密指数", "维纳攻击", "Coppersmith", "Franklin-Reiter", "广播攻击", "模不互素", "CTF核心"]
difficulty: "中级"
---

# RSA 攻击全解

## 1. 概述

RSA 是 CTF 密码学中出现频率最高的公钥密码体制，几乎每场 CTF 竞赛都有涉及。RSA 的安全性基于大整数分解的困难性，但参数选择不当会引入多种攻击面。

RSA 核心关系：
- `n = p * q`（模数）
- `phi(n) = (p-1)(q-1)`
- `e * d ≡ 1 (mod phi(n))`
- `c ≡ m^e (mod n)`，`m ≡ c^d (mod n)`

本章系统梳理 CTF 中 RSA 攻击的完整知识图谱，覆盖从入门到高阶的几乎所有攻击方法。

## 2. 核心原理（含数学推导）

### 2.1 解密正确性证明

由欧拉定理：`a^{phi(n)} ≡ 1 (mod n)` 当 gcd(a,n)=1
`c^d ≡ m^{e*d} ≡ m^{1 + k*phi(n)} ≡ m * (m^{phi(n)})^k ≡ m (mod n)`

### 2.2 维纳攻击的连分数理论基础

当 `d < n^{0.25}/3` 时，可通过 `e/n` 的连分数展开恢复 d。

原理：
`e*d ≡ 1 (mod phi(n)) => e*d = 1 + k*phi(n)`
`=> e/phi(n) - k/d = 1/(d*phi(n))`
由于 phi(n) = (p-1)(q-1) = n - p - q + 1 ≈ n - 2*sqrt(n)
`|e/n - k/d|` 极小，k/d 为 e/n 连分数展开的收敛项之一。

### 2.3 Coppersmith 方法核心思想

Coppersmith 定理：对单变量多项式 f(x)，可高效找到所有满足 `|x0| < N^{1/deg(f)}` 的根。

高位的缺失意味着待求解变量的界很小，当界小于 `N^{1/k}`（k 为方程度数）时可通过 LLL 格基约简求解。

### 2.4 Franklin-Reiter 相关消息攻击

当同一明文 m 用两个相关多项式加密（如 m 和 m+delta），且 e 较小时可恢复 m。

核心：计算两个密文的结式 (resultant)，求解 gcd 消去变量。

## 3. 关键技巧/攻击方法（含 Python 代码）

### 3.1 直接分解法（FactorDB / YAFU / SageMath）

```python
import gmpy2
from gmpy2 import mpz, is_prime, next_prime, invert

# 方法1: SageMath 内置 factor
# factor(n)

# 方法2: 在线 FactorDB（需网络）
# 断网备选：使用本地 YAFU 或预缓存的 FactorDB 数据

# 方法3: 小质数试除法
def trial_division(n, limit=10**6):
    """对 n 进行小质数试除"""
    p = mpz(2)
    while p < limit:
        if n % p == 0:
            return p, n // p
        p = gmpy2.next_prime(p)
    return None

# 方法4: Pollard's p-1
def pollard_p1(n, B=10**5):
    """当 p-1 是光滑数时有效"""
    a = 2
    for i in range(2, B + 1):
        a = gmpy2.powmod(a, i, n)
        g = gmpy2.gcd(a - 1, n)
        if 1 < g < n:
            return g, n // g
    return None

# 方法5: William's p+1
def williams_p1(n, B=10**5):
    """当 p+1 是光滑数时有效"""
    # 使用 Lucas 序列
    def lucas_v(P, Q, k, n):
        """计算 Lucas V_k"""
        v0, v1 = 2, P % n
        k_bits = bin(k)[3:]
        for bit in k_bits:
            v0, v1 = (v0 * v1 - P) % n, (v1 * v1 - 2 * Q) % n
            if bit == '1':
                v0, v1 = v1, (P * v1 - Q * v0) % n
        return v0 % n

    for A in range(1, 100):
        P, Q = A, 1
        D = P*P - 4*Q
        m = 1
        for p in range(2, B+1):
            if gmpy2.is_prime(p):
                q = p
                while q * p <= B:
                    q *= p
                m *= q
        v = lucas_v(P, Q, m, n)
        g = gmpy2.gcd(v - 2, n)
        if 1 < g < n:
            return g, n // g
    return None
```

### 3.2 共模攻击（Common Modulus Attack）

```python
def common_modulus_attack(n, e1, e2, c1, c2):
    """
    同一明文 m 用不同 e 加密（相同 n）时的攻击
    条件：gcd(e1, e2) = 1
    """
    g, s1, s2 = gmpy2.gcdext(e1, e2)  # 扩展欧几里得
    if g != 1:
        # 若 gcd(e1, e2) != 1，则尝试提取公因子
        return None

    # m = (m^{e1})^{s1} * (m^{e2})^{s2} mod n
    if s1 < 0:
        c1 = invert(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = invert(c2, n)
        s2 = -s2

    m = (gmpy2.powmod(c1, s1, n) * gmpy2.powmod(c2, s2, n)) % n
    return m

# 示例
n = mpz(0x00b0bee5e3e9e5a7e8d00b493355c618fc8c7d7d03b82e409951c182f398dee3104580e7ba70d383ae5311475656e8a964d380cb157f48c951adfa65db0b122ca40e42fa709189b54a0fa7dcdb5195dd3e5e0e1e7d6b9e5a3d2f5b5e9e5)
e1, c1 = 17, 123456789  # 实际 CTF 题中的数据
e2, c2 = 65537, 987654321
m = common_modulus_attack(n, e1, e2, c1, c2)
```

### 3.3 低加密指数攻击（Hastad 广播攻击）

```python
def hastad_broadcast_attack(pairs, e=3):
    """
    pairs: [(n1, c1), (n2, c2), (n3, c3), ...]
    当同一 m 用 e=3 加密且至少 e 个不同的 n 时
    """
    # 使用 CRT
    residues = [c for n, c in pairs]
    moduli = [n for n, c in pairs]

    M = 1
    for m in moduli:
        M *= m

    # CRT 求解 m^e
    me = 0
    for (ni, ci) in zip(moduli, residues):
        Mi = M // ni
        mi = invert(Mi, ni)
        me = (me + ci * Mi * mi) % M

    # 开 e 次方根
    m_int = int(gmpy2.iroot(me, e)[0])
    return m_int

# 示例
pairs = [
    (n1, c1),
    (n2, c2),
    (n3, c3),
]
m = hastad_broadcast_attack(pairs, e=3)
```

### 3.4 维纳攻击（Wiener's Attack）

```python
def wiener_attack(n, e):
    """
    维纳攻击：当 d < n^{0.25}/3 时有效
    通过 e/n 的连分数展开恢复 d
    """
    def continued_fraction(num, den):
        """计算连分数展开"""
        cf = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        return cf

    def convergents(cf):
        """从连分数展开获取收敛项"""
        convs = []
        for i in range(len(cf)):
            if i == 0:
                num, den = cf[0], 1
            elif i == 1:
                num, den = cf[0] * cf[1] + 1, cf[1]
            else:
                num = cf[i] * convs[-1][0] + convs[-2][0]
                den = cf[i] * convs[-1][1] + convs[-2][1]
            yield (num, den)

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # ed = 1 + k*phi(n) => phi(n) = (ed-1)/k
        phi = (e * d - 1) // k
        if (e * d - 1) % k != 0:
            continue

        # 解算 p, q: x^2 - (n-phi+1)x + n = 0
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue

        sqrt_d = int(gmpy2.isqrt(discriminant))
        if sqrt_d * sqrt_d != discriminant:
            continue

        p = (b + sqrt_d) // 2
        q = (b - sqrt_d) // 2
        if p * q == n:
            return d, p, q
    return None
```

### 3.5 Coppersmith 攻击（基于 SageMath）

```python
# 需要在 SageMath 中运行
"""

def coppersmith_small_root(n, e, partial_m):
    '''
    当已知明文的高位时的 Coppersmith 攻击
    设 m = partial_m + x，x 为未知低位
    '''
    # 构建多项式 f(x) = (partial_m + x)^e - c ≡ 0 (mod n)
    bits_missing = 100  # 未知的低位数
    R.<x> = PolynomialRing(Zmod(n))
    f = (partial_m + x)^e - c
    f = f.monic()
    
    # 调用 SageMath 的 small_roots
    roots = f.small_roots(X=2^bits_missing, beta=1.0)
    if roots:
        return partial_m + roots[0]
    return None

def coppersmith_prime_high_bits(n, prime_high, bits_missing=64):
    '''
    当已知 p 的高位时分解 n (Coppersmith 变体)
    '''
    R.<x> = PolynomialRing(Zmod(n))
    # p = prime_high + x，x 为未知低位
    p_approx = prime_high << bits_missing
    f = p_approx + x
    f = f.monic()
    
    roots = f.small_roots(X=2^bits_missing, beta=0.5)
    if roots:
        p = int(p_approx + roots[0])
        if n % p == 0:
            return p, n // p
    return None
"""
```

### 3.6 Franklin-Reiter 相关消息攻击

```python
# 需要在 SageMath 中运行
"""

def franklin_reiter(n, e, c1, c2, delta):
    '''
    c1 = (m)^e mod n
    c2 = (m + delta)^e mod n
    '''
    R.<x> = PolynomialRing(Zmod(n))
    f1 = x^e - c1
    f2 = (x + delta)^e - c2
    
    # gcd 消去 x
    g = f1.gcd(f2)
    if g.degree() > 0:
        # 提取根
        root = -g[0]  # 常数项系数取负
        return int(root)
    return None
"""
```

### 3.7 模不互素攻击（GCD Attack）

```python
def gcd_attack(n_list):
    """
    当多个 n 共享质因子时（如两个 n 有共同的 p）
    """
    for i in range(len(n_list)):
        for j in range(i+1, len(n_list)):
            g = gmpy2.gcd(n_list[i], n_list[j])
            if g > 1:
                p = g
                q1 = n_list[i] // p
                q2 = n_list[j] // p
                return {
                    'p': p,
                    f'n{i}_q': q1,
                    f'n{j}_q': q2
                }
    return None

# 常见于多组 RSA 参数共享生成器 bug
```

### 3.8 d 泄露攻击（已知 d 分解 n）

```python
def factor_from_d(n, e, d):
    """
    已知私钥 d，可以概率性分解 n
    算法来自 Boneh 的 Twenty Years of Attacks on RSA
    """
    k = e * d - 1  # k 是 phi(n) 的倍数

    # 不断选取随机数直到成功
    while True:
        g = gmpy2.mpz_random(gmpy2.random_state(), n - 2) + 2
        t = k
        while t % 2 == 0:
            t //= 2
            x = gmpy2.powmod(g, t, n)
            if x > 1 and gmpy2.gcd(x - 1, n) > 1:
                p = gmpy2.gcd(x - 1, n)
                q = n // p
                return p, q
```

### 3.9 Boneh-Durfee 攻击（SageMath 实现）

```python
# 需要在 SageMath 中运行
"""
def boneh_durfee(n, e, delta=0.28):
    '''
    Boneh-Durfee 攻击：当 d < n^{0.292} 时有效（比维纳攻击的 0.25 更强）
    '''
    # 构建多项式 f(x,y) = 1 + x*(e*A - 1)，其中 A = n+1 (phi 的近似)
    A = n + 1  # 近似 phi(n) ≈ n + 1 - 2*sqrt(n)
    
    R.<x,y> = PolynomialRing(ZZ)
    f = 1 + x * (e + y)  # 正确形式
    
    # 构建格（此处简化，完整实现需构造三角矩阵）
    X = int(n^(delta))
    Y = int(n^(0.5))
    
    # 使用 small_roots（SageMath 内置）
    # 注意：SageMath 的 small_roots 默认支持 Boneh-Durfee 类型的格基构造
    m = 2  # 格维度参数
    t = int((1 - 2*delta) * m)
    
    # 构造多变量多项式格...
    # （完整实现较长，比赛时通常用现成脚本）
    return None
"""
```

### 3.10 完整 RSA 攻击工具箱

```python
#!/usr/bin/env python3
"""
CTF RSA 自动攻击工具箱
Usage: python rsa_toolkit.py
"""

import gmpy2
from gmpy2 import mpz, is_prime, next_prime, invert, gcd, iroot, isqrt
import sys

class RSACracker:
    def __init__(self, n=None, e=None, c=None):
        self.n = mpz(n) if n else None
        self.e = mpz(e) if e else None
        self.c = mpz(c) if c else None

    def decrypt(self, p, q):
        """已知 p, q 解密"""
        phi = (p - 1) * (q - 1)
        d = invert(self.e, phi)
        m = gmpy2.powmod(self.c, d, self.n)
        return m

    def auto_attack(self) -> list:
        """自动尝试多种攻击方法"""
        results = []

        # 1. 判断 n 是否为素数（phi(n)=n-1）
        if self.n and gmpy2.is_prime(self.n):
            d = invert(self.e, self.n - 1)
            m = gmpy2.powmod(self.c, d, self.n)
            results.append(('n_is_prime', m))

        # 2. 判断 e 是否太小（直接开根）
        if self.e and self.e <= 7:
            m_int, exact = gmpy2.iroot(self.c, int(self.e))
            if exact:
                results.append(('small_e_root', m_int))

        # 3. 费马分解（当 |p-q| 小时）
        if self.n:
            a = gmpy2.isqrt(self.n)
            if a * a < self.n:
                a += 1
            for attempt in range(10**6):
                b2 = a * a - self.n
                b = gmpy2.isqrt(b2)
                if b * b == b2:
                    p = a - b
                    q = a + b
                    m = self.decrypt(p, q)
                    results.append(('fermat', m))
                    break
                a += 1

        # 4. 维纳攻击
        if self.n and self.e:
            wiener_result = self._wiener_attack()
            if wiener_result:
                results.append(('wiener', wiener_result))

        return results

    def _wiener_attack(self):
        """简化的维纳攻击"""
        def get_convergents(e, n):
            cf = []
            a, b = e, n
            while b:
                cf.append(a // b)
                a, b = b, a - (a // b) * b
            convergents = []
            for i in range(len(cf)):
                if i == 0:
                    h, k = cf[0], 1
                elif i == 1:
                    h, k = cf[0]*cf[1] + 1, cf[1]
                else:
                    h = cf[i]*convergents[-1][0] + convergents[-2][0]
                    k = cf[i]*convergents[-1][1] + convergents[-2][1]
                convergents.append((h, k))
            return convergents

        for k, d in get_convergents(self.e, self.n):
            if k == 0:
                continue
            if (self.e * d - 1) % k != 0:
                continue
            phi = (self.e * d - 1) // k
            b = self.n - phi + 1
            disc = b*b - 4*self.n
            if disc < 0:
                continue
            sqrt_disc = int(gmpy2.isqrt(disc))
            if sqrt_disc * sqrt_disc != disc:
                continue
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == self.n:
                return self.decrypt(p, q)
        return None

# 使用示例
if __name__ == "__main__":
    cracker = RSACracker(n=..., e=65537, c=...)
    for attack_type, result in cracker.auto_attack():
        print(f"[+] {attack_type}: {bytes.fromhex(hex(int(result))[2:].zfill(-(-len(hex(result)[2:])//2)*2))}")
```

## 4. 常见误区与注意事项

1. **python int 不会溢出**：RSA 的 n 通常 1024-2048 bit，Python 直接支持，但 `pow()` 效率低，用 `gmpy2.powmod()` 或 `pow(m, e, n)`。
2. **phi(n) 计算**：标准 RSA 用 `(p-1)(q-1)`，多质数 RSA 用 `(p-1)(q-1)(r-1)...`。
3. **e 太小时 padding 是关键**：CTF 中 e=3 往往意味着没有正确 padding（PKCS#1 v1.5），此时 Hastad 攻击可行。
4. **维纳攻击的界**：原始论文是 `d < n^0.25/3`，实际阈值略大于此。Boneh-Durfee 放宽到 0.292。
5. **Coppersmith 需要 SageMath**：纯 Python 无法高效运行 LLL，必须用 SageMath。
6. **密文对应关系**：共模攻击要求同一个 m，实际题目可能增加随机 padding，需注意区分。
7. **多素数 RSA**：有些题目使用 `n = p*q*r`，phi = (p-1)(q-1)(r-1)，基本攻击同样适用。

## 5. 实战示例

**场景**：已知 n, e, c，其中 p 和 q 是通过不安全的随机数生成器产生的（共享因子攻击）。

```python
import gmpy2

# 假设我们有三组 RSA 参数
n_list = [
    0xabc123...,
    0xdef456...,
    0x789012...,
]
e = 65537
c_list = [c1, c2, c3]

# 检查共享因子
for i in range(len(n_list)):
    for j in range(i+1, len(n_list)):
        p = gmpy2.gcd(n_list[i], n_list[j])
        if p > 1:
            print(f"[+] Found shared prime factor between n{i} and n{j}")
            q_i = n_list[i] // p
            q_j = n_list[j] // p

            # 解密
            phi_i = (p - 1) * (q_i - 1)
            d_i = gmpy2.invert(e, phi_i)
            m_i = gmpy2.powmod(c_list[i], d_i, n_list[i])
            print(f"[+] Decrypted flag: {bytes.fromhex(hex(int(m_i))[2:])}")
            break
```

## 6. 相关知识点

- **RSA 填充方案**：PKCS#1 v1.5、OAEP（Bleichenbacher padding oracle 攻击）
- **多质数 RSA**：n = p*q*r（CRT 加速解密）
- **Rabin 密码**：RSA 的 e=2 变体，解密需要中国剩余定理和平方根
- **Paillier 同态加密**：基于合数剩余判定问题
- **Schmidt-Samoa 密码**：n = p^2*q 的变体
- **LWE/NTRU**：后量子替代方案
- **Boneh-Durfee**：维纳攻击的优化版（d < n^0.292）
- **部分密钥泄露**：给定 d 的低位 -> 格攻击恢复完整 d
- **Oracle 攻击**：LSB Oracle、Decryption Oracle（Bleichenbacher 1998）
- **量子计算威胁**：Shor 算法可在多项式时间内分解大整数
