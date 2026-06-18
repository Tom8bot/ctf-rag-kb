---
category: "密码学"
tags: ["格密码", "LLL算法", "背包密码", "Knapsack", "NTRU", "隐藏数问题", "HNP", "CVP", "SVP", "格基约简", "CTF高级"]
difficulty: "高级"
---

# 格密码基础与 LLL 算法应用

## 1. 概述

格 (Lattice) 密码学是现代密码学最活跃的研究方向之一，也是 CTF 中最高阶的考点。LLL 算法（Lenstra-Lenstra-Lovász, 1982）是格基约简的核心工具，可用于解决多种密码学攻击问题。

CTF 中格方法应用场景：
- **背包密码系统破解**（Knapsack / Merkle-Hellman）
- **同余方程组求解**（Coppersmith、HNP）
- **RSA 部分信息泄露**（已知 p 的高位、d 的部分位）
- **ECDSA 的 nonce 偏差**（Hidden Number Problem）
- **NTRU 加密系统的攻击**
- **最短向量问题 (SVP) 和最近向量问题 (CVP) 的各种构造**

## 2. 核心原理（含数学推导）

### 2.1 格的定义

格 L 是 R^m 中由 n 个线性无关向量 b_1, ..., b_n 生成的整系数线性组合构成的离散加法子群：
`L = {∑ a_i b_i : a_i ∈ Z}`

**格基**：{b_1, ..., b_n} 是格 L 的一组基。
**格的维数**：基向量的个数 n。
**格的行列式**：`det(L) = sqrt(det(B B^T))`（B 是以基向量为行的矩阵）

### 2.2 格中的核心问题

**SVP (Shortest Vector Problem)**：找到格中最短的非零向量。
**CVP (Closest Vector Problem)**：给定目标向量 t，找到格中最近的向量 v。
**SIVP (Shortest Independent Vectors Problem)**：找到 n 个线性无关的最短向量。

### 2.3 LLL 算法

给定格基 B = [b_1, ..., b_n]，LLL 算法在多项式时间内输出约简基 B'，满足：
- `||b'_1|| ≤ 2^{(n-1)/2} * λ_1` （其中 λ_1 是最短向量长度）
- `||b'_1|| ≤ 2^{(n-1)/4} * det(L)^{1/n}`

LLL 的核心操作：
1. **整数 Gram-Schmidt 正交化**：保持格不变
2. **大小约简 (Size Reduction)**：确保投影系数 < 1/2
3. **Lovász 条件**：检查是否需交换向量

### 2.4 背包密码的格攻击

Merkle-Hellman 背包系统：
- 私钥：超递增序列 {a_i} 和乘数 w, m (gcd(w,m)=1)
- 公钥：b_i = (w * a_i) mod m
- 加密：c = ∑ x_i * b_i
- 解密：c' = w^{-1} * c mod m，然后用超递增背包求解

LLL 攻击：构造格矩阵找根。

## 3. 关键技巧/攻击方法（含 Python 代码）

### 3.1 LLL 基本用法（SageMath）

```python
# SageMath 代码
"""
# LLL 格基约简基础示例
B = Matrix(ZZ, [
    [1, 0, 0, 123456],
    [0, 1, 0, 789012],
    [0, 0, 1, 345678],
    [0, 0, 0, 10**10],
])

print("Original basis:")
print(B)
print()

B_lll = B.LLL()
print("LLL-reduced basis:")
print(B_lll)
print()

# 检查约简后的向量长度
for row in B_lll:
    print(f"  ||v|| = {float(row.norm()):.4f}")
"""
```

### 3.2 背包密码（Knapsack）LLL 攻击

```python
# SageMath 代码
"""
def knapsack_lll_attack(public_key, ciphertext):
    '''
    使用 LLL 攻击 Merkle-Hellman 背包密码系统
    
    参数:
        public_key: 公钥列表 [b_0, b_1, ..., b_{n-1}]
        ciphertext: 密文 c = sum(x_i * b_i)
    返回:
        明文比特列表 [x_0, x_1, ..., x_{n-1}]
    '''
    n = len(public_key)
    
    # 构造格矩阵 (n+1) x (n+1)
    # | 1  0  0 ... 0  b_0 |
    # | 0  1  0 ... 0  b_1 |
    # | 0  0  1 ... 0  b_2 |
    # | .  .  . ... .  .   |
    # | 0  0  0 ... 1  b_{n-1} |
    # | 0  0  0 ... 0  -c  |
    B = Matrix(ZZ, n + 1, n + 1)
    
    for i in range(n):
        B[i, i] = 1
        B[i, n] = public_key[i]
    
    B[n, n] = -ciphertext
    
    # LLL 约简
    B_lll = B.LLL()
    
    # 搜索包含 (x_1, x_2, ..., x_n, 0) 的短向量
    for row in B_lll:
        if row[n] == 0:
            solution = [abs(row[i]) for i in range(n)]
            # 验证
            if all(x in (0, 1) for x in solution):
                check = sum(x * b for x, b in zip(solution, public_key))
                if check == ciphertext:
                    return solution
    
    return None

# 示例
# 超递增序列构造的背包
private_key = [2, 3, 7, 14, 30, 57, 120, 251]  # 超递增
w = 101
m = 509
public_key = [(w * a) % m for a in private_key]

# 加密
plaintext_bits = [1, 0, 1, 1, 0, 0, 1, 0]
ciphertext = sum(x * b for x, b in zip(plaintext_bits, public_key))
print(f"Public key: {public_key}")
print(f"Ciphertext: {ciphertext}")

# LLL 攻击
recovered = knapsack_lll_attack(public_key, ciphertext)
print(f"Recovered bits: {recovered}")
print(f"Original bits:  {plaintext_bits}")
"""
```

### 3.3 隐藏数问题 (HNP) 的格攻击

```python
# SageMath 代码
"""
def hnp_attack(t_list, u_list, modulus, known_msb_bits):
    '''
    隐藏数问题 (Hidden Number Problem) 格攻击
    已知 t_i, u_i 满足: u_i ≡ α * t_i (mod n)，且 α 的部分 MSB 已知
    
    更常见的场景：ECDSA nonce 偏差攻击
    已知: k_i 的部分高位值 a_i，s_i = k_i^{-1}(h_i + r_i*d) mod n
    => d*r_i ≡ s_i*k_i - h_i (mod n)
    => d*r_i/s_i ≡ k_i - h_i/s_i (mod n)
    => k_i = a_i + x_i (x_i 小)
    => a_i - h_i/s_i ≡ -x_i + d*r_i/s_i (mod n)
    
    参数:
        t_list: t_i 值列表
        u_list: u_i 值列表 
        modulus: 模数 n
        known_msb_bits: 已知的 MSB 位数
    '''
    from sage.all import Matrix, vector, ZZ, QQ, ceil, log
    
    m = len(t_list)
    l = known_msb_bits
    
    # 构造格 (m+2) x (m+2)
    B_size = m + 2
    B = Matrix(ZZ, B_size, B_size)
    
    # 主对角块 (m x m) 填充 modulus
    for i in range(m):
        B[i, i] = modulus
    
    # (m+1) 行填充 t_i
    for i in range(m):
        B[m, i] = t_list[i]
    
    # (m+2) 行填充 u_i
    for i in range(m):
        B[m+1, i] = u_list[i]
    
    # 右下角
    B[m, m] = 1
    B[m+1, m+1] = 2**l
    
    # LLL
    B_lll = B.LLL()
    
    # 搜索短向量
    for row in B_lll:
        if row[m] == 1:
            alpha = (row[m+1] * 2**l) % modulus
            return alpha
        elif row[m] == -1:
            alpha = (-row[m+1] * 2**l) % modulus
            return alpha
    
    return None

# ECDSA nonce 攻击示例 (简化)
def ecdsa_hnp_attack(signatures, n, known_bits):
    '''
    ECDSA 签名 nonce 高位泄露攻击
    signatures: [(r_i, s_i, h_i, a_i)] 其中 a_i 是 k_i 的已知高位
    '''
    t_list = []
    u_list = []
    
    for r, s, h, a in signatures:
        s_inv = inverse_mod(s, n)
        t = (r * s_inv) % n
        u = (a - h * s_inv) % n
        t_list.append(int(t))
        u_list.append(int(u))
    
    return hnp_attack(t_list, u_list, n, known_bits)
"""
```

### 3.4 Coppersmith 方法的格构造

```python
# SageMath 代码
"""
def coppersmith_howgrave_graham(n, e, c, partial_m=None, kbits=0):
    '''
    Coppersmith 单变量攻击的简化实现
    
    场景1：已知 m 的高位 (partial_m)，求低位
    场景2：求 m^e ≡ c (mod n) 的小解（当 m < n^{1/e} 时直接开根）
    
    这里演示格构造原理
    '''
    if partial_m is None:
        # 小根情况
        R.<x> = PolynomialRing(Zmod(n))
        f = x^e - c
        roots = f.small_roots(X=2^(n.nbits()//e), beta=1.0)
        return roots
    else:
        # 已知高位
        R.<x> = PolynomialRing(Zmod(n))
        f = (partial_m * 2^kbits + x)^e - c
        f = f.monic()
        roots = f.small_roots(X=2^kbits, beta=1.0)
        if roots:
            return partial_m * 2^kbits + roots[0]
    return None

def coppersmith_manual_lattice(f, X, N):
    '''
    手工实现 Coppersmith 格构造（教学用）
    f: 多项式 f(x) ≡ 0 (mod N)
    X: |x0| < X 的界
    N: 模数
    '''
    n = f.degree()
    # 构造多项式 g_i(x) = x^i * f(x) 和 h_j(x) = N * x^j
    # 构建格矩阵
    k = 3  # 格维度参数
    m = 3  # Howgrave-Graham 参数
    
    dim = n * m + k
    M = Matrix(ZZ, dim, dim)
    
    # 填充格
    # ...(具体构造省略，仅说明原理)
    
    return M.LLL()
"""
```

### 3.5 联立方程与 CVP 求解

```python
# SageMath 代码
"""
def solve_linear_congruences_cvp(a_list, b_list, n, kbits):
    '''
    使用 CVP 求解多变量同余方程组
    ∑ a_{i,j} * x_j ≡ b_i (mod n)
    其中所有 x_j 都很小（< 2^kbits）
    '''
    m = len(a_list)  # 方程数
    t = len(a_list[0])  # 变量数
    
    # 构造格
    B = Matrix(ZZ, m + t, m + t)
    
    # 左上角: n * I_m
    for i in range(m):
        B[i, i] = n
    
    # 右上角: 0
    # 左下角: A^T
    for i in range(m):
        for j in range(t):
            B[m + j, i] = a_list[i][j]
    
    # 右下角: I_t
    for i in range(t):
        B[m + i, m + i] = 1
    
    # 目标向量
    target = vector(ZZ, list(b_list) + [0] * t)
    
    # LLL 约简后使用 Babai 最近平面法解 CVP
    B_lll = B.LLL()
    
    # Babai's nearest plane
    GS, mu = B_lll.gram_schmidt()
    v = target
    for i in range(B_lll.nrows() - 1, -1, -1):
        c = (v * GS[i]) / (GS[i] * GS[i])
        c = round(c)
        v = v - c * B_lll[i]
    
    # 解向量 = target - v
    solution = target - v
    x_values = [solution[m + j] for j in range(t)]
    
    return x_values
"""
```

### 3.6 Babai 最近平面算法

```python
# SageMath 代码
"""
def babai_closest_vector(B, target):
    '''
    Babai 最近平面算法求解 CVP
    B: 格的 LLL 约简基
    target: 目标向量
    返回格中最近的向量
    '''
    # Gram-Schmidt 正交化
    G, mu = B.gram_schmidt()
    
    # Babai 算法
    t = target
    for i in range(B.nrows() - 1, -1, -1):
        c = (t * G[i]) / (G[i] * G[i])
        c = round(c)
        t = t - c * B[i]
    
    # result = target - t
    return target - t

def babai_rounding(B, target):
    '''
    Babai 取整算法（更简单但精度更低）
    '''
    # 求解 t = x * B，然后取整 x
    B_inv = B.inverse()
    x = target * B_inv
    x_rounded = vector(ZZ, [round(xi) for xi in x])
    return x_rounded * B
"""
```

### 3.7 NTRU 基本解密与格攻击思路

```python
# SageMath 代码
"""
# NTRU 简单实现
def ntru_keygen(N=167, p=3, q=128):
    '''
    NTRU 密钥生成（简化版）
    参数: N 多项式度, p 小数模, q 大数模
    '''
    R.<x> = PolynomialRing(ZZ)
    # 在 Z[x]/(x^N - 1) 中操作
    pass

def ntru_coppersmith_shamir():
    '''
    Coppersmith-Shamir 对 NTRU 的格攻击
    当公钥 h 的部分系数已知时有效
    '''
    pass
"""
```

## 4. 常见误区与注意事项

1. **LLL 不是万能药**：LLL 只能找到相对短的向量，不保证找到绝对最短向量（SVP 确切解是 NP-hard）。
2. **格的构造是核心难点**：CTF 中使用 LLL 的最大挑战不是调用 LLL 本身（一行代码），而是**如何构造正确的格**。不同问题的格构造方式完全不同。
3. **参数选择**：格的大小和常数因子 C（如 `ciphertext * C`）的选择影响 LLL 的成功率。C 通常选择为 `max(public_key)` 或 `2^(nbits)`。
4. **BKZ vs LLL**：当 LLL 不够时，可使用更强的 BKZ (Block Korkine-Zolotarev) 算法（但更耗时）。SageMath 支持 `BKZ(block_size)`。
5. **浮点精度**：`small_roots()` 使用 LLL 的 p-adic 版本，比浮点 Gram-Schmidt 更精确。
6. **多变量 Coppersmith**：SageMath 的 `small_roots()` 对单变量效果最好，多变量需手工构造格。
7. **对称 vs 非对称格**：背包攻击的格通常不对称（非方阵），需注意构造方案。

## 5. 实战示例

**场景**：题目给出一个 Merkle-Hellman 背包密码的加密结果，要求恢复明文。

```python
#!/usr/bin/env sage
# SageMath Knapsack CTF Solver

def solve_knapsack_ctf(public_key, ciphertext):
    """完整的背包密码CTF解题脚本"""
    n = len(public_key)
    print(f"[*] Key length: {n}")
    print(f"[*] Public key: {public_key}")
    print(f"[*] Ciphertext: {ciphertext}")

    # 方法1: 标准 LLL 攻击
    # 构造格矩阵
    M = Matrix(ZZ, n + 1, n + 1)

    for i in range(n):
        M[i, i] = 1
        M[i, n] = public_key[i]

    M[n, n] = -ciphertext

    print("[*] Running LLL...")
    M_lll = M.LLL()

    for row in M_lll:
        if row[n] == 0:
            sol = [abs(int(row[i])) for i in range(n)]
            if all(s in (0, 1) for s in sol):
                # 验证
                check = sum(s * b for s, b in zip(sol, public_key))
                if check == ciphertext:
                    print(f"[+] Solution found: {sol}")
                    return sol

    # 方法2: 若方法1失败，尝试调整权重
    max_b = max(public_key)
    C = max(ciphertext, max_b)

    M2 = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M2[i, i] = 1
        M2[i, n] = C * public_key[i]
    M2[n, n] = -C * ciphertext

    print("[*] Trying with weight adjustment...")
    M2_lll = M2.LLL()

    for row in M2_lll:
        if row[n] == 0:
            sol = [abs(int(row[i])) for i in range(n)]
            if all(s in (0, 1) for s in sol):
                check = sum(s * b for s, b in zip(sol, public_key))
                if check == ciphertext:
                    print(f"[+] Solution found: {sol}")
                    return sol

    print("[-] LLL attack failed")
    return None

# 测试
# pk = [99, 234, 180, 67, 196, 115, 75, 191]
# ct = 471
# result = solve_knapsack_ctf(pk, ct)
```

## 6. 相关知识点

- **BKZ 算法**：LLL 的改进版本，使用更大块大小，找到更短的向量
- **高斯启发式**：估算格中最短向量长度的经验公式 λ_1 ≈ sqrt(n/(2πe)) * det(L)^{1/n}
- **NTRU**：后量子密码方案，安全性基于格的 SVP/CVP
- **Learning With Errors (LWE)**：格密码的核心问题，多变量含噪线性方程
- **Ring-LWE / Module-LWE**：基于环和模的 LWE 变体（Kyber、Dilithium）
- **GGH 密码系统**：基于 CVP 的公钥加密（已被破解）
- **Coppersmith 方法**：用于解模多项式的小根
- **Howgrave-Graham 定理**：确保格约简后的多项式在整数上有相同的小根
- **Ajtai-Dwork 密码**：第一个基于最坏情况格问题的密码系统
- **Regev 加密**：基于 LWE 的公钥加密
- **格基约简库**：fplll (C++)、NTL (C++)、SageMath (Python wrapper)
- **Dual Lattice**：对偶格在 CVP 求解中起关键作用
