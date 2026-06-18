---
category: "密码学"
tags: ["XOR", "线性分析", "差分分析", "代数攻击", "S盒", "线性密码分析", "Z3求解器", "方程组求解", "CTF构造题"]
difficulty: "中级"
---

# XOR 与数学构造题

## 1. 概述

XOR（异或）是密码学中最基础的运算，也是 CTF 中出现频率极高的考点。从简单的单字节 XOR 加密到复杂的多轮非线性 XOR 结构，XOR 的数学性质使其成为构造攻击的天然对象。

本章涵盖：
- **XOR 基础性质与攻击**
- **线性密码分析的数学基础**
- **差分分析的基本思路**
- **Z3 求解器在密码学中的应用**
- **S-Box 的代数构造与逆向**
- **多变量方程组求解（代数攻击）**

## 2. 核心原理（含数学推导）

### 2.1 XOR 的代数性质

XOR 运算符 `⊕` 等价于 GF(2) 上的加法：
- `a ⊕ b = (a + b) mod 2` （逐位实现）
- `a ⊕ a = 0`
- `a ⊕ 0 = a`
- `a ⊕ b = b ⊕ a`（交换律）
- `(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)`（结合律）

在 GF(2)^n 空间中，XOR 构成向量空间的加法运算。

**多字节 XOR 的矩阵表示**：
若将字节数组 `[p_0, p_1, ..., p_n]` 写为列向量，则 XOR 加密 `c = M * p`
其中 M 是 GF(2) 上的矩阵。

### 2.2 线性密码分析 (Linear Cryptanalysis)

线性密码分析由 Matsui 于 1993 年提出，用于攻击 DES。

核心：寻找明文中某些位、密文中某些位和密钥中某些位的线性近似。
`P[i1] ⊕ P[i2] ⊕ ... ⊕ C[j1] ⊕ C[j2] ⊕ ... = K[k1] ⊕ K[k2] ⊕ ...`
这个等式以概率 p != 1/2 成立（偏差 ε = |p - 1/2|）。

攻击复杂度与 1/ε^2 成正比。

对于 DES，Matsui 使用两轮近似：`PL[15] ⊕ F(PR, K1)[7,18,24,29] = CL[7,18,24,29] ⊕ F(CR, K15)[15] = K1[22] ⊕ K3[22]`
此等式以概率约 0.69 成立。

### 2.3 差分密码分析 (Differential Cryptanalysis)

差分分析由 Biham 和 Shamir 于 1990 年提出。

核心：分析输入差分 ΔP = P1 ⊕ P2 如何在加密过程中演变为输出差分 ΔC = C1 ⊕ C2。

对于 S-Box f，差分分布表：
`DDT(Δin, Δout) = |{x : f(x) ⊕ f(x ⊕ Δin) = Δout}|`

高概率的差分特征 (differential characteristic) 可用于区分攻击和密钥恢复。

### 2.4 代数攻击基础

将密码转化为 GF(2) 上的多变元多项式方程组：
- 每个 S-Box 可表示为次数 >= 2 的多项式
- 通过线性化、XL 算法或 Groebner 基求解

对于 AES，S-Box 的代数表达式为：
`S(x) = 05*x^{254} + 09*x^{253} + F9*x^{251} + ... + 63`

## 3. 关键技巧/攻击方法（含 Python 代码）

### 3.1 单字节 XOR 破解

```python
import string

def single_byte_xor_crack(ciphertext: bytes) -> list:
    """
    单字节 XOR 破解：暴力枚举所有 256 种密钥
    使用英语文本评分函数选择最佳结果
    """
    def score_english(text: bytes) -> float:
        """基于英文字母频率的评分函数"""
        freq = {
            ' ': 15.0, 'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51,
            'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99,
            'd': 4.25, 'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41,
            'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93,
            'b': 1.49, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
            'q': 0.10, 'z': 0.07,
        }
        return sum(freq.get(chr(b).lower(), -5) for b in text if b >= 32)

    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in ciphertext)
        score = score_english(plain)
        results.append((key, plain, score))

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:5]

# 使用
ct = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
for key, plain, score in single_byte_xor_crack(ct):
    print(f"[+] Key=0x{key:02x} ({chr(key)}): {plain.decode('ascii', errors='replace')} (score={score:.2f})")
```

### 3.2 重复密钥 XOR 破解

```python
def hamming_distance(b1: bytes, b2: bytes) -> int:
    """计算两个字节串的汉明距离（不同bit数）"""
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))

def break_repeating_key_xor(ciphertext: bytes, max_keylen: int = 40) -> tuple:
    """
    破解重复密钥 XOR (Vigenere XOR)
    使用汉明距离推测密钥长度，然后逐字节破解
    """
    # 1. 推测密钥长度
    key_scores = []
    for keylen in range(2, min(max_keylen + 1, len(ciphertext) // 4)):
        # 取前4个块的平均汉明距离
        blocks = [ciphertext[i*keylen:(i+1)*keylen] for i in range(4)]
        dist = 0
        count = 0
        for i in range(len(blocks)):
            for j in range(i+1, len(blocks)):
                dist += hamming_distance(blocks[i], blocks[j]) / keylen
                count += 1
        key_scores.append((keylen, dist / count))

    key_scores.sort(key=lambda x: x[1])

    # 取前3个最可能的密钥长度
    best_results = []
    for keylen, _ in key_scores[:3]:
        # 2. 将密文按密钥位置分组
        key = bytearray()
        for pos in range(keylen):
            group = ciphertext[pos::keylen]
            candidates = single_byte_xor_crack(group)
            key.append(candidates[0][0])  # 取最佳密钥字节

        # 3. 解密
        plain = bytes(ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext)))
        best_results.append((bytes(key), plain))

    return best_results
```

### 3.3 构造 XOR 方程组并求解

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools

def solve_xor_linear_system(known_pt: bytes, known_ct: bytes, target_ct: bytes) -> bytes:
    """
    已知部分明文-密文对，求解未知明文
    假设: 加密方式为固定密钥的一次性XOR（密钥 >= 消息长度）
    但密钥未知
    """
    # 从已知对恢复部分密钥
    partial_key = bytes(pc ^ ct for pc, ct in zip(known_pt, known_ct))
    # 用部分密钥解密目标
    result = bytes(tc ^ partial_key[i % len(partial_key)]
                   for i, tc in enumerate(target_ct))
    return result

def solve_multi_xor_system(equations):
    """
    解 GF(2) 上的 XOR 线性方程组
    equations: [(coeffs, target)] 其中 coeffs 是字节位掩码
    例如：a⊕b⊕c = 1, a⊕c = 0, b = 1
         => coeffs = [0b111, 0b101, 0b010], target = [1, 0, 1]
    """
    n_vars = len(equations[0][0].bit_length())
    # 构建 GF(2) 矩阵
    import numpy as np
    A = np.zeros((len(equations), n_vars), dtype=np.int8)
    b = np.zeros(len(equations), dtype=np.int8)

    for i, (coeff_mask, target) in enumerate(equations):
        for j in range(n_vars):
            A[i, j] = (coeff_mask >> j) & 1
        b[i] = target

    # 高斯消元（GF(2)）
    for col in range(n_vars):
        pivot = None
        for row in range(col, len(equations)):
            if A[row, col] == 1:
                pivot = row
                break
        if pivot is None:
            continue
        # 交换
        A[[col, pivot]] = A[[pivot, col]]
        b[col], b[pivot] = b[pivot], b[col]
        # 消元
        for row in range(len(equations)):
            if row != col and A[row, col] == 1:
                A[row] ^= A[col]
                b[row] ^= b[col]

    return b[:n_vars]
```

### 3.4 Z3 求解器在密码题中的应用

```python
from z3 import *

def z3_crack_simple_xor():
    """
    使用 Z3 求解 XOR 约束
    问题：已知 a ⊕ b = 0x41, a ⊕ b ⊕ c = 0x56, c = ?
    """
    a = BitVec('a', 8)
    b = BitVec('b', 8)
    c = BitVec('c', 8)

    s = Solver()
    s.add(a ^ b == 0x41)
    s.add(a ^ b ^ c == 0x56)

    if s.check() == sat:
        m = s.model()
        print(f"[+] a = {m[a]}, b = {m[b]}, c = {m[c]}")
        return m
    return None

def z3_crack_sbox(sbox_inputs, sbox_outputs):
    """
    使用 Z3 恢复未知的 S-Box 映射（已知输入输出对）
    假设 S-Box 由仿射变换构成
    """
    s = Solver()

    # S(x) = (A * x) ⊕ b，其中 A 是 8x8 GF(2) 矩阵，b 是 8-bit 向量
    A = [[Bool(f'A_{i}_{j}') for j in range(8)] for i in range(8)]
    b = [Bool(f'b_{k}') for k in range(8)]

    for input_val, output_val in zip(sbox_inputs, sbox_outputs):
        in_bits = [(input_val >> j) & 1 for j in range(8)]
        out_bits = [(output_val >> j) & 1 for j in range(8)]

        for i in range(8):
            # 计算 A 的第 i 行与输入的乘积（GF(2)）
            product = BoolVal(False)
            for j in range(8):
                if in_bits[j]:
                    product = Xor(product, A[i][j])
            expected = Xor(product, b[i])
            s.add(expected if out_bits[i] else Not(expected))

    if s.check() == sat:
        m = s.model()
        print("[+] S-Box parameters found!")
        return m
    return None
```

### 3.5 差分分析工具

```python
def compute_sbox_ddt(sbox: list, n_bits: int = 8) -> dict:
    """
    计算 S-Box 的差分分布表 (DDT)

    参数:
        sbox: S-Box 查找表（256 个 8-bit 值）
        n_bits: 输入输出位数
    返回:
        DDT 字典 {(delta_in, delta_out): count}
    """
    ddt = {}
    n = 2**n_bits

    for delta_in in range(n):
        for x in range(n):
            y1 = sbox[x]
            y2 = sbox[x ^ delta_in]
            delta_out = y1 ^ y2
            key = (delta_in, delta_out)
            ddt[key] = ddt.get(key, 0) + 1

    return ddt

def find_best_differential(ddt: dict, min_prob: float = 0.01) -> list:
    """
    寻找最佳的差分特征（高概率差分对）
    """
    best = []
    n_total = sum(v for (di, do), v in ddt.items() if di == list(ddt.keys())[0][0])

    for (di, do), count in ddt.items():
        prob = count / 256  # 总输入对为 256
        if prob >= min_prob and di != 0:
            best.append((di, do, prob, count))

    best.sort(key=lambda x: x[2], reverse=True)
    return best[:20]

# 示例：AES S-Box 的差分特征
def aes_sbox_example():
    # AES S-Box (简化示例，仅前64个值)
    aes_sbox_partial = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
    ] * 32  # 仅示例
    ddt = compute_sbox_ddt(aes_sbox_partial, 8)
    best = find_best_differential(ddt)
    for di, do, prob, cnt in best[:5]:
        print(f"  di=0x{di:02x} -> do=0x{do:02x} prob={prob:.4f} count={cnt}")
```

### 3.6 混合布尔算术 (MBA) 混淆与反混淆

```python
def mba_deobfuscate(expr: str) -> str:
    """
    简化混合布尔算术表达式
    例如: (x ^ y) + 2*(x & y) => x + y
          (x | y) - (x & y) => x ^ y
    """
    # 使用 Z3 验证等价性
    x = BitVec('x', 32)
    y = BitVec('y', 32)

    identities = [
        ("(x ^ y) + 2*(x & y)", "x + y"),
        ("(x | y) - (x & y)", "x ^ y"),
        ("(x + y) - 2*(x & y)", "x ^ y"),
        ("(x & y) + (x | y)", "x + y"),
    ]

    for complex_expr, simple_expr in identities:
        # 验证
        s = Solver()
        complex_val = eval(complex_expr)
        simple_val = eval(simple_expr)
        s.add(complex_val != simple_val)
        if s.check() == unsat:
            print(f"[+] Identity confirmed: {complex_expr} == {simple_expr}")
```

### 3.7 多轮 XOR 的线性特征分析

```python
def find_linear_approximation(sbox, n_bits=4):
    """
    寻找 S-Box 的线性近似表 (LAT)
    LAT[in_mask][out_mask] = |{x: parity(x & in_mask) == parity(sbox[x] & out_mask)}| - 2^{n-1}
    偏差 = LAT_entry / 2^n
    """
    n = 1 << n_bits
    lat = [[0] * n for _ in range(n)]

    for in_mask in range(n):
        for out_mask in range(n):
            count = 0
            for x in range(n):
                in_par = bin(x & in_mask).count('1') & 1
                out_par = bin(sbox[x] & out_mask).count('1') & 1
                if in_par == out_par:
                    count += 1
            lat[in_mask][out_mask] = count - (n // 2)

    return lat

def best_linear_bias(lat, n_bits=4):
    """找出偏差最大的线性近似（绝对值）"""
    n = 1 << n_bits
    best = []
    for in_mask in range(1, n):
        for out_mask in range(1, n):
            bias = abs(lat[in_mask][out_mask]) / n
            if bias > 0.25:
                best.append((in_mask, out_mask, bias))

    best.sort(key=lambda x: x[2], reverse=True)
    return best[:10]
```

## 4. 常见误区与注意事项

1. **单字节 XOR ≠ 安全**：密钥空间仅 256，且暴力破解后可用语言统计判断结果。
2. **重复密钥 XOR ≠ 维吉尼亚密码**：维吉尼亚使用模 26 加法，XOR 是 bitwise 操作。但破解方法类似（先用汉明距离找密钥长度）。
3. **多轮 XOR 不一定更安全**：`P ⊕ K1 ⊕ K2` 等价于 `P ⊕ (K1 ⊕ K2)`，即单轮 XOR，密钥空间不变。
4. **XOR 的矩阵表示**：在大方程系统中考虑使用线性代数直接求解（GF(2) 高斯消元 O(n^3)）。
5. **Z3 不适合大规模问题**：256 位以上的非线性约束可能导致求解时间极长，应用 Groebner 基或 SAT 求解器。
6. **差分分析 vs 线性分析**：差分攻击用输入输出对的差分分布；线性攻击用输入输出的线性组合偏差。两者各适用不同场景。
7. **S-Box 的代数安全性**：AES S-Box 的 GF(2^8) 逆 + 仿射变换设计使差分/线性攻击极其困难（最佳偏差 ~2^{-3}，最佳差分概率 ~2^{-6}）。

## 5. 实战示例

**场景**：题目给出一个简单 "密码算法"：4-bit S-Box 的两轮 SPN 结构。已知 10 组明文-密文对，恢复密钥。

```python
def crack_spn_2round(plaintexts, ciphertexts, sbox, sbox_inv, pbox, num_rounds=2):
    """
    破解两轮 SPN 结构

    SPN 结构: 轮密钥加 -> S-Box -> P-Box -> 轮密钥加 -> ... -> 输出

    攻击思路：分离最后一轮的密钥
    """
    n_blocks = len(plaintexts)
    block_size = 16  # 16 nibbles (4-bit each)
    key_candidates = [set(range(16)) for _ in range(block_size)]

    # 对每组明文-密文对迭代
    for pt, ct in zip(plaintexts, ciphertexts):
        # 猜测第 2 个轮密钥的每个 nibble
        for pos in range(block_size):
            valid_keys = set()
            for k2_guess in range(16):
                # 计算最后一个 S-Box 的输入
                sbox_input = sbox_inv[ct[pos] ^ k2_guess]
                # 通过 P-Box 反向传播
                pbox_input_nibble = sbox_input  # 简化，假设 P-Box 已知

                # 检查是否与已知特征一致
                # （此处需结合差分特征判断，简化省略）
                valid_keys.add(k2_guess)
            key_candidates[pos] &= valid_keys

    return key_candidates
```

## 6. 相关知识点

- **SPN (Substitution-Permutation Network)**：AES 使用的基本结构（S-Box 替换 + Permutation）
- **Feistel 网络**：DES 使用的基本结构（左右平分迭代）
- **Linear Hull (线性壳)**：多个线性近似组合的累积效果
- **Impossible Differential (不可能差分)**：概率为 0 的差分特征用于密钥过滤
- **Integral/Square Attack (积分攻击)**：针对 AES 的高效攻击
- **Algebraic Normal Form (ANF)**：布尔函数在 GF(2) 上的多项式表示
- **NAND/NOR 组合与 XOR 实现**：现代电路设计中 XOR 的实现成本
- **Groebner 基 与 F4/F5 算法**：多项式方程组求解（代数攻击核心）
- **SAT 求解器**：布尔公式可满足性求解（CryptoMinisat）
- **Bent 函数与平衡性**：密码学布尔函数的安全性质
- **MDS 矩阵**：AES MixColumns 使用的最大距离可分矩阵
- **Walsh-Hadamard 变换**：布尔函数的频谱分析（非线性度度量）
