# Project12

## 泄漏随机数k导致私钥d的泄漏

### 概述

在基于椭圆曲线的数字签名算法中，如果已知随机数 k 和对应的签名信息 (r, s)，并且可以得到消息的哈希值 H(M)，理论上可以计算出私钥 d。
这种情况被称为“私钥泄露”或“非法私钥恢复攻击”，但在实际情况中，椭圆曲线签名算法的随机数 k 是随机选择的，并且在不同的签名中不会重复使用，不应该容易受到此类攻击。

### 原理

现在，如果已知 k、r、s 和消息的哈希值 H(M)，可以通过以下步骤计算私钥 d：

使用签名信息中的 s 值和随机数 k，计算 r = (s * k^-1) mod n，其中 k^-1 是 k 在模 n 意义下的乘法逆元。

使用消息的哈希值 H(M)、已知的 r 和 s，计算 d = ((s * r - H(M)) * s^-1) mod n，其中 s^-1 是 s 在模 n 意义下的乘法逆元。

如果计算正确，得到的 d 就是私钥。

### 代码实现

```
def verify_1(k, r, s):
    t1 = inv(s + r, int_hex(n))
    t2 = k - s
    return (t1 * t2) % int_hex(n)
```

## 随机数k重用导致私钥d泄漏

### 概述

基于椭圆曲线的数字签名算法中，使用了随机数 k 来生成签名。当随机数 k 泄漏，可能会导致私钥 d 泄露。这种情况被称为“k 泄露”或“随机数重用攻击”。
为了避免这种情况，生成签名时必须确保每次都使用新的随机数 k。可以通过使用伪随机数生成器来生成随机数 k，确保它在每次签名中都是唯一的。这样，即使公钥和签名都是公开的，私钥 d 仍然可以保持秘密。

### 原理

如果相同的随机数 k 在两个不同的签名中被使用，即 k1 和 k2 分别用于生成签名 (r1, s1) 和 (r2, s2)，则可能发生问题。假设两个签名中的消息都是相同的，即 H(M1) = H(M2)。

由于 s1 = (H(M1) + d * r1) / k1 和 s2 = (H(M2) + d * r2) / k2，如果 k1 = k2，那么就有：

s1 = (H(M1) + d * r1) / k，而 s2 = (H(M2) + d * r2) / k。

现在，如果将这两个等式相减，可以得到：

s1 - s2 = (H(M1) + d * r1) / k - (H(M2) + d * r2) / k
s1 - s2 = (H(M1) + d * r1 - H(M2) - d * r2) / k
s1 - s2 = (H(M1) - H(M2) + d * (r1 - r2)) / k

现在，攻击者可以通过解这个方程来计算私钥 d：

d = (s1 - s2) * k / (r1 - r2)

因为 k 是已知的（由于重用），攻击者可以轻易地计算出私钥 d。这就是为什么重用相同的随机数 k 会导致私钥泄露的原因。

### 代码实现

```
def verify_2(k, r_1, r_2, s_1, s_2):
    t1 = s_2 - s_1
    t2 = s_1 - s_2 + r_1 - r_2
    return (t1 * inv(t2, int_hex(n))) % int_hex(n)
```

## 两名用户使用同样的随机数k，导致用户之间可以互推出对方使用的私钥d

### 概述

在基于椭圆曲线的数字签名算法中，如果两名用户使用相同的随机数 k 来生成签名，攻击者可以推导出每名用户使用的私钥 d。这是因为 k 的重用会导致签名中的 s 值相同，从而可通过简单的数学计算推导出私钥 d。

### 原理

假设两名用户 Alice 和 Bob 使用相同的随机数 k 来生成签名，签名过程为：

Alice 选择私钥 d_A，并计算公钥 Q_A = d_A * G。

Bob 选择私钥 d_B，并计算公钥 Q_B = d_B * G。

两名用户都使用随机数 k 来生成临时点 R = k * G。

两名用户分别计算消息的哈希值 H(M)。

Alice 计算签名的 s_A 部分：s_A = (H(M) + d_A * r) / k。

Bob 计算签名的 s_B 部分：s_B = (H(M) + d_B * r) / k。

由于 k 是相同的，即 k_A = k_B = k。

将 s_A 和 s_B 的计算公式代入：

s_A = (H(M) + d_A * r) / k
s_B = (H(M) + d_B * r) / k

将两个方程相减：

s_A - s_B = (H(M) + d_A * r) / k - (H(M) + d_B * r) / k

再整理：

s_A - s_B = (d_A - d_B) * r / k

现在，攻击者（Alice和Bob中的一人）可以通过解这个方程来计算 d_A - d_B：

d_A - d_B = (s_A - s_B) * k / r

因为 k 和 r 都是已知的（由于重用），攻击者可以计算出 d_A - d_B。此时，攻击者可以进一步得到 d_A：

d_A = d_B + (s_A - s_B) * k / r

### 代码实现

```
def verify_3(k, r_2, s_2):
    t1 = inv(s_2 + r_2, int_hex(n))
    t2 = k - s_2
    return (t1 * t2) % int_hex(n)
```

## 在ECDSA签名和SM2签名中使用相同的私钥d和随机数k，导致私钥d泄漏

### 概述

在 ECDSA 签名和 SM2 签名中，如果两者使用相同的私钥 d 和随机数 k 来生成签名，攻击者可以推导出私钥 d。
这是因为 ECDSA 和 SM2 都是基于椭圆曲线的数字签名算法，它们共享类似的数学原理。

### 原理

假设攻击者得到了两个签名 (r1, s1) 和 (r2, s2)，以及对应的消息的哈希值 H(M)。

在 ECDSA 签名中：

签名的计算过程为：s = (H(M) + d * r) / k，其中 r 是临时点 R 的 x 坐标的模 n，n 是椭圆曲线的阶数。

两个签名分别为：s1 = (H(M) + d * r1) / k 和 s2 = (H(M) + d * r2) / k。

将这两个等式相减：

s1 - s2 = (H(M) + d * r1) / k - (H(M) + d * r2) / k

s1 - s2 = (H(M) + d * r1 - H(M) - d * r2) / k

s1 - s2 = (d * (r1 - r2)) / k

现在，攻击者可以通过解这个方程来计算私钥 d：

d = (s1 - s2) * k / (r1 - r2)

因为 k 是已知的（由于重用），攻击者可以计算出私钥 d。

在 SM2 签名中：

签名的计算过程为：s = (H(M) + d * r) / (1 + dA) mod n，其中 r 是临时点 R 的 x 坐标的模 n，n 是椭圆曲线的阶数。

两个签名分别为：s1 = (H(M) + d * r1) / (1 + dA) mod n 和 s2 = (H(M) + d * r2) / (1 + dA) mod n。

将这两个等式相减：

s1 - s2 = (H(M) + d * r1) / (1 + dA) mod n - (H(M) + d * r2) / (1 + dA) mod n

由于涉及模运算，直接进行减法计算可能较为复杂，但攻击者仍可以使用模运算的特性来计算出私钥 d。

### 代码实现

```
def verify_4(k, r_1, r_2, s_1, s_2):
    e_1 = (k * s_1 - int_hex(d_A) * r_1) % int_hex(n)
    t1 = s_1 * s_2 - e_1
    t2 = (r_1 - s_1 * s_2 - s_1 * r_2) % int_hex(n)
    return (t1 * inv(t2, int_hex(n))) % int_hex(n)
```

## 实现效果

随机生成d

```
d_A = hex(random.randint(pow(2, 127), pow(2, 128)))[2:]
```

下图中四种情况都可以求解出私钥d。

![image](https://github.com/1-14/Project12/blob/main/7.png)






























