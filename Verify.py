import sys
import struct
import random
from math import gcd, ceil, floor
from gmssl import sm3


def int_hex(str):
    return int(str, 16)


def sm3_hash(message):
    message = message.encode('utf-8')
    msg_list = [i for i in message]
    hash_hex = sm3.sm3_hash(msg_list)

    return hash_hex


def inv(a, m):
    if gcd(a, m) != 1:
        return None

    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a // b) * y

    t1, x, t2 = extended_gcd(a, m)
    return x % m


def add_ECC(P, Q):
    if P == 0:
        return Q
    if Q == 0:
        return P
    x1, y1, x2, y2 = int_hex(P[0]), int_hex(P[1]), int_hex(Q[0]), int_hex(Q[1])
    q_int = int_hex(q)
    tmp1, tmp2 = y2 - y1, inv(x2 - x1 % q_int, q_int)
    l = tmp1 * tmp2 % q_int
    x = (l * l - x1 - x2) % q_int
    y = (l * (x1 - x) - y1) % q_int
    res = (hex(x)[2:], hex(y)[2:])
    return res


def double_ECC(P):
    if P == 0:
        return P
    x1, y1 = int_hex(P[0]), int_hex(P[1])
    a_int, q_int = int_hex(a), int_hex(q)
    tmp1 = 3 * x1 * x1 + a_int
    tmp2 = inv(2 * y1, q_int)
    l = (tmp1 * tmp2) % q_int
    x = (l * l - 2 * x1) % q_int
    y = (l * (x1 - x) - y1) % q_int
    Q = (hex(x)[2:], hex(y)[2:])
    return Q


def mul_ECC(P, k):
    k_bin = bin(k)[2:]
    i = len(k_bin) - 1
    Q = P
    if i > 0:
        k = k - 2**i
        while i > 0:
            Q = double_ECC(Q)
            i -= 1
        if (k > 0):
            Q = add_ECC(Q, mul_ECC(P, k))

    return Q


def check_ECC(P):
    x, y = int_hex(P[0]), int_hex(P[1])
    q_int, a_int, b_int = int_hex(q), int_hex(a), int_hex(b)
    if (y * y) % q_int == (x * x * x + a_int * x + b_int) % q_int:
        return True
    else:
        return False


def KDF(Z, klen):
    ct = int_hex("00000001")
    ceil_val = ceil(klen / v)
    floor_val = floor(klen / v)
    hash = b""

    for i in range(1, ceil_val):
        ct_hex = hex(ct)[2:]
        hash += sm3_hash(Z + (ct_hex).zfill(8))
        ct += 1
    ct_hex = hex(ct)[2:]
    if klen % v == 0:
        hash_x = sm3_hash(Z + (ct_hex).zfill(8))
    else:
        hash_x = sm3_hash(Z + (ct_hex).zfill(8))
        hash_x = hash_x[:((klen - v * floor_val) // 4)]
    K = hash.hex() + hash_x

    return K


def sm2_enc(M, P_A):
    klen = len(M) * 4
    k = hex(random.randint(1, int_hex(n) - 1))[2:]
    k_int = int_hex(k)
    C1 = mul_ECC(G, k_int)
    x2, y2 = mul_ECC(P_A, k_int)
    t = KDF(x2 + y2, klen)

    C2 = hex(int_hex(M) ^ int_hex(t))[2:]
    C3 = sm3_hash(x2 + M + y2)
    C = C1[0] + C1[1] + C2 + C3
    len_x = len(C1[0])
    len_y = len(C1[1])
    len_C2 = len(C2)

    return C, len_x, len_y, len_C2


def sm2_dec(CT, d_A, len_x, len_y, len_C2, klen):
    x1 = CT[:len_x]
    y1 = CT[len_x:len_x + len_y]
    C1 = (x1, y1)
    if check_ECC(C1) == False:
        print("False!")
        return ""
    x2, y2 = mul_ECC(C1, int_hex(d_A))
    t = KDF(x2 + y2, klen)

    C2 = CT[len_x + len_y:len_x + len_y + len_C2]
    M = hex(int_hex(C2) ^ int_hex(t))[2:]

    u = sm3_hash(x2 + M + y2)
    C3 = CT[len_x + len_y + len_C2:]
    if u != C3:
        print("False!")
        return ""

    return M


#参数设定
q = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
x_G = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
y_G = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
G = (x_G, y_G)
n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
#私钥
d_A = hex(random.randint(pow(2, 127), pow(2, 128)))[2:]
P_A = mul_ECC(G, int_hex(d_A))
v = 256

M = "123"
M_1 = "321"
M_2 = "456"

ID_A = "654"


def SM2_sign(M):
    tmp = str(len(ID_A)) + ID_A + a + b + x_G + y_G + P_A[0] + P_A[1]
    Z_A = sm3_hash(tmp)

    M_ = Z_A + M
    e = sm3_hash(M_)
    #k = random.randint(1, int_hex(n) - 1)
    kG = mul_ECC(G, k)

    r = (int_hex(e) + int_hex(kG[0])) % int_hex(n)
    s = (inv(1 + int_hex(d_A), int_hex(n)) *
         (k - r * int_hex(d_A))) % int_hex(n)

    return r, s


def ECDSA_sign(M):
    kG = mul_ECC(G, k)
    e = sm3_hash(M)

    r = int_hex(kG[0]) % int_hex(n)
    s = (int_hex(e) + r * int_hex(d_A)) * inv(k, int_hex(n)) % int_hex(n)

    return r, s


def verify_1(k, r, s):
    t1 = inv(s + r, int_hex(n))
    t2 = k - s
    return (t1 * t2) % int_hex(n)


def verify_2(k, r_1, r_2, s_1, s_2):
    t1 = s_2 - s_1
    t2 = s_1 - s_2 + r_1 - r_2
    return (t1 * inv(t2, int_hex(n))) % int_hex(n)


def verify_3(k, r_2, s_2):
    t1 = inv(s_2 + r_2, int_hex(n))
    t2 = k - s_2
    return (t1 * t2) % int_hex(n)


def verify_4(k, r_1, r_2, s_1, s_2):
    e_1 = (k * s_1 - int_hex(d_A) * r_1) % int_hex(n)
    t1 = s_1 * s_2 - e_1
    t2 = (r_1 - s_1 * s_2 - s_1 * r_2) % int_hex(n)
    return (t1 * inv(t2, int_hex(n))) % int_hex(n)


###########################################################

k = 202100180118

print(f'd = {int_hex(d_A)}')

r, s = SM2_sign(M)
t1 = verify_1(k, r, s)
print(f'If k is leaked, we can get d = {t1}')

###########################################################

r_1, s_1 = SM2_sign(M_1)
r_2, s_2 = SM2_sign(M_2)

t2 = verify_2(k, r_1, r_2, s_1, s_2)
print(f'If k is reused, we can get d = {t2}')

###########################################################

t3 = verify_3(k, r_2, s_2)
print(f'If k is reused by two users, we can get another d = {t3}')

###########################################################

r_1, s_1 = ECDSA_sign(M_1)
r_2, s_2 = SM2_sign(M_2)

t4 = verify_4(k, r_1, r_2, s_1, s_2)
print(f'If k and d are reused in ECDSA and SM2, we can get d = {t4}')
