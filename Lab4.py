from Cryptodome.Cipher import DES
from Cryptodome.Random import get_random_bytes
import random
from sympy import isprime
import time
import hashlib

def generate_large_prime(bit_length):
    candidate = random.getrandbits(bit_length)
    candidate |= (1 << bit_length - 1) | 1

    while not isprime(candidate):
        candidate += 2

    return candidate

def des(A, B):
    tmp_key = [B[i:i+7] for i in range(0, len(B), 7)]

    key = ''
    for i in tmp_key:
        key += '1' + i

    key = int(key, 2).to_bytes(8, byteorder='big')
    text = int(A, 2).to_bytes(8, byteorder='big')
    IV = get_random_bytes(8)
    #IV = b'\xc0\xb1\x13\xd9\\im.'

    cipher = DES.new(key, DES.MODE_CBC, IV=IV)
    return cipher.encrypt(text)

def XOR(a, b):
    result = ""
    for i in range(len(a)):
        result += str(int(a[i]) ^ int(b[i]))
    return result


def G1(t, c):
    # step 1
    t_blocks = [t[i:i+32] for i in range(0, len(t), 32)]
    # step 2
    c_blocks = [c[i:i+32] for i in range(0, len(c), 32)]
    # step 3
    u = [XOR(i, j) for i, j in zip(t_blocks, c_blocks)]
    # step 4
    Y = []
    for i in range(5):
        # step 4.1
        b1 = c_blocks[(i + 4) % 5]
        b2 = c_blocks[(i + 3) % 5]
        # step 4.2
        a1 = u[2]
        a2 = XOR(u[(i + 1) % 5], u[(i + 4) % 5])
        # step 4.3
        A = a1 + a2
        B = b1[8:] + b2
        # step 4.4
        tmp_y = des(A, B)
        y = ''
        for j in tmp_y:
            y += bin(j)[2:].zfill(8)
        Y.append(y)
    # step 5
    Z = ''
    for i in range(5):
        Z += XOR(XOR(Y[(i + 2) % 5][32:], Y[(i + 3) % 5][:32]), Y[i][:32])
    # step 6
    return int(Z, 2)

def FIPS_186(m, q):
    # step 1
    b = 160
    # step 2
    s = random.randint(0, 2 ** b)
    print("q = " + str(q) + ";")
    print("s = " + str(s) + ";")
    s = int(bin(s)[2:].zfill(b))
    # step 3
    t = 0x67452301EFCDAB8998BADCFE10325476C3D2E1F0
    t = bin(t)[2:].zfill(b)
    # step 4
    X = []
    for i in range(m):
        # step 4.1
        y = random.randint(0, 2 ** b)
        # step 4.2
        z = (s + y) % 2**b
        z = bin(z)[2:].zfill(b)
        # step 4.3
        x = G1(t, z) % q
        # step 4.4
        s = (1 + s + x) % 2**b
        X.append(x)

    return X

def saveFile(out_sec):
    with open("out_seq.txt", "w") as file:
        file.write(str(out_sec))

    out_sec_bin = ''
    for i in out_sec:
        out_sec_bin += bin(i)[2:]

    with open("out_seq_bin.txt", "w") as file:
        file.write(out_sec_bin)

def testTime():
    count_tests = 100
    all_time = 0
    for i in range(count_tests):
        q = generate_large_prime(160)
        start_time = time.time()
        FIPS_186(256, q)
        end_time = time.time() - start_time
        all_time += end_time

    print(all_time / count_tests)

#testTime()

q = generate_large_prime(160)
out_sequence = FIPS_186(128, q)
saveFile(out_sequence)


