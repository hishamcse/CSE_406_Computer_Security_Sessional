import random
import time
import tabulate

Utils = __import__('1805004_Utils')


# link : https://crypto.stackexchange.com/questions/56155/primitive-root-of-a-very-big-prime-number-elgamal-ds
def find_primitive_root(p, min_g, max_g):
    min_g = max(2, min_g)  # to ignore 1
    max_g = min(max_g, p - 2)  # to ignore p - 1

    q = (p - 1) // 2

    g = min_g
    while g <= max_g:
        if Utils.gcd(g, p) == 1 and Utils.modExp_LR_K_ary(g, q, p) != 1:
            return g
        g += 1

    # as no primitive root found in the given range, so take any prime in that range
    for i in range(min_g, max_g + 1):
        if Utils.miller_rabin(i):
            return i

    return -1


def shared_key_calculation(public_key, private_key, public_modulus):
    return Utils.modExp_LR_K_ary(public_key, private_key, public_modulus)


def Diffie_Hellman(k, min_g, max_g, time_arr):
    bits = k

    t1 = time.time()
    safe_prime = Utils.generate_safe_prime(bits)
    t2 = time.time()
    time_arr[0] += (t2 - t1)
    print("public modulus, p : ", safe_prime)
    # print("length of public modulus p : ", len(str(bin(safe_prime)[2:])))

    t1 = time.time()
    g = find_primitive_root(safe_prime, min_g, max_g)
    t2 = time.time()
    time_arr[1] += (t2 - t1)
    print("public base, g : ", g)

    t1 = time.time()
    a = Utils.generate_safe_prime(bits // 2)
    b = Utils.generate_safe_prime(bits // 2)
    t2 = time.time()
    time_arr[2] += (t2 - t1) / 2.0

    print("\nsecret private key of sender, a : ", a)
    # print("length of secret private key sender a : ", len(str(bin(a)[2:])))
    print("secret private key of receiver, b : ", b)
    # print("length of secret private key receiver b : ", len(str(bin(b)[2:])))

    t1 = time.time()
    A = Utils.modExp_LR_K_ary(g, a, safe_prime)
    B = Utils.modExp_LR_K_ary(g, b, safe_prime)
    t2 = time.time()
    time_arr[3] += (t2 - t1) / 2.0

    print("\npublic key of sender, A : ", A)
    print("public key of receiver, B : ", B)

    t1 = time.time()
    m = shared_key_calculation(A, b, safe_prime)
    n = shared_key_calculation(B, a, safe_prime)
    t2 = time.time()
    time_arr[4] += (t2 - t1) / 2.0

    print("\nsender computes : ", n)
    print("receiver computes : ", m)
    print("same computation result : ", m == n)

    print("\nSo, shared secret key", m)


def independent_diffie_hellman():
    min_g = 300
    max_g = 35467

    time_list = []
    for k in [128, 192, 256]:
        print("\n---------------- Generating for k = ", k, "bits --------------------\n")
        time_arr = [0.0] * 5

        for r in Utils.seed_list:
            print("\n---------------- Generating for seed = ", r, "--------------------\n")
            random.seed(r)
            Diffie_Hellman(k, min_g, max_g, time_arr)

        time_arr = [t / 5.0 for t in time_arr]
        time_list.append(time_arr)

    print("\n\n ------------------------------ Time Related Performance ------------------------------\n")

    columns = ["k", "p", "g", "a or b", "A or B", "shared key"]
    data_table = ["128", time_list[0][0], time_list[0][1], time_list[0][2], time_list[0][3], time_list[0][4]], \
        ["192", time_list[1][0], time_list[1][1], time_list[1][2], time_list[1][3], time_list[1][4]], \
        ["256", time_list[2][0], time_list[2][1], time_list[2][2], time_list[2][3], time_list[2][4]]

    print(tabulate.tabulate(data_table, columns, tablefmt="fancy_grid", numalign="center", stralign="center"))


independent_diffie_hellman()
