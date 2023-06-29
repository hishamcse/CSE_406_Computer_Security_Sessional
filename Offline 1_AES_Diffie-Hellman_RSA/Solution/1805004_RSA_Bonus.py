import random

Utils = __import__('1805004_Utils')


def ConvertToInt(message_str):
    res = 0
    for i in range(len(message_str)):
        res = res * 256 + ord(message_str[i])
    return res


def ConvertToStr(n):
    res = ""
    while n > 0:
        res += chr(n % 256)
        n //= 256
    return res[::-1]


def ExtendedEuclid(a, b):
    if b == 0:
        return 1, 0
    (x, y) = ExtendedEuclid(b, a % b)
    k = a // b
    return y, x - k * y


def InvertModulo(a, n):
    (b, x) = ExtendedEuclid(a, n)
    if b < 0:
        b = (b % n + n) % n
    return b


def lambda_lcm(p, q):
    return (p - 1) * (q - 1)


def find_exponent(phi):
    exponent_e = random.randrange(2, phi)
    g = Utils.gcd(exponent_e, phi)

    while g != 1:
        exponent_e = random.randrange(2, phi)
        g = Utils.gcd(exponent_e, phi)

    return exponent_e


def RSA_Key_Generation(k):
    while True:
        p = Utils.generate_safe_prime(k)
        q = Utils.generate_safe_prime(k)
        if p != q:
            break

    modulo_n = p * q
    print("\nn = ", modulo_n)

    phi = lambda_lcm(p, q)
    print("λ = ", phi)

    exponent_e = find_exponent(phi)
    print("e = ", exponent_e)

    exponent_d = InvertModulo(exponent_e, phi)
    print("d = ", exponent_d)

    public_key = (exponent_e, modulo_n)
    private_key = (exponent_d, modulo_n)

    print("\npublic key, (e,n) = ", public_key)
    print("private key, (d,n) = ", private_key)

    return public_key, private_key


def RSA_Encryption(public_key, message):
    exponent_e, modulo_n = public_key
    cipher_text = Utils.modExp_LR_K_ary(message, exponent_e, modulo_n)
    return cipher_text


def RSA_Decryption(private_key, cipher_text):
    exponent_d, modulo_n = private_key
    message = Utils.modExp_LR_K_ary(cipher_text, exponent_d, modulo_n)
    return message


def independent_RSA_Key_Exchange():
    message = "Can They Do This"
    print("Message : ", message)

    random.seed(42)
    public_key, private_key = RSA_Key_Generation(256)

    cipher_int = RSA_Encryption(public_key, ConvertToInt(message))
    print("\nCipher Text : ", cipher_int)

    message_int = RSA_Decryption(private_key, cipher_int)
    print("Decipher Text : ", ConvertToStr(message_int))


def independent_RSA_Authentication():
    message = "Can They Do This !!!!!!!"
    print("Message : ", message)

    random.seed(42)
    print("\nAlice generating his public and private keys")
    public_key_A, private_key_A = RSA_Key_Generation(256)
    print("\nBob generating his public and private keys")
    public_key_B, private_key_B = RSA_Key_Generation(256)

    # what A will do
    cipher_int = RSA_Encryption(public_key_B, ConvertToInt(message))
    cipher_int_2 = RSA_Encryption(private_key_A, cipher_int)
    print("\nCipher Text after double encryption: ", cipher_int_2)

    # what B will do
    message_int = RSA_Decryption(public_key_A, cipher_int_2)
    message_int_2 = RSA_Decryption(private_key_B, message_int)
    print("\nDecipher Text after double decryption: ", ConvertToStr(message_int_2))


def independent_RSA():
    choice = int(input("Enter 1 for Key Exchange and 2 for Authentication : "))
    if choice == 1:
        independent_RSA_Key_Exchange()
    elif choice == 2:
        independent_RSA_Authentication()
    else:
        print("Invalid Choice")


independent_RSA()
