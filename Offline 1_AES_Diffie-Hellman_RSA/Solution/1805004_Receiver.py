import socket

Utils = __import__('1805004_Utils')
AES = __import__('1805004_AES')
Diffie_Hellman = __import__('1805004_Diffie_Hellman')


def client():
    receiver_socket = socket.socket()
    receiver_socket.connect(('127.0.0.1', 12345))
    print("Connected to server")

    print("\nReceiving public modulus, public base and public key from Server")
    received_str = receiver_socket.recv(1024).decode()

    bitLength, public_modulus, public_base, public_key_sender = [int(received_str.split(' ')[i]) for i in range(4)]

    print("\nPublic Modulus: ", public_modulus)
    print("Public Base: ", public_base)
    print("Public Key: ", public_key_sender)

    secret_private_key = Utils.generate_safe_prime(bitLength // 2)
    public_key_receiver = Utils.modExp_LR_K_ary(public_base, secret_private_key, public_modulus)

    print("\nSending public key to sender: ", public_key_receiver)
    receiver_socket.send(str(public_key_receiver).encode())

    shared_secret_key = Diffie_Hellman.shared_key_calculation(public_key_sender, secret_private_key, public_modulus)
    print("\nShared Secret Key: ", shared_secret_key)

    receiver_socket.send("Receiver Ready".encode())
    inform = receiver_socket.recv(1024).decode()

    if inform != "Sender Ready":
        print("Sender not ready")
        return

    print("\nSender Ready")

    all_str = receiver_socket.recv(1024).decode()
    opt_file = all_str.split(' ')[0]
    option = int(opt_file.split('_')[0])
    fileName = opt_file.split('_')[1]
    original_length, length_encrypted, cipher_length = [int(all_str.split(' ')[i]) for i in range(1, 4)]

    cipher_hex_text = receiver_socket.recv(1024).decode()
    while len(cipher_hex_text) < cipher_length:
        cipher_hex_text += receiver_socket.recv(1024).decode()

    print("\nCipher Text Received")
    print("cipher hex text = ", cipher_hex_text)

    decipher_hex_text, decipher_ascii_text, _ = AES.AES_Decryption(bitLength, str(shared_secret_key),
                                                                   cipher_hex_text, length_encrypted, original_length)

    print("\ndecipher hex text = ", decipher_hex_text)
    print("decipher ascii text = ", decipher_ascii_text)

    filePath = "client/"

    if option == 1:
        # Write text to text file
        filePath += "decrypted.txt"
        fb = open(filePath, "w")
        fb.write(decipher_ascii_text)
        fb.close()

    elif option == 2:
        # Write image/pdf or any other file
        ext = fileName.split('.')[1]
        newPath = filePath + "decrypted." + ext
        file_img = open(newPath, 'wb')
        file_img.write(eval(decipher_ascii_text))
        file_img.close()

    receiver_socket.close()


client()
