import socket

Utils = __import__('1805004_Utils')
AES = __import__('1805004_AES')
Diffie_Hellman = __import__('1805004_Diffie_Hellman')


def sender_AES_operation(bitLength, shared_secret_key):
    option = int(input("\nEnter 0 for normal text, Enter 1 to read from text file, Enter 2 for any file (pdf or image "
                       "or others): "))

    fileName = ""
    filePath = ""

    if option != 0:
        fileName = input("\nEnter file path: ")
        filePath = "server/" + fileName

    if option > 2:
        print("Invalid input")
        return

    if option == 0:
        # Read Text From input
        plainText = input("Enter plain text: ")

    elif option == 1:
        # Read Text From Text Files
        while fileName.split('.')[1] != 'txt':
            print("Invalid file type")
            fileName = input("Enter file path again: ")

        file = open(filePath, "r")
        plainText = file.read()
        file.close()

    else:
        # Image File or pdf file direct
        file_img = open(filePath, 'rb')
        image = file_img.read()
        plainText = str(image)
        file_img.close()

    original_length = len(plainText)

    print("\nSending Plain Text/File:")
    print("Plain Text/File (In ASCII): ", plainText)

    cipher_hex_text, _, length_encrypted, _, _ = AES.AES_Encryption(bitLength, str(shared_secret_key), plainText)
    print("\ncipher hex text = ", cipher_hex_text)

    return option, fileName, cipher_hex_text, original_length, length_encrypted


def establish_entities_creation(bitLength, min_g, max_g):
    p = Utils.generate_safe_prime(bitLength)
    g = Diffie_Hellman.find_primitive_root(p, min_g, max_g)
    a = Utils.generate_safe_prime(bitLength // 2)
    A = Utils.modExp_LR_K_ary(g, a, p)

    return p, g, a, A


def server():
    bit_length = int(input("Enter the bit length: "))
    if bit_length != 128 and bit_length != 192 and bit_length != 256:
        print("Invalid bit length")
        return

    min_g = 300
    max_g = 35467

    public_modulus, public_base, secret_private_key, public_key = establish_entities_creation(bit_length, min_g, max_g)

    print("\nPublic Modulus: ", public_modulus)
    print("Public Base: ", public_base)
    print("Public Key: ", public_key)

    sender_socket = socket.socket()
    print("\nSocket successfully created")
    sender_socket.bind(('', 12345))
    print("Socket binded to 3000")
    sender_socket.listen(5)
    print("Socket is listening.... Waiting for connection with receiver")

    while True:
        connected_socket, address = sender_socket.accept()
        print("\nGot connection from receiver end : ", address)

        all_str = str(bit_length) + " " + str(public_modulus) + " " + str(public_base) + " " + str(public_key)

        connected_socket.send(all_str.encode())
        print("\nPublic Modulus, Public Base and Public Key Sent")

        receiver_public_key = int(connected_socket.recv(1024).decode())
        print("\nReceiver Public Key: ", receiver_public_key)

        shared_secret_key = Diffie_Hellman.shared_key_calculation(receiver_public_key, secret_private_key,
                                                                  public_modulus)
        print("\nShared Secret Key: ", shared_secret_key)

        connected_socket.send("Sender Ready".encode())
        inform = connected_socket.recv(1024).decode()

        if inform != "Receiver Ready":
            print("Receiver not ready")
            return

        print("\nReceiver Ready")

        option, fileName, cipher_hex_text, original_length, length_encrypted \
            = sender_AES_operation(bit_length, shared_secret_key)

        opt_file = str(option) + "_" + fileName

        all_str = str(opt_file) + " " + str(original_length) + " " + str(length_encrypted) + " " + str(
            len(cipher_hex_text))
        connected_socket.send(all_str.encode())

        print("\nSending Cipher Text")
        connected_socket.send(cipher_hex_text.encode())
        print("Cipher Text Sent")

        connected_socket.close()
        print("\nConnection : ", address, "Closed\n")
        # break


server()
