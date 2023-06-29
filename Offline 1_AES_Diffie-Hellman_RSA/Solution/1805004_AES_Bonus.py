Utils = __import__('1805004_Utils')
Independent_AES = __import__('1805004_AES')


def independent_AES_Bonus():
    key = "BUET CSE18 Batch"

    bit_length = int(input("Enter the bit length: "))
    if bit_length != 128 and bit_length != 192 and bit_length != 256:
        print("Invalid bit length")
        return

    option = int(input("\nEnter 0 for text file, Enter 1 for any file (pdf or image or others): "))
    fileName = input("\nEnter file path: ")
    filePath = "server/" + fileName

    if option > 1:
        print("Invalid input")
        return

    if option == 0:
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

    print("Plain Text:")
    print("In ASCII: ", plainText)
    print("In Hex: ", Utils.BitVector(textstring=plainText).get_bitvector_in_hex())

    print("\nKey:")
    print("In ASCII: ", key)
    print("In Hex: ", Utils.BitVector(textstring=key).get_bitvector_in_hex())

    cipher_hex_text, cipher_ascii_text, length_encrypted, key_schedule_time, encryption_time = \
        Independent_AES.AES_Encryption(bit_length, key, plainText)

    decipher_hex_text, decipher_ascii_text, decryption_time = Independent_AES.AES_Decryption(bit_length, key,
                                                                                             cipher_hex_text,
                                                                                             length_encrypted,
                                                                                             original_length)

    filePath = "client/"

    if option == 0:
        # Write text to text file
        filePath += "decrypted.txt"
        fb = open(filePath, "w")
        fb.write(decipher_ascii_text)
        fb.close()

    else:
        # Write image/pdf or any other file
        ext = fileName.split('.')[1]
        newPath = filePath + "decrypted." + ext
        file_img = open(newPath, 'wb')
        file_img.write(eval(decipher_ascii_text))
        file_img.close()

    print("\nCipher Text:")
    print("In Hex: ", cipher_hex_text)
    print("In ASCII: ", cipher_ascii_text)

    print("\nDecipher Text:")
    print("In Hex: ", decipher_hex_text)
    print("In ASCII: ", decipher_ascii_text)

    print("\nExecution time details:")
    print("Key Scheduling: ", key_schedule_time, " seconds")
    print("Encryption Time: ", encryption_time, " seconds")
    print("Decryption Time: ", decryption_time, " seconds")


independent_AES_Bonus()
