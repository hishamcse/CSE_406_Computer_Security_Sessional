import time

Utils = __import__('1805004_Utils')


def Hex_equivalent(str):
    return [c.encode().hex() for c in str]


def adjust_key(str, allowedLen):
    keyLen = allowedLen // 8
    str = str[:keyLen]
    str = str.ljust(keyLen, '0')
    return Hex_equivalent(str)


def adjust_plainText(str, allowedLen):
    str = add_padding(Hex_equivalent(str), allowedLen // 8)
    return str


def adjust_decipherText(str, allowedLen, original_length):
    str = remove_padding(str, allowedLen // 8, original_length)
    return str


def print_2D_arr(arr):
    print([[arr[i][j].get_bitvector_in_hex() for j in range(len(arr[i]))] for i in range(4)])


def print_3D_arr(arr):
    print([[[arr[i][j][k].get_bitvector_in_hex() for k in range(len(arr[i][j]))] for j in range(len(arr[i]))] for i in
           range(len(arr))])


def add_padding(text, block_size):
    padding_length = (block_size - (len(text) % block_size)) % block_size
    text += ['00' for _ in range(padding_length)]
    return text


def remove_padding(padded_text, block_size, original_length):
    padding_length = (block_size - (original_length % block_size)) % block_size
    return padded_text[:len(padded_text) - 2 * padding_length]


def arr_1D_to_2D_col_major(arr):
    return [[Utils.BitVector(hexstring=arr[i]) for i in range(r, len(arr), 4)] for r in range(4)]


def arr_2D_to_1D_col_major(arr):
    return [arr[j][i] for i in range(len(arr[0])) for j in range(len(arr))]  # col major


def circular_left_shift(arr, shift):
    return arr[shift:] + arr[:shift]


def circular_right_shift(arr, shift):
    return arr[-shift:] + arr[:-shift]


def rot_sub_g(col, rcon):
    col = circular_left_shift(col, 1)
    for i in range(4):
        col[i] = Utils.BitVector(intVal=Utils.Sbox[col[i].intValue()], size=8)
    col[0] ^= rcon
    return col


def key_schedule(key, allowedLen):
    keys_per_round = []
    round0Key = arr_1D_to_2D_col_major(key)
    keys_per_round.append(round0Key)

    index = [i for i in range(3) if Utils.Round_Keys[i][0] == allowedLen]
    total_rounds = Utils.Round_Keys[index[0]][1] + 1

    rcon = Utils.BitVector(hexstring="01")
    total_column = allowedLen // 32

    for r in range(1, total_rounds):
        word3 = [keys_per_round[r - 1][i][total_column - 1] for i in range(4)]
        g_word3 = rot_sub_g(word3, rcon)

        curWord = g_word3
        key_row_major = []
        for i in range(total_column):
            word = [keys_per_round[r - 1][j][i] for j in range(4)]
            xor_word = [word[j] ^ curWord[j] for j in range(4)]
            key_row_major += [xor_word[j] for j in range(4)]
            curWord = xor_word

        key_col_major = [[key_row_major[i] for i in range(k, len(key_row_major), 4)] for k in range(4)]
        keys_per_round.append(key_col_major)

        rcon = rcon.gf_multiply_modular(Utils.BitVector(hexstring="02"), Utils.AES_modulus, 8)

    # print_3D_arr(keys_per_round)

    return keys_per_round


def add_round_key(state_matrix, key_matrix):
    state_matrix = [[state_matrix[i][j] ^ key_matrix[i][j] for j in range(len(state_matrix[i]))] for i in
                    range(len(state_matrix))]
    return state_matrix


def substitute_bytes(state_matrix):
    state_matrix = [
        [Utils.BitVector(intVal=Utils.Sbox[state_matrix[i][j].intValue()], size=8) for j in range(len(state_matrix[i]))]
        for i in range(len(state_matrix))]
    return state_matrix


def inv_substitute_bytes(state_matrix):
    state_matrix = [
        [Utils.BitVector(intVal=Utils.InvSbox[state_matrix[i][j].intValue()], size=8) for j in
         range(len(state_matrix[i]))]
        for i in range(len(state_matrix))]
    return state_matrix


def shift_rows(state_matrix):
    state_matrix = [circular_left_shift(state_matrix[i], i) if i > 0 else state_matrix[i] for i in
                    range(len(state_matrix))]
    return state_matrix


def inv_shift_rows(state_matrix):
    state_matrix = [circular_right_shift(state_matrix[i], i) if i > 0 else state_matrix[i] for i in
                    range(len(state_matrix))]
    return state_matrix


def mix_columns(state_matrix, total_column):
    new_state_matrix = [[Utils.BitVector(intVal=0, size=8) for _ in range(len(state_matrix[i]))] for i in
                        range(len(state_matrix))]

    for i in range(len(state_matrix)):
        for j in range(total_column):
            for k in range(len(state_matrix)):
                new_state_matrix[i][j] ^= Utils.Mixer[i][k].gf_multiply_modular(state_matrix[k][j], Utils.AES_modulus,
                                                                                8)

    return new_state_matrix


def inv_mix_columns(state_matrix, total_column):
    new_state_matrix = [[Utils.BitVector(intVal=0, size=8) for _ in range(len(state_matrix[i]))] for i in
                        range(len(state_matrix))]

    for i in range(len(state_matrix)):
        for j in range(total_column):
            for k in range(len(state_matrix)):
                new_state_matrix[i][j] ^= Utils.InvMixer[i][k].gf_multiply_modular(state_matrix[k][j],
                                                                                   Utils.AES_modulus, 8)

    return new_state_matrix


def encryption(adjusted_text, keys_per_round, allowedLen):
    round0_state_matrix = arr_1D_to_2D_col_major(adjusted_text)

    total_column = allowedLen // 32
    cur_state_matrix = add_round_key(round0_state_matrix, keys_per_round[0])
    # print_2D_arr(cur_state_matrix)

    index = [i for i in range(3) if Utils.Round_Keys[i][0] == allowedLen]
    total_rounds = Utils.Round_Keys[index[0]][1] + 1

    for r in range(1, total_rounds):
        cur_state_matrix = substitute_bytes(cur_state_matrix)

        cur_state_matrix = shift_rows(cur_state_matrix)

        if r != total_rounds - 1:
            cur_state_matrix = mix_columns(cur_state_matrix, total_column)

        cur_state_matrix = add_round_key(cur_state_matrix, keys_per_round[r])
        # print_2D_arr(cur_state_matrix)

    return cur_state_matrix


def padded_encryption(adjusted_text, keys_per_round, allowedLen):
    block_size = allowedLen // 8
    result = []
    for i in range(0, len(adjusted_text), block_size):
        result.append(encryption(adjusted_text[i:i + block_size], keys_per_round, allowedLen))
    return result


def decryption(decrypted_2D_arr, keys_per_round, allowedLen):
    keys_per_round_decrypt = keys_per_round[::-1]  # reverse the keys_per_round
    round0_state_matrix = decrypted_2D_arr
    # print_2D_arr(round0_state_matrix)

    total_column = allowedLen // 32
    cur_state_matrix = add_round_key(round0_state_matrix, keys_per_round_decrypt[0])

    index = [i for i in range(3) if Utils.Round_Keys[i][0] == allowedLen]
    total_rounds = Utils.Round_Keys[index[0]][1] + 1

    for r in range(1, total_rounds):
        cur_state_matrix = inv_shift_rows(cur_state_matrix)

        cur_state_matrix = inv_substitute_bytes(cur_state_matrix)
        # print_2D_arr(cur_state_matrix)

        cur_state_matrix = add_round_key(cur_state_matrix, keys_per_round_decrypt[r])

        if r != total_rounds - 1:
            cur_state_matrix = inv_mix_columns(cur_state_matrix, total_column)

    # print_2D_arr(cur_state_matrix)

    return cur_state_matrix


def padded_decryption(decrypted_3D_arr, keys_per_round, allowedLen):
    result = []
    for i in range(len(decrypted_3D_arr)):
        result.append(decryption(decrypted_3D_arr[i], keys_per_round, allowedLen))
    return result


def final_hex_text(arr):
    return [''.join(
        [arr_2D_to_1D_col_major(arr[i])[j].get_bitvector_in_hex() for j in range(len(arr_2D_to_1D_col_major(arr[i])))])
        for i in range(len(arr))]


def final_ascii_text(hex_text):
    return Utils.BitVector(hexstring=hex_text).get_bitvector_in_ascii()


def cipher_text_to_2D_arr(cipher_text, length):
    result = []
    counter = len(cipher_text) // length
    for j in range(length):
        result.append(arr_1D_to_2D_col_major([cipher_text[i:i + 2] for i in range(j * counter, (j + 1) * counter, 2)]))
    return result


def AES_Encryption(allowedLen, key, plainText):
    start = time.time()
    adjusted_key = adjust_key(key, allowedLen)
    keys_per_round = key_schedule(adjusted_key, allowedLen)
    end = time.time()

    key_schedule_time = end - start

    start = time.time()
    adjusted_text = adjust_plainText(plainText, allowedLen)
    # print(adjusted_text)

    encrypted_text = padded_encryption(adjusted_text, keys_per_round, allowedLen)
    # print("Encrypted Text: ")
    # print_3D_arr(encrypted_text)
    end = time.time()

    encryption_time = end - start

    cipher_text = ''.join(final_hex_text(encrypted_text))
    # print("Cipher Text: ", cipher_text)

    ascii_cipher_text = final_ascii_text(cipher_text)
    # print("ASCII Cipher Text: ", ascii_cipher_text)

    return cipher_text, ascii_cipher_text, len(encrypted_text), key_schedule_time, encryption_time


def AES_Decryption(allowedLen, key, cipherText, length_encrypted, original_length):
    adjusted_key = adjust_key(key, allowedLen)
    keys_per_round = key_schedule(adjusted_key, allowedLen)

    start = time.time()
    decrypted_3D_arr = cipher_text_to_2D_arr(cipherText, length_encrypted)
    # print("Encrypted Text while deciphering: ")
    # print_3D_arr(decrypted_3D_arr)

    decrypted_text = padded_decryption(decrypted_3D_arr, keys_per_round, allowedLen)
    # print("Decrypted Text: ")
    # print_3D_arr(decrypted_text)
    end = time.time()

    decryption_time = end - start

    decipher_hex_text = ''.join(final_hex_text(decrypted_text))
    # print("decipher_hex_text: ", decipher_hex_text)

    adjusted_decipher_hex_text = adjust_decipherText(decipher_hex_text, allowedLen, original_length)

    decipher_ascii_text = final_ascii_text(adjusted_decipher_hex_text)
    # print("ASCII Cipher Text: ", decipher_ascii_text)

    return adjusted_decipher_hex_text, decipher_ascii_text, decryption_time


def independent_AES():
    key = "BUET CSE18 Batch"
    plainText = "Can They Do This"

    bit_length = int(input("Enter the bit length: "))
    if bit_length != 128 and bit_length != 192 and bit_length != 256:
        print("Invalid bit length")
        return

    original_length = len(plainText)

    print("Plain Text:")
    print("In ASCII: ", plainText)
    print("In Hex: ", Utils.BitVector(textstring=plainText).get_bitvector_in_hex())

    print("\nKey:")
    print("In ASCII: ", key)
    print("In Hex: ", Utils.BitVector(textstring=key).get_bitvector_in_hex())

    cipher_hex_text, cipher_ascii_text, length_encrypted, key_schedule_time, encryption_time = AES_Encryption(
        bit_length, key, plainText)
    decipher_hex_text, decipher_ascii_text, decryption_time = AES_Decryption(bit_length, key, cipher_hex_text,
                                                                             length_encrypted,
                                                                             original_length)

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


# independent_AES()
