from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES

def msg_and_key():
    msg = input("Mensaje: ").upper()
    key = input("Llave: ").upper()
    key_map = ""

    j=0
    for i in range(len(msg)):
        if ord(msg[i]) == 32:
            key_map += " "
        else:
            if j < len(key):
                key_map += key[j]
                j += 1
            else:
                j = 0
                key_map += key[j]
                j += 1
    return msg, key_map,key


def create_vigenere_table():
    table = []
    for i in range(26):
        table.append([])

    for row in range(26):
        for column in range(26):
            if (row + 65) + column > 90:
                table[row].append(chr((row+65) + column - 26))
            else:
                table[row].append(chr((row+65)+column))
    return table


def cipher_encryption(message, mapped_key):
    table = create_vigenere_table()
    
    encrypted_text = ""
    for i in range(len(message)):
        if message[i] == chr(32):
            encrypted_text += " "
        else:
            row = ord(message[i])-65
            column = ord(mapped_key[i]) - 65
            encrypted_text += table[row][column]

    print("Texto cifrado en Vigenère: {}\n".format(encrypted_text))
    return encrypted_text


def itr_count(mapped_key, message):
    counter = 0
    result = ""

    for i in range(26):
        if mapped_key + i > 90:
            result += chr(mapped_key+(i-26))
        else:
            result += chr(mapped_key+i)
    for i in range(len(result)):
        if result[i] == chr(message):
            break
        else:
            counter += 1

    return counter


def cipher_decryption(message, mapped_key):
    table = create_vigenere_table()
    decrypted_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            decrypted_text += " "
        else:
            decrypted_text += chr(65 + itr_count(ord(mapped_key[i]), ord(message[i])))

    print("Texto descifrado de Vigenère: {}\n".format(decrypted_text))

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return unpad(cipher.decrypt(enc)).decode('utf8')

def main():
    print("Ingrese texto para analizar")
    message, mapped_key, key = msg_and_key()
    text =  cipher_encryption(message, mapped_key)
    keyAes = msg = input("KeyAes: ").upper()
    print('texto cifrado en AES 128 ECB: ', AESCipher(keyAes).encrypt(text))
    cipher_decryption(text, mapped_key)
    evelyn = AESCipher(key).encrypt(text)
    print('Texto decifrado en AES 128 ECB: ', AESCipher(keyAes).decrypt(evelyn))
    
if __name__ == "__main__":
    main()