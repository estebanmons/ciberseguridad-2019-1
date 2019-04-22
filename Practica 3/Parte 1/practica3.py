#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 16 09:01:23 2019

@author: juanestebanmonsalve
"""

from hashlib import md5
from base64 import b64encode
from Crypto.Cipher import AES

def msg_and_key():
    msg = input("Texto Vigenère: ").upper()
    key = input("Key AES 128: ").upper()
    
    return msg, key


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

def findKeyLen(cipherText,maxKeyLen):
    auxKeyLen = 1
    while(auxKeyLen<=maxKeyLen):
        i = 0
        count = 0
        while(i<len(cipherText) - auxKeyLen):
            if(cipherText[i] == cipherText[i + auxKeyLen]):
                count = count + 1
            i = i + 1
        print("Para clave de longitud %d hay %d coincidencias"%(auxKeyLen,count))
        auxKeyLen = auxKeyLen + 1

def main():
    print("Ingrese parametros de entrada")
    message, key = msg_and_key()
    print("")
    print('texto cifrado en AES 128 ECB: ', AESCipher(key).encrypt(message),'\n')
    print("Texto en Vigenère ",message,'\n')
    findKeyLen(message,16)
    
if __name__ == "__main__":
    main()


