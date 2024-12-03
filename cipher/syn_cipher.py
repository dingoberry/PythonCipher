from sys import argv, getdefaultencoding
from Crypto.Cipher import AES
from Crypto.Random import HMAC, SHA256
from Crypto.Hash import get_random_bytes

def _enAes():
    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt("123")

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()

    print('''

''')

def _deAes():
    pass

def _enDes():
    pass

def _deDes():
    pass

CipherDict = {
    "aes": (_enAes, _deAes),
    "des": (_enAes, _deAes)
}

def execute():
    argvLength = len(argv)

    isEncoding : None
    algorithm : None
    if argvLength >= 7:
         for index in range(3, argvLength, 2):
             if argv[index] == '-t':
                 realEncoding = argv[index + 1]
                 isEncoding = True if realEncoding == 'e' else (False if realEncoding == 'd' else None)
             elif argv[index] == '-a':
                 algorithm = argv[index + 1]
             elif argv[index] == '-e':
                 encoding = argv[index + 1]
             elif index == argvLength - 1:
                 info = argv[index]

    if isEncoding == None:
        raise Exception("Please give a target action!")
    if algorithm == None:
        raise Exception("Please give a algorithm!")