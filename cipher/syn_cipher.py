import json
from base64 import b64encode, b64decode
from sys import argv, getdefaultencoding

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def _enEs(name, data, encoding, es, el = 16):
    argv_length = len(argv)
    mode = es.MODE_CBC
    mode_str = 'cbc'
    if argv_length > 7:
        for index in range(7, argv_length, 2):
            if argv[index] == '-l' and es == AES:
                el = int(int(argv[index + 1]) / 8)
            if argv[index] == '-m':
                mode_str = argv[index + 1]
                if mode_str == 'ecb':
                    mode = es.MODE_ECB
                elif mode_str == 'ctr':
                    mode = es.MODE_CTR
                elif mode_str == 'cfb':
                    mode = es.MODE_CFB
                elif mode_str == 'ofb':
                    mode = es.MODE_OFB

    key = get_random_bytes(el)
    # noinspection PyTypeChecker
    cipher = es.new(key, mode)
    data = data.encode(encoding)
    ct_bytes = cipher.encrypt(pad(data, es.block_size) if mode in (es.MODE_CBC, es.MODE_ECB) else data)

    body = {
        "algorithm": name,
        "mode": mode_str,
        "key": b64encode(key).decode(encoding),
        "cipherText": b64encode(ct_bytes).decode(encoding)
    }

    if mode == es.MODE_CTR:
        body['nonce'] = b64encode(cipher.nonce).decode(encoding)
    elif mode != es.MODE_ECB:
        body['iv'] = b64encode(cipher.iv).decode(encoding)

    print(json.dumps(body).replace("\"", "\\\""))

def _deEs(data, encoding, es):
    b64 = json.loads(data)
    key = b64decode(b64['key'].encode(encoding))
    ct = b64decode(b64['cipherText'].encode(encoding))

    mode = es.MODE_CBC
    mode_str = b64['mode']
    if mode_str == 'ecb':
        mode = es.MODE_ECB
    elif mode_str == 'ctr':
        mode = es.MODE_CTR
    elif mode_str == 'cfb':
        mode = es.MODE_CFB
    elif mode_str == 'ofb':
        mode = es.MODE_OFB

    nonce = None
    iv = None
    if mode == es.MODE_CTR:
        nonce = b64decode(b64['nonce'].encode(encoding))
    elif mode != es.MODE_ECB:
        iv = b64decode(b64['iv'].encode(encoding))

    # noinspection PyTypeChecker
    cipher = es.new(key, mode) \
        if mode == es.MODE_ECB else es.new(key, mode, nonce=nonce) \
        if mode == es.MODE_CTR else es.new(key, mode, iv)
    data = cipher.decrypt(ct)
    if mode in (es.MODE_CBC, es.MODE_ECB):
        data = unpad(data, es.block_size)
    print(f"Decrypted cipherText: {data.decode(encoding)}")

def _enAes(data, encoding):
   _enEs('AES', data, encoding, AES)

def _deAes(data, encoding):
    _deEs(data, encoding, AES)

def _enDes(data, encoding):
    _enEs('DES', data, encoding, DES, 8)


def _deDes(data, encoding):
    _deEs(data, encoding, DES)


CipherDict = {
    "aes": (_enAes, _deAes),
    "des": (_enDes, _deDes)
}

def execute():
    argv_length = len(argv)

    is_encoding = None
    algorithm = None
    encoding = getdefaultencoding()
    info = None
    if argv_length >= 5:
        for index in range(3, argv_length, 2):
            if argv[index] == '-t':
                real_encoding = argv[index + 1]
                is_encoding = True if real_encoding == 'e' else (False if real_encoding == 'd' else None)
            elif argv[index] == '-a':
                algorithm = argv[index + 1]
            elif argv[index] == '-e':
                encoding = argv[index + 1]
            elif index == argv_length - 1:
                info = argv[index]

    if is_encoding is None:
        raise Exception("Please give a target action!")
    if algorithm is None:
        raise Exception("Please give a algorithm!")

    cipher = CipherDict.get(algorithm)
    if cipher is None:
        raise Exception("No syn-algorithm definition!")
    elif is_encoding:
        cipher[0](info, encoding)
    else:
        cipher[1](info, encoding)
