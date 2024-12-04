import json
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from common.cipher_base import CipherBase

class SymCipher(CipherBase):
    def __init__(self, argv, algorithm=None) -> None:
        super().__init__(argv, algorithm)

        if self.algorithm in ('aes', 'des'):
            l = argv.get('-l')
            self.seed_length = 8 if self.algorithm == 'des' else 16 if l is None else int(int(l) / 8)
            self.mode = argv.get('-m', 'cbc')
    
    def getMode(self, es):
        mode = self.__dict__.get('mode')
        if mode == 'ecb':
            return es.MODE_ECB
        elif mode == 'ctr':
            return es.MODE_CTR
        elif mode == 'cfb':
            return es.MODE_CFB
        elif mode == 'ofb':
            return es.MODE_OFB
        else:
            return es.MODE_CBC 

def _enEs(sym_cipher, es):
    key = get_random_bytes(sym_cipher.seed_length)
    mode = sym_cipher.getMode(es)
    # noinspection PyTypeChecker
    cipher = es.new(key, mode)
    data = sym_cipher.useContent()
    ct_bytes = cipher.encrypt(pad(data, es.block_size) if mode in (es.MODE_CBC, es.MODE_ECB) else data)

    sym_cipher.__dict__['key'] = sym_cipher.encodeBase64(key)
    sym_cipher.__dict__['cipher_text'] = sym_cipher.encodeBase64(ct_bytes)

    if mode == es.MODE_CTR:
        sym_cipher.__dict__['nonce'] = sym_cipher.encodeBase64(cipher.nonce)
    elif mode != es.MODE_ECB:
        sym_cipher.__dict__['iv'] = sym_cipher.encodeBase64(cipher.iv)

    sym_cipher.__dict__['cipher_sum'] = sym_cipher.encodeBase85(str(sym_cipher))
    print(sym_cipher)

def _deEs(sym_cipher, es):
    data = None
    try:
        data = json.loads(sym_cipher.useContent())
    except json.JSONDecodeError as e:
        data = json.loads(sym_cipher.decodeBase85(sym_cipher.content))

    key = sym_cipher.decodeBase64(data['key'])
    ct = sym_cipher.decodeBase64(data['cipher_text'])

    mode = sym_cipher.getMode(es)
    nonce = None
    iv = None
    if mode == es.MODE_CTR:
        nonce = sym_cipher.decodeBase64(data['nonce'])
    elif mode != es.MODE_ECB:
        iv = sym_cipher.decodeBase64(data['iv'])

    # noinspection PyTypeChecker
    cipher = es.new(key, mode) \
        if mode == es.MODE_ECB else es.new(key, mode, nonce=nonce) \
        if mode == es.MODE_CTR else es.new(key, mode, iv)
    data = cipher.decrypt(ct)
    if mode in (es.MODE_CBC, es.MODE_ECB):
        data = unpad(data, es.block_size)
    sym_cipher.__dict__['output'] = data.decode(sym_cipher.encoding)
    print(sym_cipher)

def _enAes(sym_cipher):
   _enEs(sym_cipher, AES)

def _deAes(sym_cipher):
    _deEs(sym_cipher, AES)

def _enDes(sym_cipher):
    _enEs(sym_cipher, DES)

def _deDes(sym_cipher):
    _deEs(sym_cipher, DES)


CipherDict = {
    "aes": (_enAes, _deAes),
    "des": (_enDes, _deDes)
}

def execute(argv):
    s_base = SymCipher(argv)
    cipher = s_base.retrieveAlgorithm(CipherDict, "symmetric algorithm")

    if s_base.isEncrypt():
        cipher[0](s_base)
    else:
        cipher[1](s_base)
