import json
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from common.cipher_base import CipherBase

class SynCipher(CipherBase):
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

def _enEs(synCipher, es):
    key = get_random_bytes(synCipher.seed_length)
    mode = synCipher.getMode(es)
    # noinspection PyTypeChecker
    cipher = es.new(key, mode)
    data = synCipher.useContent()
    ct_bytes = cipher.encrypt(pad(data, es.block_size) if mode in (es.MODE_CBC, es.MODE_ECB) else data)

    synCipher.__dict__['key'] = synCipher.encodeBase64(key)
    synCipher.__dict__['cipher_text'] = synCipher.encodeBase64(ct_bytes)

    if mode == es.MODE_CTR:
        synCipher.__dict__['nonce'] = synCipher.encodeBase64(cipher.nonce)
    elif mode != es.MODE_ECB:
        synCipher.__dict__['iv'] = synCipher.encodeBase64(cipher.iv)

    synCipher.__dict__['cipher_sum'] = synCipher.encodeBase85(str(synCipher))
    print(synCipher)

def _deEs(synCipher, es):
    data = None
    try:
        data = json.loads(synCipher.useContent())
    except json.JSONDecodeError as e:
        data = json.loads(synCipher.decodeBase85(synCipher.content))

    key = synCipher.decodeBase64(data['key'])
    ct = synCipher.decodeBase64(data['cipher_text'])

    mode = synCipher.getMode(es)
    nonce = None
    iv = None
    if mode == es.MODE_CTR:
        nonce = synCipher.decodeBase64(data['nonce'])
    elif mode != es.MODE_ECB:
        iv = synCipher.decodeBase64(data['iv'])

    # noinspection PyTypeChecker
    cipher = es.new(key, mode) \
        if mode == es.MODE_ECB else es.new(key, mode, nonce=nonce) \
        if mode == es.MODE_CTR else es.new(key, mode, iv)
    data = cipher.decrypt(ct)
    if mode in (es.MODE_CBC, es.MODE_ECB):
        data = unpad(data, es.block_size)
    synCipher.__dict__['output'] = data.decode(synCipher.encoding)
    print(synCipher)

def _enAes(synCipher):
   _enEs(synCipher, AES)

def _deAes(synCipher):
    _deEs(synCipher, AES)

def _enDes(synCipher):
    _enEs(synCipher, DES)

def _deDes(synCipher):
    _deEs(synCipher, DES)


CipherDict = {
    "aes": (_enAes, _deAes),
    "des": (_enDes, _deDes)
}

def execute(argv):
    s_base = SynCipher(argv)
    cipher = s_base.retrieveAlgorithm(CipherDict, "syn-algorithm") 

    if s_base.isEncrypt():
        cipher[0](s_base)
    else:
        cipher[1](s_base)
