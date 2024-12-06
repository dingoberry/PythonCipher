import json

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS, PKCS1_v1_5 as PKCS1_v1_5_SIG

from common.cipher_base import CipherBase


class Asymmetric(CipherBase):
    def __init__(self, argv):
        super().__init__(argv)
        if self.algorithm == "rsa":
            if self.isEncrypt():
                l = argv.get('-l')
                self.gen_len = int(l) if l in ('1024', '2048', '3072') else 2048 if l is None else 0
                if self.gen_len == 0:
                    raise Exception("Please choose a valid length: 1024, 2048, or 3072!")
            self.mode = argv.get('-m', "oaep")
            sign = argv.get('-s')
            if sign is not None:
                self.sign = sign
            signature = argv.get('-sm')
            if signature is not None:
                self.signature = signature
            pwd = argv.get('-pwd')
            if pwd is not None:
                self.pwd = pwd

    def getRsaMode(self):
        if self.mode == "oaep":
            return PKCS1_OAEP.new
        elif self.mode == "v1.5":
            return PKCS1_v1_5.new
        else:
            raise Exception("Please choose a valid mode: oaep or v1.5!")


def _enRsa(asym_cipher):
    key = RSA.generate(asym_cipher.gen_len)

    pwd = asym_cipher.__dict__.get('pwd')
    private_key = asym_cipher.encodeText(key.export_key(passphrase=pwd))
    public_key = RSA.import_key(asym_cipher.encodeText(key.publickey().export_key()))

    mode = asym_cipher.getRsaMode()
    cipher_rsa = mode(public_key)
    cipher_text = asym_cipher.calculateDuration(lambda: cipher_rsa.encrypt(asym_cipher.useContent())) 

    if asym_cipher.__dict__.get('sign') is not None:
        signature = asym_cipher.__dict__.get('signature')
        sig = {'1.5' : PKCS1_v1_5_SIG, 'pss' : PKCS1_PSS}.get(signature) if signature is not None else PKCS1_PSS
        if sig is None:
            raise Exception("Please set a valid signature mode!")
        asym_cipher.__dict__['sign_text'] = asym_cipher.encodeBase64(
            sig.new(RSA.import_key(private_key, passphrase=pwd)).sign(SHA256.new(asym_cipher.sign.encode(asym_cipher.encoding))))

    if pwd is not None:
        asym_cipher.__dict__['password'] = pwd
    asym_cipher.__dict__['gen_len'] = asym_cipher.gen_len
    asym_cipher.__dict__['cipher_text'] = asym_cipher.encodeBase64(cipher_text)
    asym_cipher.__dict__['cipher_min_len'] = len(cipher_text)
    asym_cipher.__dict__['private_key'] = asym_cipher.encodeText(private_key)
    asym_cipher.__dict__['cipher_sum'] = asym_cipher.encodeBase85(str(asym_cipher))

    print(asym_cipher)

def _deRsa(asym_cipher):
    data : any
    try:
        data = json.loads(asym_cipher.useContent())
    except json.JSONDecodeError:
        data = json.loads(asym_cipher.decodeBase85(asym_cipher.content))

    ciphertext = asym_cipher.decodeBase64(data['cipher_text'])
    private_key = RSA.import_key(data['private_key'], passphrase=data.get('password'))

    mode = asym_cipher.getRsaMode()
    cipher_rsa = mode(private_key)
    data = asym_cipher.calculateDuration(lambda: cipher_rsa.decrypt(ciphertext) if mode == PKCS1_OAEP.new else cipher_rsa.decrypt(ciphertext, None))

    asym_cipher.__dict__['cipher_min_len'] = private_key.size_in_bytes()
    asym_cipher.__dict__['output'] = asym_cipher.encodeText(data)
    print(asym_cipher)

CipherDict = {
    "rsa": (_enRsa, _deRsa),
}

# noinspection DuplicatedCode
def execute(argv):
    a_base = Asymmetric(argv)
    cipher = a_base.retrieveAlgorithm(CipherDict, "asymmetric algorithm")
    
    if a_base.isEncrypt():
        cipher[0](a_base)
    else:
        cipher[1](a_base)