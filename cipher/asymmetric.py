import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from common.cipher_base import CipherBase
import json

def _enRsa(asym_cipher):
    key = RSA.generate(2048)

    private_key = key.export_key().decode(asym_cipher.encoding)
    public_key  = RSA.import_key(key.publickey().export_key().decode(asym_cipher.encoding))
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(asym_cipher.useContent())
 
    asym_cipher.__dict__['session_key_len'] = len(enc_session_key)
    asym_cipher.__dict__['session_key'] = asym_cipher.encodeBase64(enc_session_key)
    asym_cipher.__dict__['nonce'] = asym_cipher.encodeBase64(cipher_aes.nonce)
    asym_cipher.__dict__['tag'] = asym_cipher.encodeBase64(tag)
    asym_cipher.__dict__['cipher_text'] = asym_cipher.encodeBase64(ciphertext)
    asym_cipher.__dict__['private_key'] = private_key
    asym_cipher.__dict__['cipher_sum'] = asym_cipher.encodeBase85(str(asym_cipher))

    print(asym_cipher)

def _deRsa(asym_cipher):
    data = None
    try:
        data = json.loads(asym_cipher.useContent())
    except json.JSONDecodeError as e:
        data = json.loads(asym_cipher.decodeBase85(asym_cipher.content))

    enc_session_key = asym_cipher.decodeBase64(data['session_key'])
    nonce = asym_cipher.decodeBase64(data['nonce'])
    tag = asym_cipher.decodeBase64(data['tag'])
    ciphertext = asym_cipher.decodeBase64(data['cipher_text'])
    private_key = RSA.import_key(data['private_key'])     

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    asym_cipher.__dict__['session_key_len'] = private_key.size_in_bytes()
    asym_cipher.__dict__['output'] = asym_cipher.encodeText(lambda: data)
    print(asym_cipher)

CipherDict = {
    "rsa": (_enRsa, _deRsa),
}

# noinspection DuplicatedCode
def execute(argv):
    a_base = CipherBase(argv)
    cipher = a_base.retrieveAlgorithm(CipherDict, "asymmetric algorithm")
    
    if a_base.isEncrypt():
        cipher[0](a_base)
    else:
        cipher[1](a_base)