import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from common.cipher_base import CipherBase
import json

def _enRsa(asynCipher):
    key = RSA.generate(2048)

    private_key = key.export_key().decode(asynCipher.encoding)
    public_key  = RSA.import_key(key.publickey().export_key().decode(asynCipher.encoding))
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(asynCipher.useContent())
 
    asynCipher.__dict__['session_key_len'] = len(enc_session_key)
    asynCipher.__dict__['session_key'] = asynCipher.encodeBase64(enc_session_key)
    asynCipher.__dict__['nonce'] = asynCipher.encodeBase64(cipher_aes.nonce)
    asynCipher.__dict__['tag'] = asynCipher.encodeBase64(tag)
    asynCipher.__dict__['cipher_text'] = asynCipher.encodeBase64(ciphertext)
    asynCipher.__dict__['private_key'] = private_key
    asynCipher.__dict__['cipher_sum'] = asynCipher.encodeBase85(str(asynCipher))

    print(asynCipher)

def _deRsa(asynCipher):
    data = None
    try:
        data = json.loads(asynCipher.useContent())
    except json.JSONDecodeError as e:
        data = json.loads(asynCipher.decodeBase85(asynCipher.content))

    enc_session_key = asynCipher.decodeBase64(data['session_key'])
    nonce = asynCipher.decodeBase64(data['nonce'])
    tag = asynCipher.decodeBase64(data['tag'])
    ciphertext = asynCipher.decodeBase64(data['cipher_text'])
    private_key = RSA.import_key(data['private_key'])     

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    asynCipher.__dict__['session_key_len'] = private_key.size_in_bytes()
    asynCipher.__dict__['output'] = asynCipher.encodeText(lambda: data)
    print(asynCipher)

CipherDict = {
    "rsa": (_enRsa, _deRsa),
}

# noinspection DuplicatedCode
def execute(argv):
    a_base = CipherBase(argv)
    cipher = a_base.retrieveAlgorithm(CipherDict, "asyn-algorithm")
    
    if a_base.isEncrypt():
        cipher[0](a_base)
    else:
        cipher[1](a_base)