import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from sys import argv, getdefaultencoding
import json

def _enRsa(data, encoding):
    key = RSA.generate(2048)

    private_key = key.export_key().decode(encoding)

    recipient_key = RSA.import_key(key.publickey().export_key().decode(encoding))
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode(encoding))

    print(json.dumps({
        "algorithm": "rsa",
        "session_key": enc_session_key.hex(),
        "nonce": cipher_aes.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "private_key": private_key
    }).replace("\"", "\\\""))

def _deRsa(data, encoding):
    data = json.loads(data)

    enc_session_key = data['session_key']
    nonce = data['nonce']
    tag = data['tag']
    ciphertext = data['ciphertext']
    private_key = data['private_key']

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(private_key.size_in_bytes())

    # Decrypt the data with the AES session key
    # cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    # data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    # print(f"Decrypted cipherText: {data.decode(encoding)}")

CipherDict = {
    "rsa": (_enRsa, _deRsa),
}

# noinspection DuplicatedCode
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
        raise Exception("No asyn-algorithm definition!")
    elif is_encoding:
        cipher[0](info, encoding)
    else:
        cipher[1](info, encoding)