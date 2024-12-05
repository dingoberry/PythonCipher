from sys import getdefaultencoding
from base64 import *
from common.cipher_base import CipherBase

BaseDict = {
    "16": (b16encode, b16decode),
    "32": (b32encode, b32hexdecode),
    "32h": (b32hexencode, b32hexdecode),
    "64": (b64encode, b64decode),
    "85": (b85encode, b85decode)
}

def execute(argv):
    c_base = CipherBase(argv, '64')
    
    base = c_base.retrieveAlgorithm(BaseDict, 'BASE')   
    base = base[0] if c_base.isEncrypt() else base[1]

    c_base.__dict__['output'] = c_base.calculateDuration(lambda: c_base.encodeText(base(c_base.useContent())))
    c_base.algorithm = f"base{c_base.algorithm}"

    print(c_base)
