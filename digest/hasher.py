from sys import getdefaultencoding
from hashlib import *
from common.cipher_base import AlgorithmBase
 
HashDict = {
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "sha224": sha224,
    "sha384": sha384,
    "sha3384": sha3_384,
    "sha3224": sha3_224,
    "sha3256": sha3_256,
    "sha3512": sha3_512,
    "sha512": sha512,
    "shake128": shake_128,
    "shake256": shake_256,
    "blake2b": blake2b,
    "blake2s": blake2s,
}

class Hasher(AlgorithmBase):
    def __init__(self, argv, algorithm=None) -> None:
        super().__init__(argv, algorithm)
        length = argv.get('-l')
        if length is not None:
            self.var_len = length

    def getVarLen(self):
        if self.__dict__.get('var_len') is None:
            raise Exception("Shake algorithm require a length!")
        else:
            return int(self.var_len)

def execute(argv):
    h_base = Hasher(argv)
 
    digest = h_base.retrieveAlgorithm(HashDict, "hash")
     
   
    digest_exc = digest(h_base.useContent())
      # noinspection PyArgumentList
    _bytes = h_base.calculateDuration(lambda: digest_exc.digest(h_base.getVarLen()) if digest == shake_128 or digest == shake_256 else digest_exc.digest())

    _hex = _bytes.hex()
    h_base.__dict__['bytes'] = str(_bytes)
    h_base.__dict__['hex'] = _hex
    h_base.__dict__['length'] = len(_hex)

    print(h_base)