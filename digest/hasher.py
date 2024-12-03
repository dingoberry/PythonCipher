from sys import argv, getdefaultencoding
from hashlib import *
 
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

def execute():
    argv_length = len(argv)
    if argv_length < 5 or argv[3] != '-h':
        raise Exception("Please give a hash algorithm!")
    
    al = argv[4]
    digest = HashDict.get(al)
    if digest is None:
        raise Exception("No hash algorithm definition!")
    else:
        info = None
        el = None
        encoding = getdefaultencoding()
        if argv_length > 6:
            for index in range(5, argv_length, 2):
                if argv[index] == '-e':
                    encoding = argv[index + 1]
                elif argv[index] == '-l':
                    el = int(argv[index + 1])
                elif index == argv_length - 1:
                    info = argv[index]
            
        elif argv_length == 6:
            info = argv[5]

        if info is None:
            raise Exception("No message definition!")
       
        _hex = None
        _bytes = None
        digest_exc = digest(info.encode(encoding))
        if digest == shake_128 or digest == shake_256:
            if el is None:
                raise Exception("Shake algorithm require a length!")
            else:
                # noinspection PyArgumentList
                _hex = digest_exc.hexdigest(el)
                # noinspection PyArgumentList
                _bytes = digest_exc.digest(el)
        else:
            _hex = digest_exc.hexdigest()
            _bytes = digest_exc.digest()
      
        print(f"""
Raw: {info}
Hash: {al}
Bytes: {_bytes}
Hex: {_hex}
Length: {len(_hex)}""")