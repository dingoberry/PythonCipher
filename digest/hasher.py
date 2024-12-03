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
    argvLength = len(argv)
    if argvLength < 5 or argv[3] != '-h':
        raise Exception("Please give a hash algorithm!")
    
    al = argv[4]
    digest = HashDict.get(al)
    if digest == None:
        raise Exception("No hash algorithm definition!")
    else:
        info = None
        el = None
        encoding = getdefaultencoding()
        if argvLength > 6:
            for index in range(5, argvLength, 2):
                if argv[index] == '-e':
                    encoding = argv[index + 1]
                elif argv[index] == '-l':
                    el = int(argv[index + 1])
                elif index == argvLength - 1:
                    info = argv[index]
            
        elif argvLength == 6:
            info = argv[5]

        if info == None:
            raise Exception("No message definition!")
       
        hex : None
        _bytes: None
        digestExc = digest(info.encode(encoding))
        if digest == shake_128 or digest == shake_256:
            if el == None:
                raise Exception("Shake algorithm require a length!")
            else:
                hex = digestExc.hexdigest(el)
                _bytes = digestExc.digest(el)
        else:
            hex = digestExc.hexdigest()
            _bytes = digestExc.digest()
      
        print(f"""
Raw: {info}
Hash: {al}
Bytes: {_bytes}
Hex: {hex}
Length: {len(hex)}""")