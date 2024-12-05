from sys import argv, getdefaultencoding, exc_info
import digest.hasher as LibHasher
import digest.baser as LibBaser
import cipher.symmetry as LibSymCipher
import cipher.asymmetry as LibAsymCipher

def _showHelp():
    encoding = getdefaultencoding()
    print(f'''
Support help:
    -w hash | base | sci | aci [...Required] [Option] <message>
        [Option]:
            -e(encoding) {encoding}(default)
        
        [Required]:    
            hash:
                -a(Algorithm) {' | '.join([item for item in LibHasher.HashDict.keys()])}
                    [Option]: 
                            -l(shake128, shake256 required) <byte length>
                    
            base(Base Algorithm): 
                -t e(Encrypt) | d(Decrypt) -a(Algorithm)(base64-default) {' | '.join([item for item in LibBaser.BaseDict.keys()])}
                    
            sci(Symmetric Cipher):
                -t e(Encrypt) | d(Decrypt) -a(Algorithm) {' | '.join([item for item in LibSymCipher.CipherDict.keys()])}
                    [Option]:
                            aes: -l(length) 128(default) | 192 | 256
                            des | aes: -m(mode) cbc(default) | ecb | ofb | cfb | ctr | eax
                            
            aci(Asymmetric Cipher):
                -t e(Encrypt) | d(Decrypt) -a(Algorithm) {' | '.join([item for item in LibAsymCipher.CipherDict.keys()])}
                    [Option]: 
                            rsa(Encrypt): -l(length) 1024 | 2048(default) | 3072 -s <Sign message> -sm(Signature) pss | 1.5(default)
                                          -m(mode) oaep(default) | v1.5
                                          -pwd <Password>
''')
    
ExecuteDict = {
    "hash": LibHasher.execute,
    "base": LibBaser.execute,
    "sci": LibSymCipher.execute,
    "aci": LibAsymCipher.execute
}

def _parseArgs(arg_dic):
     arg_key = None
     for arg in argv[1:]:
        if arg.startswith('-'):
            arg_dic[arg] = None
            arg_key = arg
        elif arg_key is not None:
            arg_dic[arg_key] = arg
            arg_key = None
        else:
            arg_dic['content'] = arg
            

if __name__ == "__main__":
    argDic = {}
    _parseArgs(argDic)

    if len(argDic) == 0 or argDic.__contains__('-h'):
        _showHelp()
        exit(1)       

    ec = argDic.get('-w')
    ec = ExecuteDict[ec] if ec is not None else ec
    if ec is None:
        _showHelp()
        exit(1)     
    else:
        try:
            ec(argDic)
        except Exception as e:
            print(e)
            _showHelp()
        except any:
            for exc in exc_info(): 
                print(exc)
            _showHelp()