from sys import argv, getdefaultencoding, exc_info
import digest.hasher as LibHasher
import digest.baser as LibBaser
import cipher.syn_cipher as LibSynCipher
import cipher.asyn_cipher as LibAsynCipher

def _showHelp():
    encoding = getdefaultencoding()
    print(f'''
Support help:
    -w hash | base | s-cipher | a-cipher
        hash:
            -a(Algorithm) {' | '.join([item for item in LibHasher.HashDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default) -l(shake128, shake128 required) <byte length>
        base:
            -t e(Encrypt) | d(Decrypt) -a(Algorithm)(base64-default) {' | '.join([item for item in LibBaser.BaseDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default)
                
        s-cipher:
            -t e(Encrypt) | d(Decrypt) -a(Algorithm) {' | '.join([item for item in LibSynCipher.CipherDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default)
                        aes: -l(length) 128(default) | 192 | 256 -m(mode) cbc(default) | ecb | ofb | cfb | ctr
                        des: -m(mode) cbc(default) | ecb | ofb | cfb | ctr
        a-cipher:
            -t e(Encrypt) | d(Decrypt) -a(Algorithm) {' | '.join([item for item in LibAsynCipher.CipherDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default)
''')
    
executeDict = {
    "hash": LibHasher.execute,
    "base": LibBaser.execute,
    "s-cipher": LibSynCipher.execute,
    "a-cipher": LibAsynCipher.execute
}

def _parseArgs(argDic):
     argKey = None
     for arg in argv[1:]:
        if arg.startswith('-'):
            argDic[arg] = None
            argKey = arg
        elif argKey is not None:
            argDic[argKey] = arg
            argKey = None
        else:
            argDic['content'] = arg
            

if __name__ == "__main__":
    argDic = {}
    _parseArgs(argDic)

    if len(argDic) == 0 or argDic.__contains__('-h'):
        _showHelp()
        exit(1)       

    ec = argDic.get('-w')
    ec = executeDict[ec] if ec is not None else ec
    if ec is None:
        _showHelp()
        exit(1)     
    else:
        try:
            ec(argDic)
        except Exception as e:
            for exc in exc_info(): 
                print(exc)
            _showHelp()
        except:
            for exc in exc_info(): 
                print(exc)
            _showHelp()