from sys import argv, getdefaultencoding, exc_info
import digest.hasher as LibHasher
import digest.baser as LibBaser

def _showHelp():
    encoding = getdefaultencoding()
    print(f'''
Support help:
    -w hash | base
        hash:
            -h(Hash) {' | '.join([item for item in LibHasher.HashDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default) -l(shake128, shake128 required) <byte length>
        base:
            -t e(encoding) | d(decoding) -b(bit) {' | '.join([item for item in LibBaser.BaseDict.keys()])} [Option] <message>
                Option: -e(encoding) {encoding}(default)
          
''')
    
executeDict = {
    "hash": LibHasher.execute,
    "base": LibBaser.execute
}

if __name__ == "__main__":
    if len(argv) < 2 or argv[1] == '-h' or argv[1] != '-w':
        _showHelp()
        exit(1)

    ec = executeDict.get(argv[2])
    if ec == None:
       _showHelp()
    else:
        try:
            ec()
        except Exception as e:
            print(e)
            _showHelp()
        except:
            for exc in exc_info(): 
                print(exc)
            _showHelp()