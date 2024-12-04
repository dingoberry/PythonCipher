from sys import getdefaultencoding
from base64 import b64encode, b64decode, b85decode, b85encode
import json

class AlgorithmBase:
    def __init__(self, argv, algorithm = None) -> None:
        self.algorithm = argv.get('-a', algorithm)
        self.encoding = argv.get('-e', getdefaultencoding())
        self.content = argv.get('content')

        if self.algorithm is None:
            raise Exception("Please give a algorithm!")
        
    def retrieveAlgorithm(self, dict, hint = None):
        algorithmfuc = dict.get(self.algorithm)
        if algorithmfuc is None:
            raise Exception(f"No {hint + " " if hint is not None else ""}algorithm definition!")
        return algorithmfuc

    def useContent(self):
        if self.content is None:
            raise Exception("No message definition!")
        return self.content.encode(self.encoding)
    
    def encodeText(self, task):
        result = task()
        if isinstance(result, bytes):
            return result.decode(self.encoding)
        elif isinstance(result, str):
            return result
        else:
            raise Exception("Bad encoding text for none defined result!")

    def encodeBase64(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode(self.encoding)
        return self.encodeText(lambda: b64encode(data))

    def decodeBase64(self, data: str):
        return b64decode(data.encode(self.encoding))
    
    def encodeBase85(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode(self.encoding)
        return self.encodeText(lambda: b85encode(data))

    def decodeBase85(self, data: str):
        return b85decode(data.encode(self.encoding))

    def __str__(self) -> str:
        return f'\n{json.dumps(self.__dict__, ensure_ascii=False, indent=3)}\n'

class CipherBase(AlgorithmBase):
    def __init__(self, argv, algorithm = None) -> None:
        super().__init__(argv, algorithm)

        self.action = argv.get('-t')
        if self.action is None:
            raise Exception("Please give a target action!")
        else:
            if self.action == 'e':
                self.action = 'encrypt'
            elif self.action == 'd':
                self.action = 'decrypt'
            else:
                raise Exception("Please give a valid action!")
    
    def isEncrypt(self):
        return self.action == 'encrypt'
    
    def isDecrypt(self):
        return self.action == 'decrypt'