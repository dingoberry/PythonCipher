from sys import argv, getdefaultencoding
from base64 import *
 

BaseDict = {
    "16": (b16encode, b16decode),
    "32": (b32encode, b32hexdecode),
    "32h": (b32hexencode, b32hexdecode),
    "64": (b64encode, b64decode),
    "85": (b85encode, b85decode)
}

def execute():
    argvLength = len(argv)
    
    isEncoding : None
    bit : None
    encoding = getdefaultencoding()
    info = None
    if argvLength >= 7:
         for index in range(3, argvLength, 2):
             if argv[index] == '-t':
                 realEncoding = argv[index + 1]
                 isEncoding = True if realEncoding == 'e' else (False if realEncoding == 'd' else None)
             elif argv[index] == '-b':
                 bit = argv[index + 1]
             elif argv[index] == '-e':
                 encoding = argv[index + 1]
             elif index == argvLength - 1:
                 info = argv[index]
             

    if isEncoding == None:
        raise Exception("Please give a target action!")
    if bit == None:
        raise Exception("Please give a encoding bit!")
    if info == None:
        raise Exception("No message definition!")
    
    base = BaseDict.get(bit)
    if base == None:
        raise Exception("No base algorithm definition!")
    
    base = base[0] if isEncoding else base[1]
    print(f"""
Raw: {info}
Method: {"encoding" if isEncoding else "decoding"} - {bit}
Output: {base(info.encode(encoding)).decode(encoding)}""")
    
