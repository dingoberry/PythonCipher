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
    argv_length = len(argv)

    is_encoding = None
    bit = None
    encoding = getdefaultencoding()
    info = None
    if argv_length >= 7:
         for index in range(3, argv_length, 2):
             if argv[index] == '-t':
                 real_encoding = argv[index + 1]
                 is_encoding = True if real_encoding == 'e' else (False if real_encoding == 'd' else None)
             elif argv[index] == '-b':
                 bit = argv[index + 1]
             elif argv[index] == '-e':
                 encoding = argv[index + 1]
             elif index == argv_length - 1:
                 info = argv[index]
             

    if is_encoding is None:
        raise Exception("Please give a target action!")
    if bit is None:
        raise Exception("Please give a encoding bit!")
    if info is None:
        raise Exception("No message definition!")
    
    base = BaseDict.get(bit)
    if base is None:
        raise Exception("No base algorithm definition!")
    
    base = base[0] if is_encoding else base[1]
    print(f"""
Raw: {info}
Method: {"encoding" if is_encoding else "decoding"} - {bit}
Output: {base(info.encode(encoding)).decode(encoding)}""")
    
