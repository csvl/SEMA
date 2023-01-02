from os import listdir
from RC4Encryption import RC4Encryption

for f in listdir("output2"):
    print(f)
    o = open("output2/" + f, "r")
    r = o.read()
    arr = []
    for i in range(0x40):
        rc4 = RC4Encryption(b'warzone160\x00')
        rc4.make_key()
        cipher = rc4.crypt(b'\x29\xbb\x66\xe4\x00\x00\x00\x00' + i.to_bytes(1,"big") + b'\x00\x00\x00')
        found = r.find(hex(int(cipher.hex(),base=16)))
        if found != -1:
            arr.append(hex(i))
    if len(arr) > 0:
        print(arr)
    arr = []
    for j in range(0x40):
        rc4 = RC4Encryption(b'warzoneTURBO\x00')
        rc4.make_key()
        cipher = rc4.crypt(b'\x9f\x49\xa4\xb5\x00\x00\x00\x00' + j.to_bytes(1,"big") + b'\x00\x00\x00')
        found = r.find(hex(int(cipher.hex(),base=16)))
        if found != -1:
            arr.append(hex(j))
    if len(arr) > 0:
        print(arr)
